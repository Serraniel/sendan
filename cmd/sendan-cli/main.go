// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

// Command sendan sends and receives files through a Sendan instance.
//
// It is a separate binary from the server on purpose. This is the program a
// user is asked to obtain independently and trust — see docs/design.md §7.1 —
// so it carries none of the server's dependencies: no database drivers, no
// object storage client, no embedded web client. What it links is the
// cryptographic scheme and the standard library, which is also what makes a
// reproducible build worth checking.
//
// Everything it prints that is not the result goes to stderr, so the result can
// be piped:
//
//	sendan up notes.txt | pbcopy
//	tar cz dir | sendan up --name backup.tgz
//	sendan down 'https://…/d/…#…' > restored.tgz
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"mime"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Serraniel/sendan/internal/client"
)

func main() {
	// Interrupting must stop the transfer rather than leave a half-written
	// upload the instance will reap later.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := run(ctx, os.Args[1:]); err != nil {
		if errors.Is(err, context.Canceled) {
			fmt.Fprintln(os.Stderr, "sendan: cancelled")
			os.Exit(130)
		}
		fmt.Fprintf(os.Stderr, "sendan: %v\n", err)
		os.Exit(1)
	}
}

const usage = `sendan — send and receive end-to-end encrypted files

  sendan up [file]        encrypt and upload; reads stdin when no file is given
  sendan down <link>      download and decrypt; writes the file named in it

Options for up:
  --to <url>              the instance to upload to (or set SENDAN_INSTANCE)
  --name <name>           the filename a recipient sees; required for stdin
  --password              protect the file with a password, asked for twice
  --password-file <path>  read that password from a file instead
  --expires <duration>    30m, 12h, 7d; the instance decides if omitted
  --downloads <n>         allow n downloads, then remove it

Options for down:
  -o <path>               write here instead; "-" means stdout

There is no --password <value>: an argument appears in the process list and in
shell history, and the password contributes to the key. Use the prompt, a file,
or SENDAN_PASSWORD.

The link contains the key after the #. Anyone who has it can open the file, and
a link that loses that part cannot be repaired.
`

func run(ctx context.Context, args []string) error {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, usage)
		return errors.New("no command given")
	}

	switch args[0] {
	case "up":
		return up(ctx, args[1:])
	case "down":
		return down(ctx, args[1:])
	case "help", "-h", "--help":
		_, _ = fmt.Fprint(os.Stdout, usage)
		return nil
	default:
		fmt.Fprint(os.Stderr, usage)
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func up(ctx context.Context, args []string) error {
	var path, instance, name, passwordFile, expires, downloads string
	wantPassword := false

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--to":
			var err error
			if instance, err = value(args, &i, "--to"); err != nil {
				return err
			}
		case "--name":
			var err error
			if name, err = value(args, &i, "--name"); err != nil {
				return err
			}
		case "--password":
			wantPassword = true
		case "--password-file":
			var err error
			if passwordFile, err = value(args, &i, "--password-file"); err != nil {
				return err
			}
			// Naming a file is asking for a password; requiring both would be a
			// distinction with nothing behind it.
			wantPassword = true
		case "--expires":
			var err error
			if expires, err = value(args, &i, "--expires"); err != nil {
				return err
			}
		case "--downloads":
			var err error
			if downloads, err = value(args, &i, "--downloads"); err != nil {
				return err
			}
		default:
			if strings.HasPrefix(args[i], "-") && args[i] != "-" {
				return fmt.Errorf("unknown option %q", args[i])
			}
			if path != "" {
				return errors.New("only one file can be sent at a time")
			}
			path = args[i]
		}
	}

	if instance == "" {
		instance = os.Getenv("SENDAN_INSTANCE")
	}
	if instance == "" {
		return errors.New("no instance given: pass --to <url> or set SENDAN_INSTANCE")
	}

	opts, err := uploadOptions(wantPassword, passwordFile, expires, downloads)
	if err != nil {
		return err
	}

	source, size, sourceName, cleanup, err := openSource(path)
	if err != nil {
		return err
	}
	defer cleanup()

	if name == "" {
		name = sourceName
	}
	if name == "" {
		return errors.New("reading from a pipe, so the filename is not known: pass --name")
	}

	c := &client.Client{Origin: instance}
	fmt.Fprintf(os.Stderr, "encrypting and uploading %s…\n", name)

	upload, err := c.Send(ctx, source, name, mediaType(name), size, opts)
	if err != nil {
		return err
	}

	// The link on stdout and nothing else, so it composes. Everything a person
	// reads is on stderr.
	fmt.Println(upload.Link.String())
	fmt.Fprintln(os.Stderr, "\n"+describeProtection(opts))
	fmt.Fprintf(os.Stderr,
		"\nKeep this to delete the upload early; it is shown once and stored nowhere:\n  %s\n",
		encodeToken(upload.OwnerToken))
	return nil
}

// uploadOptions turns what was asked for into what is sent.
//
// Read before anything is opened or uploaded: a password that cannot be
// obtained, or a lifetime that is not one, should stop the command before it
// has done anything rather than after it has read a file.
func uploadOptions(wantPassword bool, passwordFile, expires, downloads string) (client.UploadOptions, error) {
	var opts client.UploadOptions

	if wantPassword {
		password, err := readNewPassword(passwordFile)
		if err != nil {
			return opts, err
		}
		opts.Password = password
	} else if passwordFile != "" {
		return opts, errors.New("--password-file was given without a password being wanted")
	}

	if expires != "" {
		d, err := parseLifetime(expires)
		if err != nil {
			return opts, err
		}
		if d == 0 {
			return opts, errors.New("--expires 0 would ask for an upload that never expires, " +
				"which an instance permits only if it is configured to; omit the flag for its default")
		}
		opts.TTLSeconds = int64(d.Seconds())
	}

	if downloads != "" {
		n, err := strconv.ParseInt(downloads, 10, 64)
		if err != nil || n < 0 {
			return opts, fmt.Errorf("--downloads %q is not a number of downloads", downloads)
		}
		// Zero means no limit on the wire, which is what omitting the flag
		// already asks for. Accepting it as "none allowed" would be the
		// opposite of what somebody typing it meant.
		if n == 0 {
			return opts, errors.New("--downloads 0 would mean no limit, not none; omit the flag for that")
		}
		opts.MaxDownloads = n
	}

	return opts, nil
}

// describeProtection says what was actually applied.
//
// From the options that were sent, not from the flags that were typed: what
// matters is what the file got. The lifetime is what was asked for - the
// instance decides the deadline, and may have its own maximum.
func describeProtection(opts client.UploadOptions) string {
	parts := []string{}
	if opts.Password != "" {
		parts = append(parts, "protected with a password")
	} else {
		parts = append(parts, "no password: anyone with the link can open it")
	}
	if opts.TTLSeconds > 0 {
		parts = append(parts, "expires after "+
			(time.Duration(opts.TTLSeconds)*time.Second).String())
	} else {
		parts = append(parts, "expires when the instance decides")
	}
	if opts.MaxDownloads > 0 {
		parts = append(parts, fmt.Sprintf("%d download(s) allowed", opts.MaxDownloads))
	}
	return strings.Join(parts, "; ") + "."
}

func down(ctx context.Context, args []string) error {
	var raw, out string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-o":
			var err error
			if out, err = value(args, &i, "-o"); err != nil {
				return err
			}
		default:
			if strings.HasPrefix(args[i], "-") && args[i] != "-" {
				return fmt.Errorf("unknown option %q", args[i])
			}
			if raw != "" {
				return errors.New("only one link can be opened at a time")
			}
			raw = args[i]
		}
	}
	if raw == "" {
		return errors.New("no link given")
	}

	link, err := client.ParseLink(raw)
	if err != nil {
		return err
	}

	c := &client.Client{Origin: link.Origin}
	published, err := c.Describe(ctx, link.ID())
	if err != nil {
		return err
	}

	password := ""
	if published.PasswordRequired {
		if password, err = readPassword(); err != nil {
			return err
		}
	}

	opened, err := client.Open(link, published, password)
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "%s, %s\n", opened.File.Name, humanSize(opened.File.Size))

	dest, finish, err := openDestination(out, opened.File.Name)
	if err != nil {
		return err
	}
	if err := c.Fetch(ctx, link.ID(), opened, dest); err != nil {
		// Nothing is kept: a stream that failed its integrity check has
		// produced bytes, and a file of those bytes would look like a file.
		_ = finish(false)
		return err
	}
	return finish(true)
}

// value reads the argument after a flag.
func value(args []string, i *int, flag string) (string, error) {
	*i++
	if *i >= len(args) {
		return "", fmt.Errorf("%s needs a value", flag)
	}
	return args[*i], nil
}

// openSource returns what to upload, its size, and a name if it has one.
//
// A size of -1 means the source cannot be measured without reading it, which is
// what a pipe is. See client.Send for what that costs.
func openSource(path string) (io.Reader, int64, string, func(), error) {
	if path == "" || path == "-" {
		return os.Stdin, -1, "", func() {}, nil
	}

	f, err := os.Open(path) //nolint:gosec // the path is the user's own argument
	if err != nil {
		return nil, 0, "", func() {}, err
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, 0, "", func() {}, err
	}
	if info.IsDir() {
		_ = f.Close()
		return nil, 0, "", func() {}, fmt.Errorf("%s is a directory; pipe an archive instead", path)
	}
	return f, info.Size(), filepath.Base(path), func() { _ = f.Close() }, nil
}

// openDestination returns where to write, and how to finish.
//
// A file is written under a temporary name and renamed only on success, so an
// interrupted or failed download never leaves something that looks like the
// file. Standard output cannot offer that, which is why it is not the default.
func openDestination(out, suggested string) (io.Writer, func(ok bool) error, error) {
	if out == "-" {
		return os.Stdout, func(bool) error { return nil }, nil
	}

	path := out
	if path == "" {
		// The name came from whoever uploaded the file, and is about to become
		// a path on this disk. See safeName: it is not trusted to be a name.
		name, err := safeName(suggested)
		if err != nil {
			return nil, nil, err
		}
		path = name
	}

	//nolint:gosec // G703: either the user's own -o argument, or a name that
	// safeName has reduced to a single harmless path element.
	tmp, err := os.CreateTemp(filepath.Dir(path), ".sendan-*")
	if err != nil {
		return nil, nil, err
	}
	return tmp, func(ok bool) error {
		// Every os.Remove below deletes the temporary file this function
		// created, whose name came from os.CreateTemp and from nothing else.
		if cerr := tmp.Close(); cerr != nil && ok {
			_ = os.Remove(tmp.Name()) //nolint:gosec // G703: our own temporary file
			return cerr
		}
		if !ok {
			_ = os.Remove(tmp.Name()) //nolint:gosec // G703: our own temporary file
			return nil
		}
		//nolint:gosec // G703: as above - the destination is the user's own
		// argument or a name reduced to one path element.
		if err := os.Rename(tmp.Name(), path); err != nil {
			_ = os.Remove(tmp.Name())
			return err
		}
		fmt.Fprintf(os.Stderr, "saved %s\n", path)
		return nil
	}, nil
}

// safeName reduces a sender-supplied filename to something safe to create.
//
// The name travels in the metadata envelope, which the sender wrote. Used as a
// path it would let them choose where the recipient's file lands: "../../.bashrc"
// is a filename as far as the format is concerned.
//
// filepath.Base removes the directories, which handles traversal - but not
// every result of it is a name. "." and ".." survive Base intact and are
// directories, and an empty name is not a file at all. Those are refused rather
// than repaired, because a recipient choosing the path with -o is a better
// outcome than this program guessing one.
func safeName(sender string) (string, error) {
	name := filepath.Base(filepath.Clean(sender))

	switch name {
	case "", ".", "..", string(filepath.Separator):
		return "", fmt.Errorf(
			"the sender gave this file the name %q, which is not one this can create; pass -o",
			sender)
	}
	// Base has removed any directory, so this can only fire on a name that was
	// nothing but separators.
	if strings.ContainsRune(name, filepath.Separator) {
		return "", fmt.Errorf("the sender gave this file an unusable name %q; pass -o", sender)
	}
	return name, nil
}

// mediaType guesses from the name, which is all there is to go on.
func mediaType(name string) string {
	if t := mime.TypeByExtension(filepath.Ext(name)); t != "" {
		return t
	}
	return "application/octet-stream"
}

func encodeToken(token []byte) string {
	return client.EncodeToken(token)
}

func humanSize(n int64) string {
	const unit = 1000
	if n < unit {
		return fmt.Sprintf("%d bytes", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "kMGTP"[exp])
}
