// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

// Command sendan runs the Sendan server.
//
// The same binary serves the embedded web client and the API. Setting
// SENDAN_SERVE_UI=false disables the client, producing a backend-only instance
// rather than a second deployable.
package main

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/Serraniel/sendan/internal/blob"
	"github.com/Serraniel/sendan/internal/compat"
	"github.com/Serraniel/sendan/internal/config"
	"github.com/Serraniel/sendan/internal/httpapi"
	"github.com/Serraniel/sendan/internal/logging"
	"github.com/Serraniel/sendan/internal/ratelimit"
	"github.com/Serraniel/sendan/internal/store"
	"github.com/Serraniel/sendan/internal/upload"
	"github.com/Serraniel/sendan/internal/webui"
)

// version is set at build time by the release tooling and reported at
// /api/source, which is how an instance discloses what it is running. An
// unstamped build falls back to the revision Go embeds, so a binary built
// without the release tooling still reports something true.
var (
	version = "dev"
	commit  = "unknown"
)

const (
	shutdownGrace = 30 * time.Second

	// The reaper is a backstop, not the mechanism: expiry is enforced on every
	// read, so this interval governs how promptly disk is reclaimed rather than
	// whether a dead upload is reachable.
	reapInterval = 5 * time.Minute
	reapBatch    = 500
)

func main() {
	// Subcommands, and the server when there are none. Kept to the two
	// operations that must happen while nothing is serving: everything else the
	// server does, it does from the environment.
	if args := os.Args[1:]; len(args) > 0 {
		var err error
		switch args[0] {
		case "generate-master-key":
			err = generateMasterKey()
		case "rotate-master-key":
			err = rotateMasterKey(context.Background(), args[1:])
		case "help", "-h", "--help":
			fmt.Print(masterKeyUsage)
			return
		default:
			fmt.Fprint(os.Stderr, masterKeyUsage)
			err = fmt.Errorf("unknown command %q", args[0])
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "sendan: %v\n", err)
			os.Exit(1)
		}
		return
	}

	if err := run(); err != nil {
		// Configuration errors arrive before a logger exists, so they go to
		// stderr directly rather than being lost.
		fmt.Fprintf(os.Stderr, "sendan: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load(os.Getenv)
	if err != nil {
		return err
	}

	log := logging.New(os.Stdout, logging.Options{Level: cfg.LogLevel, Format: cfg.LogFormat})
	slog.SetDefault(log)

	log.Info("starting",
		"version", version,
		"commit", commit,
		"listen", cfg.Listen,
		"base_url", cfg.BaseURL.String(),
		"source_url", cfg.SourceURL.String(),
		"serve_ui", cfg.ServeUI,
		"send_compat", cfg.SendCompat,
		"default_ttl", cfg.DefaultTTL.String(),
		"max_ttl", cfg.MaxTTL.String(),
		"allow_infinite_ttl", cfg.AllowInfiniteTTL,
		"max_upload_size", cfg.MaxUploadSize,
		"rate_limit_per_minute", cfg.RateLimit,
		"trusted_proxies", cfg.TrustedProxies,
	)
	if cfg.SendCompat {
		log.Warn("third-party compatibility endpoints are enabled; uploads made through them use a weaker, server-enforced password model")
	}
	if cfg.AllowInfiniteTTL {
		log.Warn("unlimited retention is permitted; uploads may never expire")
	}
	if cfg.RateLimit <= 0 {
		log.Warn("rate limiting is disabled; every endpoint is unmetered")
	}
	if cfg.TrustedProxies > 0 {
		// Trusting a hop that is not there lets a caller write the header that
		// decides which bucket they are charged to.
		log.Warn("trusting forwarded client addresses; this must match the number of reverse proxies actually in front of this instance",
			"trusted_proxies", cfg.TrustedProxies)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Storage is opened before the listener, so a misconfigured backend is a
	// startup failure rather than an error the first visitor discovers.
	metadata, err := store.Open(ctx, cfg.Database)
	if err != nil {
		return err
	}
	defer func() {
		if err := metadata.Close(); err != nil {
			log.Error("closing the metadata store", "error", err)
		}
	}()
	// Wrapped before anything reads a row, so no path exists that reaches an
	// at-rest key in its stored form.
	if len(cfg.MasterKey) > 0 {
		if metadata, err = store.WithMasterKey(metadata, cfg.MasterKey); err != nil {
			return err
		}
	}

	log.Info("metadata store ready",
		"location", redactCredentials(cfg.Database),
		// Whether, never which. An operator needs to know the setting took
		// effect, and a log is one of the places this key must never appear.
		"at_rest_keys_wrapped", len(cfg.MasterKey) > 0)

	blobs, err := blob.Open(ctx, cfg.Storage)
	if err != nil {
		return err
	}
	log.Info("blob store ready", "location", redactCredentials(cfg.Storage))

	var limiter *ratelimit.Limiter
	if cfg.RateLimit > 0 {
		limiter = ratelimit.New(ratelimit.Config{
			Rate:  float64(cfg.RateLimit) / 60,
			Burst: cfg.RateBurst,
		})
	}

	attempts := ratelimit.NewPasswordAttempts()
	uploads := upload.New(metadata, blob.NewShredder(blobs), upload.Policy{
		DefaultTTL:          cfg.DefaultTTL,
		MaxTTL:              cfg.MaxTTL,
		AllowInfiniteTTL:    cfg.AllowInfiniteTTL,
		IncompleteTTL:       cfg.IncompleteTTL,
		DefaultMaxDownloads: cfg.DefaultMaxDownloads,
	}, log).WithPasswordAttempts(attempts)

	var reaper sync.WaitGroup
	reaper.Add(1)
	go func() {
		defer reaper.Done()
		uploads.RunReaper(ctx, reapInterval, reapBatch)
	}()
	defer reaper.Wait()

	// Only when asked for. A nil handler means the routes are never
	// registered, so the mode being off is structural rather than a check
	// inside each endpoint.
	var compatHandler http.Handler
	if cfg.SendCompat {
		cs, ok := metadata.(store.CompatStore)
		if !ok {
			return fmt.Errorf("this database backend cannot store compatibility uploads")
		}
		compatHandler = compat.New(compat.Options{
			Store:    cs,
			Uploads:  uploads,
			Metadata: metadata,
			Blobs:    blob.NewShredder(blobs),
			BaseURL:  cfg.BaseURL,
			Log:      log,
		})
	}

	handler := httpapi.New(httpapi.Options{
		BaseURL:       cfg.BaseURL,
		SourceURL:     cfg.SourceURL,
		Version:       version,
		Commit:        commit,
		Uploads:       uploads,
		Compat:        compatHandler,
		ServeUI:       cfg.ServeUI,
		WebUI:         clientAssets(),
		MaxUploadSize: cfg.MaxUploadSize,

		RateLimit:      limiter,
		TrustedProxies: cfg.TrustedProxies,

		Log: log,
	})

	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		// No write timeout: downloads stream for as long as the client needs,
		// and a deadline here would truncate large transfers.
		IdleTimeout: 2 * time.Minute,
	}

	errc := make(chan error, 1)
	go func() {
		log.Info("listening", "addr", srv.Addr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errc <- fmt.Errorf("serve: %w", err)
			return
		}
		errc <- nil
	}()

	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
		log.Info("shutting down", "grace", shutdownGrace.String())
	}

	// In-flight transfers are given time to finish. Cutting them off would
	// leave partial uploads for the reaper to clean up unnecessarily.
	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownGrace)
	defer cancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("shutdown: %w", err)
	}
	log.Info("stopped")
	return <-errc
}

// redactCredentials removes any userinfo from a location before it is logged.
//
// Database and storage locations carry passwords, and a startup line naming the
// backend is useful while a startup line naming its password is a disclosure.
func redactCredentials(location string) string {
	u, err := url.Parse(location)
	if err != nil || u.User == nil {
		return location
	}
	u.User = url.User(u.User.Username())
	return u.String()
}

// clientAssets returns the embedded web client, or nil when this binary was
// built without one.
func clientAssets() fs.FS {
	assets, ok := webui.Assets()
	if !ok {
		return nil
	}
	return assets
}
