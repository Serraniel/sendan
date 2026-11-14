// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

// Generates an SPDX 2.3 SBOM for a shipped Go binary.
//
// # Why this is in the repository rather than a tool we install
//
// scripts/release-build.sh is both the script that produces a release and the
// script somebody runs to reproduce one, and its header says why that matters:
// "If this needed a release tool installed, verifying a binary would mean
// trusting that tool as well, and the thing being verified is the project's
// trust anchor." syft and cyclonedx-gomod would each put a third-party binary
// into exactly that path. This needs nothing but the Go already present.
//
// # Why it is deterministic, and how
//
// The release builds twice and fails if SHA256SUMS differs, because that check
// is what makes the binaries reproducible. The SBOM is checksummed with them,
// so it has to come out byte-identical too - which rules out the two things an
// SBOM usually carries:
//
//   - a creation timestamp. Taken from SOURCE_DATE_EPOCH, which
//     release-build.sh already exports and defaults to 0.
//   - a random document namespace. Derived from the version and the commit, so
//     two builds of one release agree and two different releases do not.
//
// # What it does not claim
//
// Every package carries NOASSERTION for its licence. The licences are known -
// THIRD-PARTY-NOTICES.txt beside this file in the same archive carries their
// full text - but deciding that a given text *is* MIT rather than something
// MIT-shaped is a judgement, and an SBOM is the wrong place to record a
// judgement as a fact. Annex I Pt II(1) asks for the components; the notices
// discharge the licence obligation. See #355.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"time"

	"github.com/Serraniel/sendan/internal/gomodules"
)

type creationInfo struct {
	Created  string   `json:"created"`
	Creators []string `json:"creators"`
}

type externalRef struct {
	Category string `json:"referenceCategory"`
	Type     string `json:"referenceType"`
	Locator  string `json:"referenceLocator"`
}

type spdxPackage struct {
	SPDXID           string        `json:"SPDXID"`
	Name             string        `json:"name"`
	VersionInfo      string        `json:"versionInfo"`
	DownloadLocation string        `json:"downloadLocation"`
	FilesAnalyzed    bool          `json:"filesAnalyzed"`
	LicenseConcluded string        `json:"licenseConcluded"`
	LicenseDeclared  string        `json:"licenseDeclared"`
	CopyrightText    string        `json:"copyrightText"`
	Supplier         string        `json:"supplier,omitempty"`
	ExternalRefs     []externalRef `json:"externalRefs,omitempty"`
}

type relationship struct {
	SPDXElementID      string `json:"spdxElementId"`
	RelationshipType   string `json:"relationshipType"`
	RelatedSPDXElement string `json:"relatedSpdxElement"`
}

type document struct {
	SPDXVersion       string         `json:"spdxVersion"`
	DataLicense       string         `json:"dataLicense"`
	SPDXID            string         `json:"SPDXID"`
	Name              string         `json:"name"`
	DocumentNamespace string         `json:"documentNamespace"`
	CreationInfo      creationInfo   `json:"creationInfo"`
	Packages          []spdxPackage  `json:"packages"`
	Relationships     []relationship `json:"relationships"`
	DocumentDescribes []string       `json:"documentDescribes"`
}

// An SPDX identifier may hold letters, digits, dots and hyphens and nothing
// else, so a module path's slashes and plus signs have to go.
var notIdentifier = regexp.MustCompile(`[^0-9A-Za-z.-]+`)

func identifier(prefix, s string) string {
	return "SPDXRef-" + prefix + "-" + notIdentifier.ReplaceAllString(s, "-")
}

// created renders SOURCE_DATE_EPOCH as the UTC timestamp SPDX wants. Anything
// unparseable is an error rather than a silent fallback to now: "now" is the
// one value that would break the reproducibility check, and it would do it
// intermittently.
func created(epoch string) (string, error) {
	if epoch == "" {
		epoch = "0"
	}
	seconds, err := strconv.ParseInt(epoch, 10, 64)
	if err != nil {
		return "", fmt.Errorf("SOURCE_DATE_EPOCH=%q is not a number of seconds: %w", epoch, err)
	}
	return time.Unix(seconds, 0).UTC().Format("2006-01-02T15:04:05Z"), nil
}

func build(binary, version, commit, toolchain, epoch string, modules []gomodules.Module) (*document, error) {
	stamp, err := created(epoch)
	if err != nil {
		return nil, err
	}

	root := identifier("Binary", binary)
	doc := &document{
		SPDXVersion: "SPDX-2.3",
		DataLicense: "CC0-1.0",
		SPDXID:      "SPDXRef-DOCUMENT",
		Name:        binary + "-" + version,
		// Derived, not random: two builds of one release have to agree, and
		// two different releases have to differ.
		DocumentNamespace: "https://github.com/Serraniel/sendan/spdx/" + binary + "-" + version + "-" + commit,
		CreationInfo: creationInfo{
			Created:  stamp,
			Creators: []string{"Tool: sendan-go-sbom", "Organization: Sendan contributors"},
		},
		DocumentDescribes: []string{root},
	}

	doc.Packages = append(doc.Packages, spdxPackage{
		SPDXID:           root,
		Name:             binary,
		VersionInfo:      version,
		DownloadLocation: "https://github.com/Serraniel/sendan",
		FilesAnalyzed:    false,
		// The one licence this document is entitled to state, because it is
		// this project's own.
		LicenseConcluded: "AGPL-3.0-or-later",
		LicenseDeclared:  "AGPL-3.0-or-later",
		CopyrightText:    "Copyright (C) 2026 Serraniel and the Sendan contributors",
		Supplier:         "Organization: Sendan contributors",
		ExternalRefs: []externalRef{{
			Category: "PACKAGE-MANAGER",
			Type:     "purl",
			Locator:  "pkg:golang/github.com/Serraniel/sendan@" + version,
		}},
	})

	// The standard library is code in the binary, and which toolchain compiled
	// it is the single most load-bearing fact about a Go build - two toolchains
	// do not produce the same bytes, and a standard library advisory is fixed
	// by moving this and nothing else.
	stdlib := identifier("Package", "go-stdlib")
	doc.Packages = append(doc.Packages, spdxPackage{
		SPDXID:           stdlib,
		Name:             "go",
		VersionInfo:      toolchain,
		DownloadLocation: "https://go.dev/dl/",
		FilesAnalyzed:    false,
		LicenseConcluded: "NOASSERTION",
		LicenseDeclared:  "NOASSERTION",
		CopyrightText:    "NOASSERTION",
		ExternalRefs: []externalRef{{
			Category: "PACKAGE-MANAGER",
			Type:     "purl",
			Locator:  "pkg:golang/std@" + toolchain,
		}},
	})
	doc.Relationships = append(doc.Relationships, relationship{root, "DEPENDS_ON", stdlib})

	for _, module := range modules {
		id := identifier("Package", module.Path+"-"+module.Version)
		doc.Packages = append(doc.Packages, spdxPackage{
			SPDXID:      id,
			Name:        module.Path,
			VersionInfo: module.Version,
			// The proxy rather than the upstream host: it is where the build
			// actually fetched this, and it is immutable.
			DownloadLocation: "https://proxy.golang.org/" + module.Path + "/@v/" + module.Version + ".zip",
			FilesAnalyzed:    false,
			LicenseConcluded: "NOASSERTION",
			LicenseDeclared:  "NOASSERTION",
			CopyrightText:    "NOASSERTION",
			ExternalRefs: []externalRef{{
				Category: "PACKAGE-MANAGER",
				Type:     "purl",
				Locator:  "pkg:golang/" + module.Path + "@" + module.Version,
			}},
		})
		doc.Relationships = append(doc.Relationships, relationship{root, "DEPENDS_ON", id})
	}

	doc.Relationships = append(doc.Relationships,
		relationship{"SPDXRef-DOCUMENT", "DESCRIBES", root})

	return doc, nil
}

func main() {
	pkg := flag.String("pkg", "./cmd/sendan-cli", "the main package the binary is built from")
	binary := flag.String("binary", "sendan", "the name of the shipped binary")
	version := flag.String("version", "", "the release version, e.g. v0.4.0")
	commit := flag.String("commit", "", "the commit the release was built from")
	out := flag.String("out", "", "where to write the document")
	flag.Parse()

	if *version == "" || *commit == "" || *out == "" {
		fmt.Fprintln(os.Stderr, "go-sbom: -version, -commit and -out are all required")
		os.Exit(2)
	}

	if err := run(*pkg, *binary, *version, *commit, *out); err != nil {
		fmt.Fprintf(os.Stderr, "go-sbom: %v\n", err)
		os.Exit(1)
	}
}

func run(pkg, binary, version, commit, out string) error {
	modules, err := gomodules.Linked(pkg)
	if err != nil {
		return err
	}

	goMod, err := os.ReadFile("go.mod")
	if err != nil {
		return err
	}
	toolchain, err := gomodules.Toolchain(goMod)
	if err != nil {
		return err
	}

	doc, err := build(binary, version, commit, toolchain, os.Getenv("SOURCE_DATE_EPOCH"), modules)
	if err != nil {
		return err
	}

	encoded, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')

	// Readable by anyone: this is a published artefact, the same reasoning
	// tools/asset-manifest records for the same mode.
	//nolint:gosec // G306: a published bill of materials, deliberately not private.
	if err := os.WriteFile(out, encoded, 0o644); err != nil {
		return err
	}

	fmt.Printf("go-sbom: %s, %d modules plus the standard library -> %s\n",
		binary, len(modules), out)
	return nil
}
