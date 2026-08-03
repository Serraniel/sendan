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
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/Serraniel/sendan/internal/blob"
	"github.com/Serraniel/sendan/internal/config"
	"github.com/Serraniel/sendan/internal/logging"
	"github.com/Serraniel/sendan/internal/ratelimit"
	"github.com/Serraniel/sendan/internal/store"
	"github.com/Serraniel/sendan/internal/upload"
)

// version is set at build time by the release tooling. It will be reported at
// /api/source, which is how an instance discloses what it is running; that
// endpoint is not built yet (#32), so these are currently compiled in and
// unused.
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
		"serve_ui", cfg.ServeUI,
		"send_compat", cfg.SendCompat,
		"default_ttl", cfg.DefaultTTL.String(),
		"max_ttl", cfg.MaxTTL.String(),
		"allow_infinite_ttl", cfg.AllowInfiniteTTL,
		"max_upload_size", cfg.MaxUploadSize,
	)
	if cfg.SendCompat {
		log.Warn("third-party compatibility endpoints are enabled; uploads made through them use a weaker, server-enforced password model")
	}
	if cfg.AllowInfiniteTTL {
		log.Warn("unlimited retention is permitted; uploads may never expire")
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
	log.Info("metadata store ready", "location", redactCredentials(cfg.Database))

	blobs, err := blob.Open(ctx, cfg.Storage)
	if err != nil {
		return err
	}
	log.Info("blob store ready", "location", redactCredentials(cfg.Storage))

	attempts := ratelimit.NewPasswordAttempts()
	uploads := upload.New(metadata, blob.NewShredder(blobs), upload.Policy{
		DefaultTTL:          cfg.DefaultTTL,
		MaxTTL:              cfg.MaxTTL,
		AllowInfiniteTTL:    cfg.AllowInfiniteTTL,
		DefaultMaxDownloads: cfg.DefaultMaxDownloads,
	}, log).WithPasswordAttempts(attempts)

	var reaper sync.WaitGroup
	reaper.Add(1)
	go func() {
		defer reaper.Done()
		uploads.RunReaper(ctx, reapInterval, reapBatch)
	}()
	defer reaper.Wait()

	// Routes arrive with the API (M3). Until then the server exists so that
	// configuration, logging and shutdown are exercised rather than assumed.
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("ok\n"))
	})

	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           mux,
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
