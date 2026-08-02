# edge

## Purpose

Publishes a container image from the tip of `main`, for people who want to run
unreleased work.

## Triggers

Pushes to `main`, and on demand.

## What it does

Builds and pushes `:edge` and `:sha-<commit>` to GHCR for amd64 and arm64.

Deliberately **unversioned and unsigned**. It carries no stability claim and is
not a release. Automatically signing untested builds would erode the meaning of
a signature on the artefacts that are released.

## Why there are no nightly releases

A version number is a claim. Minting one automatically every night makes the
claim meaningless, fills the changelog with noise, and produces a stream of
GitHub Releases nobody reads. This workflow provides what nightly builds are
actually wanted for — a way to run current `main` — without any of that.

## What a failure means

`main` does not build as a container image. It does not affect any published
release, but `:edge` will be stale until it is fixed.
