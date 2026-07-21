# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **`tapwarden doctor`**: read-only diagnostics that check the config (load,
  validity, `0600` perms), backend credentials presence, Touch ID
  availability, the LaunchAgent load state, the agent socket (present and
  answering), and the SSH `IdentityAgent`/`SSH_AUTH_SOCK` wiring. Prints a
  `[ ok ]`/`[warn]`/`[fail]` checklist and exits non-zero on any failure.
  `--check-backend` additionally fetches every configured key from the backend
  end-to-end (needs network + credentials; keychain creds may prompt Touch ID).

## [0.1.4] - 2026-07-20

### Changed

- Renamed the project from `sigilo` to `tapwarden`. This includes the crate
  and binary name, the config directory (`~/.config/tapwarden`), the
  LaunchAgent label (`com.tapwarden.agent`), the log file
  (`~/Library/Logs/tapwarden.log`), the Keychain service name, and all
  environment variable prefixes (`SIGILO_*` → `TAPWARDEN_*`). The old `sigilo`
  crate on crates.io is yanked; migrate by reinstalling `tapwarden` and
  renaming your `SIGILO_VW_*` env vars to `TAPWARDEN_VW_*`.

## [0.1.3] - 2026-07-06

### Added

- Publish workflow now also builds the macOS release binary, packages it
  with a sha256 checksum, and creates a GitHub Release (body sourced from
  this file's per-version section) via `softprops/action-gh-release`.

## [0.1.2] - 2026-07-06

### Added

- crates.io publish GitHub Action, triggered on `v*` tags: verifies the tag
  matches `Cargo.toml`, runs the full CI gate, then `cargo publish`.
- Cargo package metadata (`repository`, `readme`, `keywords`, `categories`)
  for the crates.io listing.
- README steps for self-signed code signing so a rebuilt binary keeps a
  stable code identity for the macOS Keychain.

### Changed

- Bump edition 2021 → 2024 (rust-version already required 1.85.0, which is
  where 2024 stabilized). Reformatted imports to the new style edition; the
  two test-only `std::env::set_var`/`remove_var` calls are now wrapped in
  `unsafe` blocks as 2024 requires.

### Fixed

- Harden `setup`/`daemon` file handling per security review: keychain
  entries are stored before the config write (no config pointing at entries
  that don't exist on a mid-store failure), pre-planted symlinks at the
  config/plist/log paths are rejected, and `tapwarden logs` reads at most the
  last 1 MiB of the log file.

## [0.1.1] - 2026-07-04

### Changed

- Upgrade `ssh-agent-lib` 0.5 → 0.6 (`Identity`/`SignRequest` now carry a
  `PublicCredential` instead of a bare public key).

### Fixed

- Pin `signature` to the version `ssh-key` uses; a v3 release resolved into a
  second copy of the crate and broke `PrivateKey::try_sign` on a clean build.
  CI now builds `--locked` so the lockfile is authoritative.

## [0.1.0] - 2026-07-04

First working release: a daily-drivable SSH agent.

### Added

- SSH agent (ssh-agent-lib) serving Ed25519 keys, with a **Touch ID prompt
  authorizing every signature** — no silent signing path, even for same-uid
  processes. `per_use` and per-key `grace` authorization modes.
- **Bitwarden Secrets Manager backend**: direct REST client (no official SDK
  dependency), machine-account access tokens scoped to a single project.
- **Vaultwarden backend**: personal API key login against a dedicated account,
  serving SSH-key vault items (cipher type 5); PBKDF2 and Argon2id KDFs
  mirrored from the official SDK source and verified against its published
  test vectors.
- **`tapwarden setup`**: interactive wizard — logs in once (TOTP 2FA supported),
  obtains the personal API key automatically, lists the account's SSH keys
  for selection, and writes the config.
- **macOS Keychain credential storage** (`credentials: keychain`, the setup
  default): backend credentials never live in env vars, and **every read is
  gated by its own Touch ID prompt** — a recent signature approval never
  unlocks them. Env-var mode remains available for CI.
- **LaunchAgent daemon**: `tapwarden start` installs a per-user LaunchAgent
  (auto-start at login, restart on crash); `stop`, `logs`, `uninstall`,
  `socket-path` round out the CLI. A one-line `IdentityAgent` entry in
  `~/.ssh/config` replaces `SSH_AUTH_SOCK` exports.

### Security

- Private keys, tokens, and the master password exist in memory only; backend
  credentials are dropped from memory after the first successful
  authentication. Error messages never carry secret material or response bodies.
- EncString decryption verifies the HMAC in constant time **before**
  decrypting; KDF parameters from the server are bounds-checked (downgrade /
  DoS / overflow).
- HTTPS enforced (localhost exempt for development); HTTP redirects disabled;
  response bodies hard-capped.
- Agent socket in a per-user 0700 runtime directory validated against symlink
  planting; umask tightened before bind; a live instance cannot be displaced
  by a second `start`.
