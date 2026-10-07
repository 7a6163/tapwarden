# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.1] - 2026-10-08

### Added

- `tapwarden doctor` starts with the version and path of the binary that
  produced the report, so an older copy earlier on `PATH` is easy to spot.
- README: install with Homebrew (`brew install 7a6163/tap/tapwarden`).
- README: a banner image (`docs/banner.webp`, kept out of the crate package).

## [0.3.0] - 2026-10-06

### Changed

- The agent socket moved to `~/Library/Application Support/tapwarden/agent.sock`.
  It used to live under `$TMPDIR`, which macOS purges of entries nobody touched
  for a few days: after a long weekend the socket was gone while the agent kept
  running, and every `ssh` failed until a restart. **Re-run `tapwarden start`
  and update `IdentityAgent` in `~/.ssh/config`** — keep the quotes, the path
  contains a space. `start` prints the exact line.
- An expired backend session is renewed. A 401 on a fetch now logs in again and
  retries once, so a key whose first fetch failed can still load an hour later.
  To make that possible with `credentials: env`, the parsed credentials are kept
  for the agent's life; they were already in its environment the whole time.
  Keychain credentials are still never kept: renewal re-reads them behind the
  presence prompt.

### Fixed

- `tapwarden start` rejects a config whose `secret_ids` are not UUIDs or whose
  Vaultwarden `server_url` is invalid. Both used to pass, install the
  LaunchAgent, and then crash-loop under launchd.
- After a failed backend login (offline, server down, unlock prompt dismissed)
  the agent waits 30 seconds before trying, and prompting, again. Every `ssh`
  lists keys first, so it used to raise a prompt that could not succeed, once
  per configured key.
- Clients that list keys at the same moment share one fetch per key.
- A key that keeps failing the same way is logged once instead of on every
  request, so the unrotated agent log no longer grows with every `ssh`.
- `tapwarden doctor` reads the `IdentityAgent` ssh will actually use (via
  `ssh -G`) instead of judging only `SSH_AUTH_SOCK`, which macOS always points
  at its own agent. A Mac set up as the README describes now passes.
- Snippets printed by `start`, `start --fg` and `doctor` quote the socket path.

### Documentation

- README: install with `cargo install tapwarden`; the status line says
  self-reviewed rather than security-reviewed; documents the one
  credential-unlock prompt that listing can raise with `credentials: keychain`;
  adds rbw to the comparison table.

## [0.2.5] - 2026-09-28

### Fixed

- A passphrase-protected OpenSSH key is now refused when the secret is loaded,
  with an error naming the secret. Its public half is cleartext, so it used to
  be advertised to SSH and only failed after the user had approved the prompt.
- Identities are listed in config order. SSH tries keys in the order the agent
  returns them, and the order used to change between calls and restarts.
- A secret whose content is unusable (non-Ed25519, passphrase-protected, not an
  OpenSSH key) is fetched once and then skipped instead of being re-fetched on
  every request. A failed *fetch* (network, 404) is still retried.
- The key cache lock is no longer held while a secret is fetched, and `sign`
  checks the cache before loading. A key that is already in memory is usable
  while another id's fetch, or the first credential-unlock prompt, is pending.
- A Touch ID prompt that never delivers a verdict (dismissed by a screen lock,
  never drawn) now times out after two minutes instead of holding that request,
  and everyone waiting behind it, forever. The timeout is a failure, not an
  approval, and the next request prompts again.
- The LaunchAgent is started with `--socket <path>`, pinning the socket path
  `tapwarden start` printed. The shell and the launchd GUI domain can disagree
  on `XDG_RUNTIME_DIR` / `TMPDIR`, which used to leave SSH pointed at a socket
  the agent never bound. `start --fg --socket` is also available directly.
- `tapwarden start` (background) now refuses a config that resolves credentials
  from env vars instead of warning and installing an agent that launchd would
  restart into a throttled crash loop. Use `start --fg` or `credentials:
  keychain`.
- `tapwarden setup` asks whether to overwrite an existing config *before* it
  writes the new account's credentials to the Keychain. Declining used to leave
  the old config paired with the new credentials.
- `[Y/n]` prompts in `tapwarden setup` treat `yes` as yes. It used to count as
  no, which selected `credentials: env` and printed the client secret.

### Security

- Vaultwarden `server_url` is validated the same way as the BWS endpoint: it
  must have a host and carry no credentials, query, or fragment. A
  `https://user:pw@host` URL used to pass and reqwest would have sent the
  userinfo as a Basic-auth header on every request.

## [0.2.4] - 2026-09-14

### Changed

- The Touch ID gate now runs on `robius-authentication` 0.3. The prompt and the
  policy it asks for are unchanged (`DeviceOwnerAuthentication`, so a failed
  fingerprint still falls back to the account password); the new API returns as
  soon as the prompt is raised and delivers its verdict through a callback, so
  the gate waits on a channel and treats a prompt that ends without answering
  as a denial. The 0.3 Apple backend also refuses an empty prompt reason
  instead of raising `NSInvalidArgumentException`, and no longer dereferences a
  null `NSError` or unwinds a panic across the Objective-C frame.
- Dependency refresh: `argon2` 0.5 → 0.6 (the Vaultwarden KDF, still matching
  the published SDK vectors), `dirs` 6 → 7, `clap` 4.6.6, `libc` 0.2.189.

## [0.2.3] - 2026-09-08

### Fixed

- `tapwarden logs` no longer fails on a log that is not valid UTF-8. The read
  of the last 1 MiB lands at an arbitrary byte offset, so on a large log the
  seek almost always splits a character; the whole log is now decoded lossily
  instead of being rejected.

### Security

- BWS `server_endpoint` given as a full URL now rejects embedded credentials
  (`https://user:pass@host`), matching the bare-host form. They would have been
  sent as a Basic-auth header on every request.

## [0.2.2] - 2026-07-23

### Fixed

- Retry LaunchAgent bootstrap while launchd finishes removing the previous
  service, avoiding intermittent `Bootstrap failed: 5` errors on restart.

## [0.2.1] - 2026-07-22

### Security

- YubiKey assertions now require a matching credential id, user-presence flag,
  RP id, challenge, and valid signature under the public key saved at
  registration. Existing v0.2.0 YubiKey configs must register again once.
- Explicit `start --config` paths are preserved in the LaunchAgent instead of
  silently falling back to the default config.
- BWS custom endpoints must use HTTPS; plain HTTP is limited to loopback.
- Grace-mode approvals are scoped by SHA-256 public-key fingerprint instead of
  the non-unique key comment.

## [0.2.0] - 2026-07-21

### Added

- **YubiKey / FIDO2 as the presence factor**: `authorization.factor: yubikey`
  gates every signature (and every credential unlock) on a physical touch of a
  FIDO2 security key instead of Touch ID, via a `get_assertion` against a
  credential registered once with the new `tapwarden register-yubikey` command
  (touch-only on each use; the key's PIN is only needed at registration). The
  credential id is stored in the config (`authorization.yubikey.credential_id`)
  — it is only a handle, useless without the physical key. `factor` defaults to
  `touch_id`, so existing configs are unchanged. `doctor` reports whether a
  security key is connected when this factor is selected.
- **BWS access token in the macOS Keychain**: the Bitwarden Secrets Manager
  backend now supports `credentials: keychain` (mirroring the Vaultwarden
  backend). Store the token with the new `tapwarden store-token` command; the
  agent reads it lazily on first use, behind the Touch ID gate. This makes the
  background LaunchAgent work with BWS, which previously could only source the
  token from an env var that launchd does not provide. `credentials: env`
  (the default) is unchanged.
- **`tapwarden doctor`**: read-only diagnostics that check the config (load,
  validity, `0600` perms), backend credentials presence, Touch ID
  availability, the LaunchAgent load state, the agent socket (present and
  answering), and the SSH `IdentityAgent`/`SSH_AUTH_SOCK` wiring. Prints a
  `[ ok ]`/`[warn]`/`[fail]` checklist and exits non-zero on any failure.
  `--check-backend` additionally fetches every configured key from the backend
  end-to-end (needs network + credentials; keychain creds may prompt Touch ID).

### Changed

- MSRV bumped from 1.85.0 to 1.88.0 (the `time` security fix requires 1.88).

### Fixed

- **RUSTSEC-2026-0009** (DoS via stack exhaustion in `time`): upgraded
  `time` to 0.3.47. Also updated `spin` 0.9.8 → 0.9.9 (yanked).

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
