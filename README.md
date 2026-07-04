# sigilo

An SSH agent that serves keys from **Bitwarden Secrets Manager** or a
**self-hosted Vaultwarden** and requires a **biometric tap (Touch ID) to
authorize every signature** — 1Password's per-use approval UX, on a headless /
least-privilege Bitwarden backend.

Status: **working agent** — Touch ID verified from an unsigned binary, both
backends implemented against the official SDK's protocol and test vectors,
security-reviewed; Vaultwarden credentials can live in the macOS Keychain
behind Touch ID; runs in the background as a LaunchAgent
(`start`/`stop`/`logs`/`uninstall`). Roadmap: BWS token in the OS keystore,
signing + Homebrew packaging.

## Why

| | backend | per-use auth |
|---|---|---|
| 1Password agent | 1Password vault | ✅ Touch ID |
| Bitwarden GUI agent | personal vault | ❌ manual unlock |
| vault-conductor / bw-agent | SM / secure notes | ❌ silent signing |
| **sigilo** | **Secrets Manager or Vaultwarden (scoped)** | ✅ Touch ID per signature |

Two guarantees the alternatives don't give you together:

1. **Least privilege** — the credential in your environment can only read the
   few SSH keys you granted it (a BWS machine token scoped to one project, or a
   dedicated Vaultwarden account that holds nothing else). Never your whole vault.
2. **Presence** — every `sign` request passes a Touch ID gate. A same-uid
   process that reaches the agent socket still can't sign silently.

Private keys exist in memory only. Nothing is ever written to disk or logged.

## Requirements

- macOS with Touch ID (the biometric prompt works from an unsigned binary —
  verified; Linux support is a future milestone)
- Rust 1.85+ (`cargo build --release` → `target/release/sigilo`)
- One of the two backends below

## Setup

```sh
mkdir -p ~/.config/sigilo
cp config.yaml.example ~/.config/sigilo/config.yaml
chmod 600 ~/.config/sigilo/config.yaml
```

Keys must be **Ed25519** in **OpenSSH format**
(`-----BEGIN OPENSSH PRIVATE KEY-----`). Credentials never go in the config
file — only the *names* of the env vars that hold them.

### Backend A: Bitwarden Secrets Manager (cloud or official self-host)

1. In the web vault, enable Secrets Manager for your organization (a free tier
   exists), switch to the Secrets Manager product, and create a project.
2. Add one secret per SSH key: name = key comment, value = the OpenSSH private key.
3. Create a **machine account**, grant it read access to that project only,
   and generate an **access token** (`0.xxxx.yyyy:zzzz`, shown once).

```yaml
# ~/.config/sigilo/config.yaml
access_token_env: BWS_ACCESS_TOKEN
secret_ids:
  - <secret uuid>
# server_endpoint: bitwarden.eu     # optional; cloud EU or self-hosted host
authorization:
  mode: per_use                     # per_use | grace
  grace_seconds: 60                 # used when mode = grace
```

```sh
export BWS_ACCESS_TOKEN='0.xxxx....'
```

### Backend B: Vaultwarden (self-hosted)

Vaultwarden does not implement Secrets Manager (proprietary-licensed), so sigilo
reads **SSH-key vault items** (cipher type 5) from a **dedicated account**
instead — least privilege via account scoping.

1. Server: add `EXPERIMENTAL_CLIENT_FEATURE_FLAGS=ssh-key-vault-item` to the
   Vaultwarden environment and restart.
2. Register a dedicated account (e.g. `sigilo@example.com`) that will hold
   **only** SSH keys.
3. In its web vault, create an **SSH key** item and paste the OpenSSH private
   key. The item's UUID is in the URL (`itemId=...`) when the item is open.
4. Run **`sigilo setup`**: it logs in once, obtains the personal API key for
   you, lets you pick the keys to serve, writes the config below, and (by
   default) stores the credentials in the **macOS Keychain** — no env vars
   needed, and every agent read of them is gated by a Touch ID prompt.

```yaml
# ~/.config/sigilo/config.yaml (written by `sigilo setup`)
backend: vaultwarden
vaultwarden:
  server_url: https://vault.example.com
  email: sigilo@example.com
  credentials: keychain   # keychain (macOS, default in setup) | env (CI / Linux)
secret_ids:
  - <cipher uuid>
authorization:
  mode: per_use
```

Fallback: answer `n` to the Keychain question (or set `credentials: env`) to
keep the credentials in env vars instead — the right choice for CI or Linux.
`sigilo setup` prints the exact lines; they come from Settings → Security →
Keys → **View API key** in the web vault:

```sh
export SIGILO_VW_CLIENT_ID='user.xxxxxxxx-....'
export SIGILO_VW_CLIENT_SECRET='...'
export SIGILO_VW_MASTER_PASSWORD='...'
```

## Run

```sh
sigilo start    # background LaunchAgent: restarts on crash, starts at login
```

`start` prints the socket path. Point SSH at it permanently — no `export`
needed in any shell:

```sh
# ~/.ssh/config
Host *
  IdentityAgent <output of `sigilo socket-path`>
```

Then:

```sh
ssh-add -L      # lists public keys, no prompt
ssh somehost    # ← Touch ID prompt per signature
```

Manage it:

```sh
sigilo stop         # stop the agent (the LaunchAgent stays installed)
sigilo logs         # last 50 lines of ~/Library/Logs/sigilo.log
sigilo uninstall    # stop the agent and remove the LaunchAgent
sigilo start --fg   # debug: run in the foreground of the current shell
```

> **Env-var credentials:** launchd does not see your shell environment. If
> your config resolves credentials from env vars (backend `bws`, or
> Vaultwarden `credentials: env`), the background agent cannot read them —
> either run `sigilo start --fg` from a shell that exports them, switch to
> `credentials: keychain` (`sigilo setup`), or add an `EnvironmentVariables`
> dict to `~/Library/LaunchAgents/com.sigilo.agent.plist` yourself.

### Git commit signing

```sh
git config --global gpg.format ssh
git config --global user.signingkey 'ssh-ed25519 AAAA... comment'   # from ssh-add -L
git config --global commit.gpgsign true
```

Each `git commit` then raises one Touch ID prompt.

### Authorization modes

- `per_use` (default): every signature prompts.
- `grace`: after an approval, the **same key** signs without a prompt for
  `grace_seconds` (measured against both monotonic and wall-clock time, so the
  window does not survive a lid-close). Other keys still prompt.

## Verifying your setup

Live end-to-end tests are opt-in (they need real credentials):

```sh
# Secrets Manager
BWS_ACCESS_TOKEN=... SIGILO_TEST_SECRET_ID=<uuid> \
  cargo test fetches_real_secret_from_bws -- --ignored --nocapture

# Vaultwarden
SIGILO_VW_SERVER=https://vault.example.com SIGILO_VW_EMAIL=sigilo@example.com \
SIGILO_VW_CLIENT_ID=... SIGILO_VW_CLIENT_SECRET=... SIGILO_VW_MASTER_PASSWORD=... \
SIGILO_TEST_CIPHER_ID=<uuid> \
  cargo test fetches_real_sshkey_from_vaultwarden -- --ignored --nocapture

# Touch ID (raises a real prompt)
cargo test touch_id_prompt_manual -- --ignored --nocapture
```

## Security model

- Every `sign` passes the `Authorizer` (Touch ID) — there is no silent signing
  path, even for same-uid processes.
- With `credentials: keychain` (Vaultwarden), the backend credentials live in
  the macOS Keychain and **every read is gated by a Touch ID prompt** — a
  recent signature approval (`grace` mode) never unlocks them. An OS-level
  keychain ACL binding the entries to the sigilo binary requires code signing
  and is future work.
- Private keys, tokens, and the master password exist in memory only; error
  messages and logs never contain secret material or server response bodies.
- The agent socket lives in a per-user 0700 directory (`$XDG_RUNTIME_DIR/sigilo`
  or a uid-suffixed temp dir), validated against symlink planting; umask is
  tightened before bind.
- Backend crypto (EncString AES-256-CBC + HMAC-SHA256, KDF derivation) mirrors
  the official Bitwarden SDK source and is tested against the SDK's published
  vectors; MACs are verified in constant time **before** decryption.
- No official Bitwarden SDK dependency — the REST surface is implemented
  directly on reqwest + rustls to keep the dependency tree small and auditable
  (`cargo audit` runs clean; the one ignored advisory is documented in
  `.cargo/audit.toml`).

## Development

```sh
cargo test                                  # unit tests, no network / no prompts
cargo clippy --all-targets -- -D warnings
cargo audit
```

Backends implement the `SecretFetcher` trait; the Touch ID gate implements
`Authorizer`. Both are mocked in tests — the default test suite touches no
network and raises no prompts.

## License

MIT
