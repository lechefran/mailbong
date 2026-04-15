# mailbong

`mailbong` is a CLI utility for deleting old email messages using [`github.com/lechefran/mailbin`](https://github.com/lechefran/mailbin) `v0.1.1`.

## Run

```bash
MAILBIN_PASSWORD='app-password' go run . \
  -provider gmail \
  -email you@gmail.com \
  -age 30
```

It also supports configured accounts via `accounts.json`:

```bash
MAILBIN_PASSWORD='app-password' go run . -config accounts.json -account work -age 30
```

`-age` (or `MAILBIN_AGE`) is required and must be `>= 0`.

## Accounts Config

Use [`accounts.example.json`](./accounts.example.json) as a template.

- `name`: optional display name; defaults to the account email.
- `email`: required IMAP login email.
- `provider`: optional provider key for built-in IMAP defaults (`gmail`, `icloud`, `outlook`, `yahoo`, `aol`, `aol_export`, `zoho`).
- `imap_addr`: optional explicit IMAP address in `host:port` format.
- `password_env`: optional env var name for this account's password.

Password resolution for configured accounts:

- use `password_env` if set and present
- otherwise fallback to `MAILBIN_PASSWORD`
- if stdin is interactive, prompt for password
- if stdin is non-interactive and no password env is available, exit with an error

## Configuration flags

- `-config string`: path to accounts config JSON
- `-account string`: account name from config to run
- `-provider string`: provider for built-in IMAP defaults
- `-imap-addr string`: explicit IMAP address in `host:port`
- `-email string`: login email for single-account mode
- `-age int`: minimum email age in days to delete (`>= 0`)
- `-concurrency int`: max concurrent account runs (`0` = unlimited)
- `-timeout duration`: per-account timeout (default `30s`)

## Environment variables

- `MAILBIN_CONFIG`
- `MAILBIN_ACCOUNT`
- `MAILBIN_PROVIDER`
- `MAILBIN_IMAP_ADDR`
- `MAILBIN_EMAIL`
- `MAILBIN_AGE`
- `MAILBIN_CONCURRENCY`
- `MAILBIN_PASSWORD`
