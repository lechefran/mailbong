# mailbong

`mailbong` is a CLI utility for deleting email messages using [`github.com/lechefran/mailbin`](https://github.com/lechefran/mailbin) `v0.1.2` and [`github.com/lechefran/mailban`](https://github.com/lechefran/mailban) `v0.1.2`.

## Run

```bash
MAILBIN_PASSWORD='app-password' go run . \
  -provider gmail \
  -email you@gmail.com \
  -schedule "0 0 * * *" \
  -age 30
```

It also supports configured accounts via `accounts.json`:

```bash
MAILBIN_PASSWORD='app-password' go run . -config accounts.json -account work -schedule "0 0 * * *" -age 30
```

`-age` (or `MAILBIN_AGE`) is required and must be `>= 0`.
`-schedule` is required and must be a valid 5-field cron expression.

The process stays running and triggers at matching times in local time.

Cron fields:

- minute: `0-59`
- hour: `0-23`
- day of month: `1-31`
- month: `1-12`
- day of week: `0-7` (`0` and `7` are Sunday)

Supported cron tokens per field:

- `*`
- single value (for example `5`)
- list (for example `1,15,30`)
- range (for example `1-5`)
- step (for example `*/15`, `1-10/2`, `5/10`)

## Accounts Config

Use [`accounts.example.json`](./accounts.example.json) as a template.

The optional top-level `blacklist` list maps to `mailbin.DeleteCriteria.FromAccounts`.
Before each delete run, `mailbong` also uses `mailban` to assess senders for each selected account, adds senders with a score of 80 or higher to the same criteria, and fetches IMAP `From` headers in batches of 100.
Messages from configured or generated blacklist senders match the delete criteria regardless of age.

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
- `-schedule string`: required cron schedule (`minute hour day-of-month month day-of-week`)
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
