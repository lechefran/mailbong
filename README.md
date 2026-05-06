# mailbong

`mailbong` is a CLI utility for deleting email messages using [`github.com/lechefran/mailbin`](https://github.com/lechefran/mailbin) `v0.1.2`.

## Run

```bash
MAILBIN_PASSWORD='app-password' go run . \
  -config accounts.json \
  -schedule "0 0 * * *" \
  -age 30
```

Run one configured account by name:

```bash
MAILBIN_PASSWORD='app-password' go run . -config accounts.json -account work -schedule "0 0 * * *" -age 30
```

Account email, provider, and IMAP address values are loaded only from the JSON config.
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

When `GET_ADDR_URL` is set, `mailbong` fetches blacklist addresses from that JSON API before each delete run.
Messages from fetched blacklist senders match the delete criteria regardless of age.

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

- `-config string`: required path to accounts config JSON; defaults from `MAILBIN_CONFIG` when set
- `-account string`: account name from config to run
- `-schedule string`: required cron schedule (`minute hour day-of-month month day-of-week`)
- `-age int`: minimum email age in days to delete (`>= 0`)
- `-concurrency int`: max concurrent account runs (`0` = unlimited)
- `-timeout duration`: per-account timeout (default `30s`)

## Environment variables

- `MAILBIN_CONFIG`
- `MAILBIN_ACCOUNT`
- `MAILBIN_AGE`
- `MAILBIN_CONCURRENCY`
- `MAILBIN_PASSWORD`
- `GET_ADDR_URL`
- `API_KEY`
