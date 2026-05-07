# mailbong

`mailbong` is a CLI utility for deleting email messages using [`github.com/lechefran/mailbin`](https://github.com/lechefran/mailbin) `v0.1.2`.

## Run

```bash
go run . -config accounts.json
```

Account email, provider, IMAP address, password, age, cron, and blacklist API values are loaded only from the JSON config.

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

`mailbong` fetches blacklist addresses from `getEmailAddressesUrl` before each delete run using `apiKey` as a bearer token.
Messages from fetched blacklist senders match the delete criteria regardless of age.

- `age`: required minimum email age in days to delete (`>= 0`).
- `apiKey`: required bearer token for the blacklist email-address API.
- `cron`: required 5-field cron schedule (`minute hour day-of-month month day-of-week`).
- `getEmailAddressesUrl`: required URL for fetching blacklist sender addresses.
- `name`: optional display name; defaults to the account email.
- `email`: required IMAP login email.
- `provider`: optional provider key for built-in IMAP defaults (`gmail`, `icloud`, `outlook`, `yahoo`, `aol`, `aol_export`, `zoho`).
- `imap_addr`: optional explicit IMAP address in `host:port` format.
- `password`: required IMAP password or app password.

Password resolution for configured accounts:

- use the `password` value from the JSON config
- keep config files that contain real passwords out of git

## Configuration flags

- `-config string`: required path to accounts config JSON; defaults from `MAILBIN_CONFIG` when set

## Environment variables

- `MAILBIN_CONFIG`
