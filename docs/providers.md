# Providers

The static `MailboxProvider` contract exposes mailbox identity, provider-neutral message
enumeration, raw retrieval, the current checkpoint, checkpoint kind, and optional validation.
Provider message references are opaque. Detection receives only `NormalizedMessage` values.

Gmail is the only 0.1.4 adapter. It uses the installed-application OAuth flow and exact
`gmail.readonly` scope, bounded pagination, retryable API status handling, a 25 MiB decoded raw
message limit, and Gmail history IDs. A 404 history response becomes a typed stale-checkpoint event.

A future IMAP, Outlook, or Tuta adapter can implement the same static contract without changing
detection, confidence, findings, SQLite, results, or exports. Those providers are not implemented or
advertised as supported in this release, and there is no dynamic provider plugin system.
