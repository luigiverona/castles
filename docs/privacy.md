# Privacy

Raw RFC message bytes, parsed headers, subjects, bodies, HTML, and URLs exist only during bounded
processing. Castles persists an opaque provider message key, observation time, normalized hostname
or domain, signal kind/source/strength, policy version, explanation code, and selected provenance.
It also persists deterministic final findings and scan/checkpoint metadata.

Castles never persists raw messages, full addresses or sender local parts, recipients, subjects,
bodies, HTML, attachments, complete URLs, paths, queries, OAuth data in SQLite, raw authentication
headers, or arbitrary MIME headers. OAuth authorization is stored separately with private local
permissions. Normal output and exports contain no provider message keys.

No mailbox content or findings are uploaded. Castles has no telemetry, analytics, backend, remote
URL fetch, DNS crawl, WHOIS lookup, or AI inference. The only normal network boundary is Google
OAuth and the Gmail API during setup, scan, or an explicitly requested `doctor --provider` check.

The typical Linux configuration directory is `~/.config/castles`; state is
`~/.local/state/castles`; and the database is `~/.local/state/castles/castles.db`. Private
directories use mode `0700` and sensitive files use `0600` where supported.
