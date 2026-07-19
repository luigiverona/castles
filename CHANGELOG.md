# Changelog

## Unreleased

## 0.1.4 - 2026-07-19

- Fix HTML parsing when a hidden styled container contains styled descendants, while continuing
  to exclude hidden text and links and preserve visible content and links.
- Process destructive BeautifulSoup snapshots descendant-first so decomposed ancestors cannot
  invalidate descendants retained by later traversal steps.
- Convert bounded HTML parser failures into privacy-safe rejected messages so one malformed
  message produces a partial scan instead of aborting the mailbox scan.

## 0.1.3 - 2026-07-19

- Add guided `castles setup` with deterministic explicit/managed/interactive Downloads client
  resolution and actionable non-interactive behavior.
- Validate and normalize user-owned Google Desktop clients into an atomic private managed copy
  without deleting or persisting the source path.
- Preserve v0.1.2 tokens and OAuth hardening while adding typed privacy-safe setup failures and
  exact post-exchange scope and credential validation before token replacement.
- Publish a complete static Google OAuth setup guide, update site navigation and privacy language,
  and remove the cancelled shared-client verification initiative.
- Expand setup, client, prompt, authorization, packaging, website, security, and compatibility
  tests using synthetic values and mocked boundaries only.
- Add a checksum-verified, version-pinned quick installer and publish its inspectable command on the
  website without changing runtime, OAuth behavior, or the 0.1.2 package version.
- Harden repository documentation, package metadata, contribution guidance, CI safeguards, and
  GitHub governance without changing application behavior or the 0.1.2 package version.

## 0.1.2 - 2026-07-15

- Consolidate Gmail pagination control, simplify partial full-scan result construction, and remove
  unused internal logout and lock-path indirection without changing runtime behavior.
- Validate expired-token refresh through the production doctor and scan credential path, including
  refresh-token retention and rotation, atomic persistence, sanitized failures, and offline result
  availability.
- Give actionable, sanitized guidance for browser stalls, stale authorization tabs, localhost
  callback failures, denial, state mismatch, and the five-minute setup timeout.
- Keep the loopback callback listener responsive while the browser launcher is pending, and bound
  incomplete connections so they cannot monopolize the authorization deadline.
- Document safe OAuth troubleshooting and privacy-safe synthetic detection feedback without adding
  telemetry, mailbox evidence extraction, company rules, or detection-policy changes.
- Enforce at least 90% branch-only coverage, strengthen macOS and Windows automated behavior and
  installed-wheel smoke checks, and prevent local smoke environments from entering sdists.

## 0.1.1 - 2026-07-14

- Scope scan cleanup and finalization to the exact account and generation, and preserve safe retry
  semantics across provider and discovery interruptions.
- Reject noncanonical JSON, modified schemas or migrations, inconsistent indexes, unsafe policy
  versions, malformed Gmail responses, and untrusted Gmail authentication headers.
- Prevent symlink attacks on private state, restrict OAuth endpoints to Google, and improve doctor
  diagnostics for unsafe authorization, database, and lock paths.
- Enforce the URL/host parsing limits, bound large-mailbox confidence work, neutralize every CSV
  text field, remove mailbox addresses from normal output, and exclude caches from release archives.

## 0.1.0 - 2026-07-14

- Initial Gmail read-only release.
- Open-world mailbox entity discovery with offline public/private suffix boundaries.
- Independent identity and relationship strength with explainable policy versions.
- Privacy-minimized canonical SQLite storage and staged full-scan promotion.
- Local results, detail, JSON/CSV export, diagnostics, and authorization removal.
