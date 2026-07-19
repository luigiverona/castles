# Security policy

## Supported versions

| Version | Security support |
|---|---|
| 0.1.x | Supported |

## Report a vulnerability

Do not open a public issue. Use the repository **Security** page, choose **Advisories**, and select
**Report a vulnerability**. Include a concise impact description and synthetic reproduction. Allow
90 days for coordinated disclosure and avoid public details before a fix is available.

Never submit OAuth client JSON, tokens, mailbox addresses, messages, sender addresses, provider
message keys, databases, exports, or other private user data. If private reporting is unavailable,
open a minimal public issue asking for a private channel without vulnerability details.

The security boundary covers local Gmail read-only processing. Important mitigations include exact
least-privilege scope, PKCE and state-validated loopback OAuth on `127.0.0.1`, bounded parsing,
attachment exclusion, no URL fetching, private local permissions, canonical fingerprinted storage,
parameterized SQLite, staged full scans, read-only local queries, sanitized errors, pinned CI
actions, dependency audits, and synthetic fixtures.

For authorization failure modes, safe retry steps, token-file behavior, and the complete list of
OAuth information that must not be posted, see [OAuth setup and troubleshooting](docs/oauth.md).

Residual risks include spoofed unauthenticated headers, unknown parser/dependency flaws, malicious
terminal environments, and local compromise by an account with equivalent privileges.
