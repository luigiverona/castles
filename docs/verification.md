# Google OAuth verification preparation

This document contains public, reviewable submission material for Castles. It contains no OAuth
client identifier, project identifier, token, authorization code, mailbox identity, private contact
address, or test-account information. Official Google policy sources were reviewed on 2026-07-15.

## Application identity

- Application name: Castles
- Homepage: <https://castles.luigiverona.dev/>
- Privacy policy: <https://castles.luigiverona.dev/privacy.html>
- Support: <https://castles.luigiverona.dev/support.html>
- Authorized parent domain: `luigiverona.dev`
- Public repository: <https://github.com/luigiverona/castles>
- Developer contact: configured privately in the dedicated Google Cloud project
- Public support contact: withheld until routing, destination verification, forwarding acceptance,
  and explicit publication approval are complete

The GitHub Pages domain-verification TXT record for the personal `luigiverona` account must remain
in public DNS permanently. Google Search Console must verify the root Domain property
`luigiverona.dev` using an owner or editor of the dedicated Castles Google Cloud project. Ownership
of the root Domain property covers `castles.luigiverona.dev`.

## Scope request

Request exactly:

```text
https://www.googleapis.com/auth/gmail.readonly
```

Do not request identity, profile, email, OpenID, write, send, compose, modify, settings, Drive,
Contacts, or any other scope unless Google explicitly requires a basic identity scope and Castles
first proves that the implementation needs it.

## Scope justification

Castles discovers external entities and relationship indicators from evidence in a Gmail mailbox
that the user explicitly authorizes. It requires read access to message headers, links, and relevant
visible content to identify domains and explain signals such as authentication, billing,
subscription, commerce, support, activity, lifecycle, or marketing relationships. Gmail
metadata-only access cannot provide the message-body and link evidence required by this declared
functionality.

Castles never sends, modifies, deletes, labels, moves, drafts, or composes mail. Processing occurs
on the user's device. Raw message content is not uploaded to a Castles server and is handled only
ephemerally by bounded parsing. Castles persists only privacy-minimized derived signals, findings,
scan metadata, and checkpoints in local SQLite.

## Data flow

```text
Google OAuth
    -> local Castles process
    -> Gmail read-only API
    -> ephemeral raw message
    -> bounded local parser
    -> minimized signals and findings
    -> local SQLite
```

There is no Castles server in the Gmail-data path. The public static website receives no OAuth
callback, Gmail data, findings, telemetry, or application error reports.

## Verification video script

Record only after explicit approval, using a dedicated test Gmail account containing synthetic
messages and reserved domains. Do not use a personal mailbox, private address, real service,
private client file path, or real-world finding.

1. Start with a clean browser profile and an isolated mode-0700 Castles environment installed from
   the exact candidate wheel.
2. Set the Google consent interface to English and keep the browser address bar visible.
3. Show the public Castles homepage, privacy policy, and support page. Briefly identify the local
   processing and Gmail read-only disclosures.
4. In a clean terminal, run setup with the production desktop client through the explicit custom
   client path used during verification. Do not reveal the path or file contents.
5. Show the complete Google consent flow, the Castles application name, the visible browser address
   bar as Google requires, and the exact Gmail read-only permission. Do not zoom in on, transcribe,
   or separately publish the client identifier.
6. Approve access and show the successful protected loopback callback and sanitized terminal
   success message.
7. Run a minimal scan of the synthetic mailbox. Show that the scan completes and that the command
   exposes no mailbox identity or message content.
8. Run `castles results` and show privacy-safe synthetic findings only. Explain how the requested
   scope enables headers, visible text, and link evidence used by this feature.
9. Block network sockets and show that local results remain available without Gmail or a Castles
   server.
10. Run `castles logout`, confirm saved authorization is removed, and show that local findings
    remain available offline.
11. End on the privacy policy's authorization-removal and local-deletion instructions.

Upload the approved recording as an unlisted YouTube video. The submitted video must show the same
application name, branding, production client, exact scope, and end-to-end functionality submitted
for verification.

### Shot list

1. Public homepage and URLs
2. Privacy and support disclosures
3. Isolated candidate installation and version
4. English Google consent screen with visible address bar
5. Exact Gmail read-only permission
6. Successful loopback completion
7. Synthetic minimal scan
8. Synthetic results
9. Socket-blocked offline results
10. Logout and retained local findings
11. Local deletion instructions

### Redaction checklist

- No personal or maintainer mailbox
- No private destination or developer-contact address
- No real sender, recipient, local part, subject, body, URL, message ID, or header
- No OAuth URL transcription, callback query, state, authorization code, access token, refresh
  token, client JSON, client file path, or token path
- No terminal history, browser history, notifications, bookmarks, profile names, or unrelated tabs
- No database, export contents, raw message, or real entity finding
- Only synthetic messages and reserved domains

## Security-assessment position

Castles is a distributed desktop CLI. Restricted Gmail data is requested by and processed on the
user's own device. Castles does not operate a third-party backend that receives Gmail data; the
public website does not receive Gmail data; and Castles does not transmit findings, analytics,
telemetry, or automatic error reports.

These are factual implementation properties, not a claim of exemption. Google should determine
whether an external security assessment applies.

## Website and domain deployment gates

- Host only the static `site/` artifact on GitHub Pages.
- Keep Cloudflare limited to authoritative DNS and domain management.
- Keep the permanent GitHub Pages verification TXT record.
- Configure the repository Pages custom domain before publishing the CNAME in DNS.
- Publish only the CNAME `castles` -> `luigiverona.github.io`, with Cloudflare proxy status set to
  DNS only. Do not create wildcard records.
- Verify the CNAME with `dig`, then verify GitHub DNS health and certificate issuance.
- Confirm canonical HTTPS URLs and no mixed content before enabling Enforce HTTPS.
- Keep the Google Search Console root Domain-property TXT record permanently after verification.
- Do not publish a support email address until routing DNS is reviewed, the private destination is
  verified without disclosure, forwarding is tested from a different mailbox, and publication is
  explicitly approved.
- Do not submit OAuth verification, publish a production client identifier, change setup behavior,
  or release version 0.2.0 without the corresponding approval gate.

## Official policy references

- <https://developers.google.com/identity/protocols/oauth2/native-app>
- <https://developers.google.com/workspace/gmail/api/auth/scopes>
- <https://developers.google.com/identity/protocols/oauth2/production-readiness/restricted-scope-verification>
- <https://support.google.com/cloud/answer/13464321>
