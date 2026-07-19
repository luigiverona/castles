# OAuth setup and troubleshooting

Castles preserves a user-owned Google Desktop OAuth client architecture. It requests exactly
`https://www.googleapis.com/auth/gmail.readonly`, authorizes directly between the local process and
Google, and has no shared client, broker, hosted callback, or Castles backend. The canonical
first-time guide is <https://castles.luigiverona.dev/setup.html>.

## Client resolution

`castles setup` uses one deterministic precedence:

1. an explicit positional path supplied as `castles setup CLIENT_JSON`;
2. the existing private managed client in the platform-native Castles configuration directory;
3. valid conventional Google client files among immediate children of the current user's Downloads
   directory, only in an interactive terminal and only after confirmation or explicit selection;
4. guided instructions and a path prompt when no candidate exists.

There is no environment/config override, recursive search, arbitrary home-directory search,
network download, or packaged client. An explicit path always bypasses discovery and prompts.

Downloads discovery examines a bounded number of regular, non-symlink files with conventional
Google client names. Content is size-bounded and validated before a file becomes a candidate.
Unrelated or invalid JSON is ignored. One valid candidate is offered with confirmation; multiple
candidates are displayed as numbered, privacy-safe paths and never chosen by timestamp or filename
alone.

## Interactive and non-interactive behavior

Guided prompts require both stdin and stdout to be terminal-like and must not have been disabled
with `--non-interactive`. Redirected input, pipes, CI, EOF, and scripts never prompt and never select
a Downloads file silently. With no managed or explicit client, they receive the explicit command
and canonical guide URL. A valid managed client can still be reused without a prompt.

Prompt retries are bounded. Blank input or EOF cancels without authorizing. `--no-browser` changes
only how the Google authorization URL is delivered; it does not enable Downloads selection in a
non-interactive process.

## Validation and managed import

The supplied JSON must be a bounded Google installed/Desktop client configuration with a plausible
Google client ID, required strings, Google's HTTPS authorization and token endpoints, and a
desktop-compatible HTTP loopback redirect. Web clients, service accounts, API keys, token files,
malformed JSON, unsupported redirects, symlinks, unreadable files, and oversized structures are
rejected with category-only errors that do not reproduce sensitive values.

After validation, Castles serializes only the installed-client fields required by the OAuth
library: client ID, client secret, authorization endpoint, token endpoint, and loopback redirect
URIs. The source path and unrelated fields are not retained. The private managed filename remains
`google.json` for compatibility. Typical paths are:

```text
Linux:  ~/.config/castles/google.json
macOS:  ~/Library/Application Support/castles/google.json
Windows: the platform-native Castles configuration directory\google.json
```

On POSIX systems the parent directory is mode `0700` and the file is mode `0600`. Writes use a
private temporary file in the destination directory, flush and fsync the file, reject unsafe
destination types, and atomically replace a prior regular file. Failed validation or writing
preserves the prior managed client. Windows uses the same regular-file and atomic-replacement model
without claiming POSIX modes.

Castles never deletes or modifies the source. After successful import the source is no longer
required by Castles and may be deleted manually after setup succeeds.

## Authorization transaction

After client resolution and import, Castles explains that Gmail access is read-only, mailbox
processing is local, setup does not scan, `castles scan` starts analysis, and `castles logout`
removes local authorization.

The authorization adapter uses Google's installed-application flow with:

- exact `gmail.readonly` scope;
- PKCE with a high-entropy verifier and S256 challenge;
- a cryptographic state value checked on callback;
- `127.0.0.1` only, an ephemeral port, and callback path `/` only;
- a five-minute listener deadline;
- bounded query bytes, parameters, connection time, and unrelated requests;
- unsupported-method and stale-tab rejection; and
- no embedded browser, web view, out-of-band copy/paste flow, or hosted callback.

Normal browser mode never prints the authorization URL. `--no-browser` deliberately prints the
sensitive newest URL with a warning; do not share it or place it in issues, screenshots, shell
transcripts, or chat.

After the exact callback and state checks, the Google library exchanges the code using the same
PKCE verifier. Castles then validates credential shape and requires exactly the read-only scope
before atomically saving authorization. A denial, timeout, stale callback, exchange failure,
missing or unexpected scope, malformed credentials, or persistence failure leaves the prior token
unchanged. Setup never scans Gmail, creates findings, initializes SQLite, or deletes findings.

Success is rendered without a mailbox address:

```text
Authorization saved.

Next:
  castles scan
  castles results
```

## Testing, In production, and warning screens

For an External project in Testing, only listed test users can authorize. With this Gmail scope,
the authorization and offline refresh token currently expire after seven days. Reauthorization is
therefore expected.

Moving a personal project to In production removes the Testing allowlist behavior and seven-day
expiration, but does not verify, approve, or endorse the application. An unverified warning and
Google's current user cap or other requirements may apply. Use an unverified personal client only
for yourself or people who personally trust and can verify the project. Public distribution has a
separate verification and quota model. See the canonical guide for current first-party Google
links and the personal-use recommendation.

## Browser and callback troubleshooting

- A state mismatch normally means an old authorization tab reached the current listener. Close old
  tabs and start setup again.
- A browser error connecting to `127.0.0.1` means the local redirect was blocked. Keep Castles
  running and review firewall, hardened-browser, extension, container, or remote-shell boundaries.
- A timeout does not identify one exact cause. Authorization may be incomplete, an old tab may have
  been used, browser controls may have blocked the redirect, a Testing account may not be allowed,
  or Google may have denied the application before callback.
- If the browser cannot open, retry with `castles setup --no-browser` and open only the newest
  printed URL on the same machine.
- If Google returns a denial, Castles cannot always distinguish clicking Deny, a missing Testing
  user, browser privacy behavior, or a Google-side policy block. Review the guide's Testing section.

## Tokens, refresh, logout, revocation, and deletion

The managed client identifies the Google project; the token represents the user's authorization.
They are separate private files. Existing v0.1.2 authorized-user tokens remain compatible because
they carry the OAuth client metadata required for refresh.

Expired access tokens refresh through Google during `scan` or `doctor --provider`. A successful
refresh is validated and atomically persisted, retaining the old refresh token unless Google
rotates it. Failed refresh or persistence leaves the prior file and offline findings intact.

`castles logout` removes only the local token. It does not revoke Google access, delete findings,
delete the managed client, or delete the original JSON. Revoke the grant separately in Google
Account third-party connections. Remove findings or all local configuration/state using
[the privacy documentation](privacy.md). The managed client remains until the configuration
directory is manually removed; there is currently no dedicated command that deletes it.

Never share OAuth client JSON, client IDs or secrets, tokens, authorization codes or URLs, callback
queries, state, PKCE values, mailbox addresses, private paths, Castles databases, exports, messages,
or findings. Follow [the private security-reporting process](../SECURITY.md) for a vulnerability.
