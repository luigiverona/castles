# OAuth setup and troubleshooting

Castles supports a Google OAuth client whose application type is **Desktop app** and requests
exactly `https://www.googleapis.com/auth/gmail.readonly`. Keep the downloaded client JSON private.
It contains a client secret even though installed applications cannot keep secrets confidential.

`castles setup` starts a listener on `127.0.0.1` at an ephemeral port, opens Google authorization,
and waits for at most five minutes. Complete the newest Castles authorization tab. Tabs and URLs
from earlier attempts have different state and will not work. The authorization URL is sensitive:
never share it or include it in an issue, screenshot, shell history, or chat transcript.

## Safe setup and retry

1. Use a clean Firefox or Chromium profile. Hardened browsers, including hardened LibreWolf
   profiles, can stall on Google's page before Google redirects to Castles.
2. Run `castles setup /private/path/to/client.json`.
3. If Castles cannot open a browser, retry with `castles setup --no-browser
   /private/path/to/client.json` and open the printed sensitive URL yourself.
4. Close stale authorization tabs before retrying and use only the newest tab or URL.

A stall while the browser still shows a Google page occurs before the callback; retry with a clean
browser profile. A browser error connecting to localhost occurs during the redirect to Castles;
keep Castles running, check local firewall or browser controls for `127.0.0.1`, and retry with
`--no-browser`. Castles does not detect or bypass browser privacy controls.

A state-mismatch message normally means an older authorization tab reached the current listener.
Close old tabs and retry. A denial message means Google returned a user denial; retry only if you
intend to grant read-only access. A timeout means no valid callback arrived within five minutes, so
start a new setup attempt rather than reusing the expired tab.

## Saved authorization

Castles saves authorization separately from findings in a private regular token file, mode `0600`
on POSIX systems. Expired access tokens refresh through Google during `scan` or `doctor --provider`;
successful refreshes atomically replace the file and retain the existing refresh token unless
Google validly rotates it. A failed refresh leaves the prior file and offline findings intact.

`castles logout` removes only saved Gmail authorization. It does not revoke the Google grant or
delete local findings. Revoke Castles separately in the Google account's third-party access page
when that is desired.

Never post OAuth client JSON, client IDs or secrets, tokens, authorization codes or URLs, callback
queries, state values, mailbox addresses, token paths, Castles databases, exports, messages, or
findings publicly. Follow [the private security-reporting process](../SECURITY.md) for a suspected
vulnerability.
