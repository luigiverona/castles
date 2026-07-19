# Castles

Castles is a local-first Python CLI that discovers which external entities appear to have a
relationship with an explicitly authorized Gmail mailbox. It discovers domains from message
evidence instead of using a predefined company catalog, keeps raw content ephemeral, and stores
only privacy-minimized signals and findings in SQLite.

A billing message from `billing@unknown-saas.example` can produce an `unknown-saas.example`
finding with independent identity and billing strength, first/last seen times, and a related-message
count. Scores are deterministic heuristic strengths, not probabilities.

Castles does not claim that you own or still have an account. Marketing evidence only supports a
marketing relationship. Castles does not modify mail, fetch links, follow redirects, use AI, upload
mailbox data, run a server, or provide telemetry. Gmail data travels only between Google and the
local Castles process; there is no Castles backend in that path.

## Privacy and Gmail access

Castles supports Gmail only and requests exactly:

```text
https://www.googleapis.com/auth/gmail.readonly
```

Authorization uses Google's installed-application loopback flow bound to `127.0.0.1`, with PKCE,
state checking, an exact callback path, a five-minute deadline, and bounded unrelated requests.
Credentials and state remain in private Castles directories. `results`, `show`, `export`, and the
default `doctor` mode are offline and do not construct a Gmail client.

See [the privacy model](docs/privacy.md), [public privacy policy](https://castles.luigiverona.dev/privacy.html),
and [security policy](SECURITY.md).

## Install

The verified quick installer supports Linux and macOS and requires Bash, `curl`, `uv`, and an
already-installed Python 3.12 or newer. It does not use `sudo`, install Python or uv, edit shell
startup files, run OAuth setup, or access a mailbox.

```bash
curl -fsSL https://castles.luigiverona.dev/install | bash
```

To inspect the complete bootstrap before running it:

```bash
curl -fsSLo /tmp/castles-install https://castles.luigiverona.dev/install
less /tmp/castles-install
bash /tmp/castles-install
```

The bootstrap downloads only the version-pinned 0.1.2 wheel from the official GitHub release,
checks it against an embedded SHA-256 digest, and gives the verified local wheel to `uv`. uv may
contact configured Python package indexes to resolve the wheel's declared runtime dependencies.
HTTPS authenticates delivery of the bootstrap and the embedded digest authenticates the wheel;
this is not independent code signing. A compromise of the website could replace both the
bootstrap and its digest, so use the inspect-first flow or manually verify the release assets when
that trust boundary is unsuitable.

As a manual installation alternative, install the immutable versioned wheel directly after
verifying it against `castles-0.1.2-SHA256SUMS.txt` from the same release:

```bash
uv tool install https://github.com/luigiverona/castles/releases/download/v0.1.2/castles-0.1.2-py3-none-any.whl
castles --version
```

## Set up Google authorization

Castles intentionally uses a Google Desktop OAuth client owned by you. The normal setup command
explains the requirement, reuses a private managed client, or asks before using a valid client from
your Downloads directory:

```bash
castles setup
```

Follow the **[complete Google OAuth setup guide](https://castles.luigiverona.dev/setup.html)** to
create the personal Google Cloud project, enable Gmail API, add only the exact
`https://www.googleapis.com/auth/gmail.readonly` scope, and download a Desktop app client. Keep the
JSON private and never commit or post it. Castles stores a normalized private managed copy locally;
it does not delete the source.

Advanced users can bypass discovery and prompts with the compatible positional path:

```bash
castles setup /private/path/to/google-desktop-client.json
```

Testing projects allow only listed test users and this Gmail authorization currently expires after
seven days. Moving a personal project to In production removes those Testing-specific limits, but
does not mean Google verified or endorsed it and may show an unverified warning. Review the current
Google requirements in the setup guide before changing status.

Mailbox processing and authorization remain local; there is no Castles backend. Use `--no-browser`
only if the default browser cannot open, and never share the printed sensitive URL. See the
[technical OAuth reference](docs/oauth.md) for resolution precedence, callback behavior, safe
retry, refresh, revocation, and deletion details.

## Scan and inspect

```bash
castles scan
castles results
castles show unknown-saas.example
```

The first scan examines at most the preceding 365 days. Later scans use the provider checkpoint and
fall back to a seven-day overlap if that checkpoint is stale.

```bash
castles scan --since 2026-01-01T00:00:00+00:00
castles scan --full
```

A full scan stages a complete replacement. Any bounded parser skip makes that full scan partial and
preserves the previous active results and checkpoint.

## Export and maintenance

```bash
castles export --format json --output castles.json
castles export --format csv --output castles.csv
castles doctor
castles doctor --provider
castles logout
```

JSON uses Castles export schema version 1. CSV has a fixed documented contract. `logout` removes
saved Castles Gmail authorization only; it does not remove findings.

## Local paths

Castles uses platform-native directories via `platformdirs`. Typical Linux locations are:

```text
~/.config/castles
~/.local/state/castles/castles.db
```

Castles does not import or alter state from other applications.

Raw messages, complete addresses, subjects, bodies, HTML, URLs, and attachments are not persisted.
OAuth authorization is stored separately from findings in a private local file. Normal results and
exports omit mailbox addresses and provider message keys. `results`, `show`, `export`, and the
default `doctor` mode work offline.

## Architecture

The production path is deliberately singular:

```text
Gmail -> bounded parser -> privacy-minimized signals -> entity discovery
      -> deterministic findings -> SQLite -> CLI or export
```

Immutable provider-neutral values live in `core`; `app` orchestrates narrow ports; `parse` and
`detect` normalize and assess evidence; `provider/gmail` is the only mailbox adapter; `store` owns
persistence; and `wiring.py` is the composition root. Import Linter enforces the principal module
boundaries. See [the architecture](docs/architecture.md), [detection model](docs/detection.md), and
[storage model](docs/storage.md).

## Limitations

- Gmail is the only provider in 0.1.3.
- Message headers can be spoofed. Gmail raw messages provide no per-header provenance, so Castles
  does not treat raw `Authentication-Results` fields as authenticated identity evidence.
- Conservative resolution intentionally under-merges organizations with multiple domains.
- Unknown suffixes use the PSL prevailing rule and receive an identity score cap.
- Local users with equivalent privileges or a compromised host can read local state.

## Development

```bash
git clone https://github.com/luigiverona/castles.git
cd castles
uv sync --frozen --all-groups
uv run ruff format --check .
uv run ruff check .
uv run mypy src tests
uv run lint-imports
uv run pytest --cov=castles --cov-branch --cov-report=term-missing --cov-fail-under=90
uv build
uv run pip-audit
```

Only synthetic messages and reserved/example domains belong in tests. See
[CONTRIBUTING.md](CONTRIBUTING.md), [the architecture](docs/architecture.md), and the
[privacy-safe detection feedback workflow](docs/corpus.md#reporting-detection-feedback-safely).

## Project resources

- [Website](https://castles.luigiverona.dev/)
- [Google OAuth setup guide](https://castles.luigiverona.dev/setup.html)
- [Privacy policy](https://castles.luigiverona.dev/privacy.html)
- [Support](https://castles.luigiverona.dev/support.html)
- [Issue tracker](https://github.com/luigiverona/castles/issues)
- [Security policy](SECURITY.md)
- [Changelog](CHANGELOG.md)
- [Contributing](CONTRIBUTING.md)
- [License](LICENSE)

Do not report vulnerabilities or include mailbox data in public issues. Use the private process in
[SECURITY.md](SECURITY.md).

Licensed under Apache-2.0. The bundled Public Suffix List snapshot retains its MPL-2.0 license and
provenance notice beside the resource.
