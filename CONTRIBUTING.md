# Contributing

Open an issue before a large behavioral change. Keep the single runtime path, immutable core models,
provider neutrality, data minimization, and one-word Python naming rules intact. Do not add entity
catalogs, cloud processing, URL fetching, telemetry, or provider plugins.

Use Python 3.12+, `uv`, small commits, and synthetic messages with reserved/example domains. Never
commit mailbox content, credentials, tokens, databases, or exports.

Create a temporary topic branch, keep it focused, and open a pull request against `main`. Direct
pushes to `main`, force pushes, and merge commits are not part of the project workflow. Pull requests
are squash-merged after required checks pass and review conversations are resolved; merged topic
branches are deleted automatically.

Run the complete gate documented in [README.md](README.md#development). New behavior needs tests;
branch coverage must remain at least 90%; strict mypy, Ruff, Import Linter, build, and audit must
pass. Security reports follow [SECURITY.md](SECURITY.md), not public issues.

Maintainer releases require matching versions in `pyproject.toml` and `castles.__version__`, a dated
changelog entry, the complete validation gate, inspected wheel and sdist contents, and verified
checksums. Release tags and GitHub releases are created only from reviewed `main` commits.

By participating, you agree to [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
