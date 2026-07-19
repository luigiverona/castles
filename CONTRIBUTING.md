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
changelog entry, and the complete validation gate. Build and validate the wheel, sdist, metadata,
manifests, and checksums before publishing immutable intended release assets. Verify those published
assets, record the final wheel digest, then update the bootstrap's pinned version, filename, URL,
and digest in a separate reviewed change or another proven safe release sequence. Run the installer
contract tests and verify the live Pages installer after deployment. Never turn the bootstrap into
a dynamic latest-release installer. Release tags and GitHub releases are created only from reviewed
`main` commits.

The release sdist must contain exactly the eight files in `site/`, with `site/install` executable;
the wheel must contain no `site/` files. Keep those exact manifests synchronized with the Pages and
packaging gates instead of replacing them with wildcards.

By participating, you agree to [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
