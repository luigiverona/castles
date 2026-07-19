from __future__ import annotations

import re
import tomllib
from pathlib import Path

from castles import __version__
from castles.provider.gmail.auth import SCOPE

ROOT = Path(__file__).parents[1]
EXCLUDED = {
    ".git",
    ".venv",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".import_linter_cache",
    ".smoke",
    "dist",
    "htmlcov",
    "__pycache__",
}
TEXT_SUFFIXES = {".md", ".py", ".toml", ".yml", ".yaml", ".html", ".css", ".svg", ".txt"}


def repository_files() -> tuple[Path, ...]:
    return tuple(
        path
        for path in ROOT.rglob("*")
        if path.is_file() and not any(part in EXCLUDED for part in path.relative_to(ROOT).parts)
    )


def test_version_changelog_and_lock_are_consistent() -> None:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text())
    lock = tomllib.loads((ROOT / "uv.lock").read_text())
    assert project["project"]["version"] == __version__ == "0.1.3"
    package = next(item for item in lock["package"] if item["name"] == "castles")
    assert package["version"] == __version__
    assert f"## {__version__} - 2026-07-19" in (ROOT / "CHANGELOG.md").read_text()


def test_repository_google_scope_inventory_is_exact() -> None:
    pattern = re.compile(r"https://www\.googleapis\.com/auth/[A-Za-z0-9._/-]+")
    scopes: set[str] = set()
    for path in repository_files():
        if path.suffix in TEXT_SUFFIXES:
            scopes.update(pattern.findall(path.read_text(errors="strict")))
    assert scopes == {SCOPE}


def test_no_oauth_state_or_cancelled_verification_packet_is_present() -> None:
    relative = {path.relative_to(ROOT).as_posix() for path in repository_files()}
    forbidden_names = re.compile(
        r"(^|/)(client_secret_[^/]*\.json|google\.json|gmail\.json|castles\.db|.*\.sqlite3?)$",
        re.IGNORECASE,
    )
    assert not any(forbidden_names.search(name) for name in relative)
    assert "docs/verification.md" not in relative
    assert not any("verification-packet" in name.casefold() for name in relative)


def test_no_common_secret_token_private_email_or_host_path_patterns() -> None:
    content = "\n".join(
        path.read_text(errors="strict")
        for path in repository_files()
        if path.suffix in TEXT_SUFFIXES and path.name != "uv.lock"
    )
    assert not re.search(r"gh[pousr]_[A-Za-z0-9]{30,}", content)
    assert not re.search(r"AIza[0-9A-Za-z_-]{30,}", content)
    assert "-----BEGIN " + "PRIVATE KEY-----" not in content
    assert "/home/" + "dawg/" not in content
    assert re.search(r"@[A-Za-z0-9.-]+", content)
    for address in re.findall(
        r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})", content
    ):
        address = address.casefold()
        reserved = ("example.com", "example.org", "example.net")
        assert any(address == value or address.endswith(f".{value}") for value in reserved) or (
            address.endswith((".example", ".test", ".invalid", ".local"))
        )


def test_repository_has_no_unexpected_symlinks() -> None:
    symlinks = [
        path
        for path in ROOT.rglob("*")
        if path.is_symlink() and not any(part in EXCLUDED for part in path.relative_to(ROOT).parts)
    ]
    assert symlinks == []


def test_markdown_local_links_resolve() -> None:
    link = re.compile(r"\[[^]]+\]\(([^)]+)\)")
    missing: list[str] = []
    for document in ROOT.rglob("*.md"):
        if any(part in EXCLUDED for part in document.relative_to(ROOT).parts):
            continue
        for target in link.findall(document.read_text()):
            if target.startswith(("https://", "http://", "mailto:", "#")):
                continue
            location = target.split("#", 1)[0]
            if location and not (document.parent / location).resolve().exists():
                missing.append(f"{document.relative_to(ROOT)} -> {target}")
    assert missing == []


def test_workflows_pin_actions_and_minimize_permissions() -> None:
    workflows = tuple((ROOT / ".github" / "workflows").glob("*.yml"))
    assert {path.name for path in workflows} == {"ci.yml", "pages.yml", "security.yml"}
    for workflow in workflows:
        text = workflow.read_text()
        references = re.findall(r"uses:\s*[^@\s]+@([^\s#]+)", text)
        assert references and all(re.fullmatch(r"[0-9a-f]{40}", value) for value in references)
        assert "permissions:" in text
        assert "contents: read" in text
    pages = (ROOT / ".github" / "workflows" / "pages.yml").read_text()
    assert "pages: write" in pages
    assert "id-token: write" in pages
