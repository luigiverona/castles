from __future__ import annotations

import json
import os
import stat
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from castles.config.path import Paths, private
from castles.config.setting import TokenStore, discover_client, validate_client, write_private
from castles.core.error import ConfigurationError


def client() -> dict[str, object]:
    return {
        "installed": {
            "client_id": "example.apps.googleusercontent.com",
            "client_secret": "secret",
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
        }
    }


def test_paths_and_private_files(tmp_path: Path) -> None:
    paths = Paths(tmp_path / "config", tmp_path / "state")
    paths.prepare()
    write_private(paths.client, json.dumps(client()))
    assert private(paths.config)
    assert private(paths.client)
    if os.name == "posix":
        assert paths.client.stat().st_mode & 0o777 == 0o600


def test_sensitive_paths_reject_symlinks(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.write_text("private")
    token = tmp_path / "token.json"
    token.symlink_to(target)
    with pytest.raises(ConfigurationError, match="safely"):
        TokenStore(token).load()

    directory = tmp_path / "real"
    directory.mkdir()
    linked = tmp_path / "linked"
    linked.symlink_to(directory, target_is_directory=True)
    with pytest.raises(ConfigurationError, match="regular directory"):
        Paths(linked, tmp_path / "state").prepare()
    assert not private(linked)

    state_target = tmp_path / "state-target"
    state_target.mkdir()
    state_link = tmp_path / "state-link"
    state_link.symlink_to(state_target, target_is_directory=True)
    victim = state_target / "gmail.json"
    victim.write_text("do not remove")
    with pytest.raises(ConfigurationError, match="safely"):
        TokenStore(state_link / "gmail.json").remove()
    assert victim.read_text() == "do not remove"


def test_private_write_does_not_follow_predictable_temporary_symlink(tmp_path: Path) -> None:
    destination = tmp_path / "token.json"
    victim = tmp_path / "victim"
    victim.write_text("unchanged")
    destination.with_suffix(".json.tmp").symlink_to(victim)

    write_private(destination, "private")

    assert destination.read_text() == "private"
    assert victim.read_text() == "unchanged"


def test_token_round_trip_and_remove(tmp_path: Path) -> None:
    path = tmp_path / "token.json"
    store = TokenStore(path)
    assert store.load() is None
    store.save("private")
    assert store.load() == "private"
    assert store.remove()
    assert not store.remove()


def test_missing_authorization_directory_is_an_empty_store(tmp_path: Path) -> None:
    store = TokenStore(tmp_path / "missing" / "token.json")
    assert store.load() is None
    assert not store.remove()


def test_token_read_rejects_oversize_and_changed_file_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "token.json"
    TokenStore(path).save("private")
    monkeypatch.setattr("castles.config.setting.MAX_TOKEN_BYTES", 4)
    with pytest.raises(ConfigurationError, match="safely"):
        TokenStore(path).load()

    monkeypatch.setattr("castles.config.setting.MAX_TOKEN_BYTES", 1024)
    current = path.stat()
    with (
        patch(
            "castles.config.setting.os.fstat",
            return_value=SimpleNamespace(
                st_mode=stat.S_IFREG | 0o600,
                st_dev=current.st_dev,
                st_ino=current.st_ino + 1,
            ),
        ),
        pytest.raises(ConfigurationError, match="safely"),
    ):
        TokenStore(path).load()


def test_failed_private_replace_removes_temporary_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    destination = tmp_path / "token.json"
    monkeypatch.setattr(
        "castles.config.setting.os.replace",
        lambda *args: (_ for _ in ()).throw(OSError("denied")),
    )
    with pytest.raises(ConfigurationError, match="write"):
        write_private(destination, "private")
    assert list(tmp_path.glob(".token.json.*.tmp")) == []


def test_token_removal_rejects_unsafe_and_failed_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    directory = tmp_path / "token.json"
    directory.mkdir()
    with pytest.raises(ConfigurationError, match="regular file"):
        TokenStore(directory).remove()

    path = tmp_path / "saved.json"
    path.write_text("private")
    original_lstat = Path.lstat

    def fail_saved(value: Path, *args: object, **kwargs: object) -> os.stat_result:
        if value == path:
            raise OSError("denied")
        return original_lstat(value, *args, **kwargs)

    with monkeypatch.context() as current:
        current.setattr(Path, "lstat", fail_saved)
        with pytest.raises(ConfigurationError, match="inspected"):
            TokenStore(path).remove()
    with monkeypatch.context() as current:
        current.setattr(
            Path, "unlink", lambda *args, **kwargs: (_ for _ in ()).throw(OSError("denied"))
        )
        with pytest.raises(ConfigurationError, match="removed"):
            TokenStore(path).remove()


def test_client_validation(tmp_path: Path) -> None:
    path = tmp_path / "client.json"
    path.write_text(json.dumps(client()))
    assert "installed" in validate_client(path)
    path.write_text('{"web": {}}')
    with pytest.raises(ConfigurationError, match="desktop"):
        validate_client(path)


def test_client_validation_rejects_missing_and_wrong_shape(tmp_path: Path) -> None:
    with pytest.raises(ConfigurationError):
        validate_client(tmp_path / "missing.json")
    path = tmp_path / "client.json"
    for content in ('{"installed": []}', '{"installed": {"client_id": "id"}}'):
        path.write_text(content)
        with pytest.raises(ConfigurationError):
            validate_client(path)


def test_client_validation_rejects_non_google_oauth_endpoints(tmp_path: Path) -> None:
    path = tmp_path / "client.json"
    document = client()
    installed = document["installed"]
    assert isinstance(installed, dict)
    installed["token_uri"] = "https://attacker.example/token"
    path.write_text(json.dumps(document))
    with pytest.raises(ConfigurationError, match="desktop"):
        validate_client(path)


def test_client_discovery_is_bounded_and_validates(tmp_path: Path) -> None:
    assert discover_client(tmp_path) is None
    downloads = tmp_path / "Downloads"
    downloads.mkdir()
    (downloads / "credentials.json").write_text("{}")
    valid = downloads / "client_secret_example.json"
    valid.write_text(json.dumps(client()))
    assert discover_client(tmp_path) == valid


def test_client_discovery_handles_directory_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    downloads = tmp_path / "Downloads"
    downloads.mkdir()
    monkeypatch.setattr(Path, "iterdir", lambda _: (_ for _ in ()).throw(OSError("denied")))
    assert discover_client(tmp_path) is None


def test_client_discovery_returns_none_when_candidates_are_invalid(tmp_path: Path) -> None:
    downloads = tmp_path / "Downloads"
    downloads.mkdir()
    (downloads / "credentials.json").write_text("{}")
    assert discover_client(tmp_path) is None


def test_private_file_and_token_errors(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "private.json"
    with monkeypatch.context() as current:
        current.setattr(
            "castles.config.setting.os.open",
            lambda *args: (_ for _ in ()).throw(OSError("denied")),
        )
        with pytest.raises(ConfigurationError, match="write"):
            write_private(path, "secret")
    path.write_text("private")
    store = TokenStore(path)
    monkeypatch.setattr(
        Path, "lstat", lambda *args, **kwargs: (_ for _ in ()).throw(OSError("denied"))
    )
    with pytest.raises(ConfigurationError, match="read safely"):
        store.load()
