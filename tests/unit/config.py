from __future__ import annotations

import json
import os
import stat
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from castles.config.path import Paths, private
from castles.config.setting import (
    MAX_CLIENT_BYTES,
    TokenStore,
    discover_clients,
    import_client,
    validate_client,
    write_private,
)
from castles.core.error import (
    ClientEndpointError,
    ClientMalformedError,
    ClientOversizedError,
    ClientRedirectError,
    ClientTypeError,
    ConfigurationError,
)


def client() -> dict[str, object]:
    return {
        "installed": {
            "client_id": "example.apps.googleusercontent.com",
            "client_secret": "secret",
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
            "redirect_uris": ["http://localhost"],
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
                st_size=current.st_size,
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
    assert validate_client(path).client_id.endswith(".apps.googleusercontent.com")
    path.write_text('{"web": {}}')
    with pytest.raises(ConfigurationError, match="Desktop"):
        validate_client(path)


def test_client_validation_rejects_missing_and_wrong_shape(tmp_path: Path) -> None:
    with pytest.raises(ConfigurationError):
        validate_client(tmp_path / "missing.json")
    path = tmp_path / "client.json"
    for content in ('{"installed": []}', '{"installed": {"client_id": "id"}}'):
        path.write_text(content)
        with pytest.raises(ConfigurationError):
            validate_client(path)
    directory = tmp_path / "directory.json"
    directory.mkdir()
    with pytest.raises(ConfigurationError, match="regular"):
        validate_client(directory)


def test_client_validation_rejects_non_google_oauth_endpoints(tmp_path: Path) -> None:
    path = tmp_path / "client.json"
    document = client()
    installed = document["installed"]
    assert isinstance(installed, dict)
    installed["token_uri"] = "https://attacker.example/token"
    path.write_text(json.dumps(document))
    with pytest.raises(ClientEndpointError, match="endpoints"):
        validate_client(path)


def test_client_discovery_is_bounded_and_validates(tmp_path: Path) -> None:
    assert not discover_clients(tmp_path).downloads_available
    downloads = tmp_path / "Downloads"
    downloads.mkdir()
    (downloads / "credentials.json").write_text("{}")
    valid = downloads / "client_secret_example.json"
    valid.write_text(json.dumps(client()))
    assert discover_clients(tmp_path).candidates[0].path == valid


def test_client_discovery_handles_directory_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    downloads = tmp_path / "Downloads"
    downloads.mkdir()
    monkeypatch.setattr(Path, "iterdir", lambda _: (_ for _ in ()).throw(OSError("denied")))
    assert discover_clients(tmp_path).candidates == ()


def test_client_discovery_returns_none_when_candidates_are_invalid(tmp_path: Path) -> None:
    downloads = tmp_path / "Downloads"
    downloads.mkdir()
    (downloads / "credentials.json").write_text("{}")
    assert discover_clients(tmp_path).candidates == ()


def test_client_validation_categories_and_redaction(tmp_path: Path) -> None:
    path = tmp_path / "client.json"
    secret = "synthetic-private-client-secret"
    identifier = "synthetic-private-client.apps.googleusercontent.com"

    cases: tuple[tuple[str, type[ConfigurationError]], ...] = (
        ("not-json", ClientMalformedError),
        ('{"web": {}}', ClientTypeError),
        ('{"type": "service_account"}', ClientTypeError),
        ('{"api_key": "synthetic-private-api-key"}', ClientTypeError),
        ('{"token": "synthetic-private-token"}', ClientTypeError),
        (json.dumps({"installed": client()["installed"], "web": {}}), ClientTypeError),
    )
    for content, error in cases:
        path.write_text(content)
        with pytest.raises(error) as caught:
            validate_client(path)
        assert secret not in str(caught.value)
        assert identifier not in str(caught.value)

    document = client()
    installed = document["installed"]
    assert isinstance(installed, dict)
    installed["client_id"] = identifier
    installed["client_secret"] = secret
    installed["redirect_uris"] = ["https://attacker.example/callback"]
    path.write_text(json.dumps(document))
    with pytest.raises(ClientRedirectError) as caught:
        validate_client(path)
    assert secret not in str(caught.value)
    assert identifier not in str(caught.value)


def test_client_validation_bounds_size_depth_and_redirects(tmp_path: Path) -> None:
    path = tmp_path / "client.json"
    path.write_text("x" * (MAX_CLIENT_BYTES + 1))
    with pytest.raises(ClientOversizedError):
        validate_client(path)

    nested: object = "value"
    for _ in range(12):
        nested = {"next": nested}
    path.write_text(json.dumps({"installed": nested}))
    with pytest.raises(ClientMalformedError):
        validate_client(path)

    for redirect in (
        "file:///private/callback",
        "javascript:alert(1)",
        "http://attacker.example",
        "http://127.0.0.1/callback",
        "http://127.0.0.1:invalid",
    ):
        document = client()
        installed = document["installed"]
        assert isinstance(installed, dict)
        installed["redirect_uris"] = [redirect]
        path.write_text(json.dumps(document))
        with pytest.raises(ClientRedirectError):
            validate_client(path)


def test_managed_import_is_normalized_private_atomic_and_preserves_source(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "source.json"
    document = client()
    installed = document["installed"]
    assert isinstance(installed, dict)
    installed["project_id"] = "synthetic-private-project"
    document["unrelated"] = {"private": "value"}
    source.write_text(json.dumps(document))
    original = source.read_bytes()
    destination = tmp_path / "managed" / "google.json"

    import_client(destination, validate_client(source))

    managed = json.loads(destination.read_text())
    assert set(managed) == {"installed"}
    assert set(managed["installed"]) == {
        "auth_uri",
        "client_id",
        "client_secret",
        "redirect_uris",
        "token_uri",
    }
    assert "project_id" not in destination.read_text()
    assert str(source) not in destination.read_text()
    assert source.read_bytes() == original
    if os.name == "posix":
        assert destination.parent.stat().st_mode & 0o777 == 0o700
        assert destination.stat().st_mode & 0o777 == 0o600

    previous = destination.read_bytes()
    monkeypatch.setattr(
        "castles.config.setting.os.replace",
        lambda *args: (_ for _ in ()).throw(OSError("synthetic-private-failure")),
    )
    with pytest.raises(ConfigurationError, match="preserved"):
        import_client(destination, validate_client(source))
    assert destination.read_bytes() == previous


def test_managed_import_rejects_symlink_and_malformed_replacement(tmp_path: Path) -> None:
    source = tmp_path / "source.json"
    source.write_text(json.dumps(client()))
    destination = tmp_path / "managed" / "google.json"
    destination.parent.mkdir()
    victim = tmp_path / "victim"
    victim.write_text("unchanged")
    destination.symlink_to(victim)
    with pytest.raises(ConfigurationError):
        import_client(destination, validate_client(source))
    assert victim.read_text() == "unchanged"

    destination.unlink()
    import_client(destination, validate_client(source))
    previous = destination.read_bytes()
    source.write_text("not-json")
    with pytest.raises(ClientMalformedError):
        validate_client(source)
    assert destination.read_bytes() == previous


def test_discovery_is_immediate_regular_bounded_and_never_selects_multiple(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    downloads = tmp_path / "Downloads"
    downloads.mkdir()
    first = downloads / "client_secret_first.json"
    second = downloads / "client_secret_second.json"
    first.write_text(json.dumps(client()))
    second.write_text(json.dumps(client()))
    nested = downloads / "nested"
    nested.mkdir()
    (nested / "client_secret_nested.json").write_text(json.dumps(client()))
    (tmp_path / "client_secret_home.json").write_text(json.dumps(client()))
    linked = downloads / "client_secret_linked.json"
    linked.symlink_to(first)

    discovery = discover_clients(tmp_path)
    assert discovery.downloads_available
    assert tuple(candidate.path for candidate in discovery.candidates) == (first, second)
    assert all(
        "example.apps.googleusercontent.com" not in item.label for item in discovery.candidates
    )

    monkeypatch.setattr("castles.config.setting.MAX_CLIENT_CANDIDATES", 1)
    bounded = discover_clients(tmp_path)
    assert bounded.bounded
    assert len(bounded.candidates) == 1


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


def test_token_store_rejects_oversized_serialization(tmp_path: Path) -> None:
    with pytest.raises(ConfigurationError, match="too large"):
        TokenStore(tmp_path / "token.json").save("x" * (1024 * 1024 + 1))
