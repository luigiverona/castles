from __future__ import annotations

import hashlib
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]
INSTALLER = ROOT / "site" / "install"
VERSION = "0.1.4"
TAG = "v0.1.4"
ASSET = "castles-0.1.4-py3-none-any.whl"
URL = f"https://github.com/luigiverona/castles/releases/download/{TAG}/{ASSET}"
DIGEST = "117de05b13fe6bbb7fb75d0f9a00d09c0ee1cb46797ec8ce92dbe1c8061184dc"
QUICK_COMMAND = "curl -fsSL https://castles.luigiverona.dev/install | bash"
PAYLOAD = b"controlled offline wheel fixture\n"


def _write_executable(path: Path, text: str) -> None:
    path.write_text(text)
    path.chmod(0o755)


def _real_command(name: str) -> Path:
    result = shutil.which(name)
    assert result is not None
    return Path(result)


@dataclass
class Sandbox:
    root: Path
    bin: Path
    tool_dir: Path
    tool_bin: Path
    temporary: Path
    calls: Path
    curl_request: Path
    script: Path
    environment: dict[str, str]

    @classmethod
    def create(cls, root: Path) -> Sandbox:
        fake_bin = root / "bin"
        tool_dir = root / "uv-tools"
        tool_bin = root / "uv-bin"
        temporary = root / "temporary"
        for directory in (fake_bin, tool_dir, tool_bin, temporary):
            directory.mkdir()

        for name in ("bash", "mktemp", "rm"):
            (fake_bin / name).symlink_to(_real_command(name))

        _write_executable(
            fake_bin / "uname",
            "#!/bin/sh\nprintf '%s\\n' \"${FAKE_OS:-Linux}\"\n",
        )
        _write_executable(
            fake_bin / "curl",
            """#!/bin/sh
output=''
url=''
while [ "$#" -gt 0 ]; do
  case "$1" in
    --output) shift; output=$1 ;;
    https://*) url=$1 ;;
  esac
  shift
done
printf '%s\n' "$url" > "$FAKE_CURL_REQUEST"
case "${FAKE_CURL_MODE:-success}" in
  failure) printf '%s\n' 'curl: transport failure' >&2; exit 7 ;;
  http) printf '%s\n' 'curl: (22) HTTP 404' >&2; exit 22 ;;
  empty) : > "$output" ;;
  mismatch) printf '%s' 'different bytes' > "$output" ;;
  interrupt)
    printf '%s' "$FAKE_PAYLOAD" > "$output"
    kill -TERM "$PPID"
    exit 143
    ;;
  *) printf '%s' "$FAKE_PAYLOAD" > "$output" ;;
esac
""",
        )
        _write_executable(
            fake_bin / "uv",
            """#!/bin/sh
if [ "$1" = tool ] && [ "$2" = dir ]; then
  case " $* " in
    *' --bin '*) printf '%s\n' "$UV_TOOL_BIN_DIR" ;;
    *) printf '%s\n' "$UV_TOOL_DIR" ;;
  esac
  exit 0
fi
if [ "$1" = tool ] && [ "$2" = list ]; then
  if [ "${FAKE_UV_MANAGED:-0}" = 1 ]; then
    printf 'castles v%s (%s/castles)\n' "${FAKE_INSTALLED_VERSION:-0.1.1}" "$UV_TOOL_DIR"
    printf '%s\n' "- castles ($UV_TOOL_BIN_DIR/castles)"
  fi
  exit 0
fi
if [ "$1" = tool ] && [ "$2" = install ]; then
  printf '%s\n' "$*" >> "$FAKE_UV_CALLS"
  if [ "${FAKE_UV_INSTALL_FAIL:-0}" = 1 ]; then
    exit 1
  fi
  /bin/mkdir -p "$UV_TOOL_DIR/castles" "$UV_TOOL_BIN_DIR"
  printf '%s\n' '#!/bin/sh' "printf 'Castles %s\\n' '${FAKE_UV_RESULT_VERSION:-0.1.4}'" > "$UV_TOOL_BIN_DIR/castles"
  /bin/chmod 755 "$UV_TOOL_BIN_DIR/castles"
  exit 0
fi
exit 2
""",
        )
        (fake_bin / "python3").symlink_to(Path(sys.executable))

        digest = hashlib.sha256(PAYLOAD).hexdigest()
        script = root / "install"
        script.write_text(INSTALLER.read_text().replace(DIGEST, digest))
        script.chmod(0o755)
        calls = root / "uv-calls"
        curl_request = root / "curl-request"
        environment = {
            "PATH": os.pathsep.join((str(tool_bin), str(fake_bin))),
            "HOME": str(root / "home"),
            "TMPDIR": str(temporary),
            "XDG_CONFIG_HOME": str(root / "xdg-config"),
            "XDG_STATE_HOME": str(root / "xdg-state"),
            "XDG_DATA_HOME": str(root / "xdg-data"),
            "XDG_CACHE_HOME": str(root / "xdg-cache"),
            "UV_TOOL_DIR": str(tool_dir),
            "UV_TOOL_BIN_DIR": str(tool_bin),
            "FAKE_UV_CALLS": str(calls),
            "FAKE_CURL_REQUEST": str(curl_request),
            "FAKE_PAYLOAD": PAYLOAD.decode(),
        }
        return cls(
            root,
            fake_bin,
            tool_dir,
            tool_bin,
            temporary,
            calls,
            curl_request,
            script,
            environment,
        )

    def run(self, **overrides: str) -> subprocess.CompletedProcess[str]:
        environment = self.environment | overrides
        return subprocess.run(  # noqa: S603
            ["/bin/bash", str(self.script)],
            env=environment,
            text=True,
            capture_output=True,
            timeout=10,
            check=False,
        )

    def remove_command(self, name: str) -> None:
        (self.bin / name).unlink()

    def install_managed(self, version: str = "0.1.1") -> None:
        _write_executable(
            self.tool_bin / "castles",
            f"#!/bin/sh\nprintf 'Castles {version}\\n'\n",
        )
        self.environment["FAKE_UV_MANAGED"] = "1"
        self.environment["FAKE_INSTALLED_VERSION"] = version

    def assert_no_install_or_temporary_files(self) -> None:
        assert not self.calls.exists()
        assert list(self.temporary.iterdir()) == []


@pytest.fixture
def sandbox(tmp_path: Path) -> Sandbox:
    return Sandbox.create(tmp_path)


def test_static_installer_contract() -> None:
    text = INSTALLER.read_text()
    assert text.startswith("#!/usr/bin/env bash\n")
    assert INSTALLER.stat().st_mode & 0o777 == 0o755
    result = subprocess.run(  # noqa: S603
        ["/bin/bash", "-n", str(INSTALLER)], capture_output=True, text=True, check=False
    )
    assert result.returncode == 0, result.stderr
    assert "set -Eeuo pipefail" in text
    assert "umask 077" in text
    assert f"readonly VERSION='{VERSION}'" in text
    assert f"readonly RELEASE_TAG='{TAG}'" in text
    assert f"readonly WHEEL_FILENAME='{ASSET}'" in text
    assert f"readonly WHEEL_URL='{URL}'" in text
    match = re.search(r"readonly WHEEL_SHA256='([^']+)'", text)
    assert match is not None
    assert match.group(1) == DIGEST
    assert re.fullmatch(r"[0-9a-f]{64}", match.group(1))
    assert "/latest/" not in text
    assert "raw.githubusercontent.com" not in text
    assert not re.search(r"(^|[;&|]\s*)eval(?:\s|$)", text)
    assert not re.search(r"(^|[;&|]\s*)sudo(?:\s|$)", text)
    assert not re.search(r"(^|[;&|]\s*)source(?:\s|$)", text)
    assert not re.search(r"^\s*castles\s+(setup|scan|doctor\s+--provider)", text, re.MULTILINE)
    assert not re.search(r"(?:curl|wget).*(?:uv\.sh|python)", text, re.IGNORECASE)
    assert not re.search(r"\.(?:bashrc|zshrc)|config\.fish|profile", text)
    assert "--force" not in text
    assert "--no-python-downloads" in text
    assert '"$wheel_path"' in text
    assert text.index("actual_sha256=") < text.index("uv tool install")


def test_documentation_and_distribution_contracts() -> None:
    readme = (ROOT / "README.md").read_text()
    homepage = (ROOT / "site" / "index.html").read_text()
    workflow = (ROOT / ".github" / "workflows" / "pages.yml").read_text()
    package_workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text()
    pyproject = (ROOT / "pyproject.toml").read_text()
    assert QUICK_COMMAND in readme
    assert QUICK_COMMAND in homepage
    assert "curl -fsSLo /tmp/castles-install https://castles.luigiverona.dev/install" in readme
    assert "less /tmp/castles-install" in readme
    assert "bash /tmp/castles-install" in readme
    assert "site/install" in package_workflow
    assert '"src/castles"' in pyproject
    assert '"site"' in pyproject
    assert (
        "CNAME favicon.svg index.html install logo.svg privacy.html setup.html style.css support.html"
        in workflow
    )
    assert "-eq 9" in package_workflow


@pytest.mark.parametrize(
    ("command", "message"),
    (
        ("bash", "bash is required"),
        ("curl", "curl is required"),
        ("uv", "uv is required"),
        ("python3", "python3 is required"),
    ),
)
def test_missing_preflight_command_fails_closed(
    sandbox: Sandbox, command: str, message: str
) -> None:
    sandbox.remove_command(command)
    result = sandbox.run()
    assert result.returncode != 0
    assert message in result.stderr
    sandbox.assert_no_install_or_temporary_files()


def test_old_python_fails_closed(sandbox: Sandbox) -> None:
    sandbox.remove_command("python3")
    _write_executable(sandbox.bin / "python3", "#!/bin/sh\nexit 1\n")
    result = sandbox.run()
    assert result.returncode != 0
    assert "Python 3.12 or newer is required" in result.stderr
    sandbox.assert_no_install_or_temporary_files()


def test_unsupported_operating_system_fails_closed(sandbox: Sandbox) -> None:
    result = sandbox.run(FAKE_OS="FreeBSD")
    assert result.returncode != 0
    assert "only Linux and macOS are supported" in result.stderr
    sandbox.assert_no_install_or_temporary_files()


def test_unmanaged_path_executable_fails_closed(sandbox: Sandbox) -> None:
    _write_executable(sandbox.tool_bin / "castles", "#!/bin/sh\nexit 0\n")
    result = sandbox.run()
    assert result.returncode != 0
    assert "does not report as managed" in result.stderr
    sandbox.assert_no_install_or_temporary_files()


@pytest.mark.parametrize("mode", ("failure", "http"))
def test_transport_failures_do_not_install(sandbox: Sandbox, mode: str) -> None:
    result = sandbox.run(FAKE_CURL_MODE=mode)
    assert result.returncode != 0
    assert "download failed" in result.stderr
    sandbox.assert_no_install_or_temporary_files()


def test_empty_download_does_not_install(sandbox: Sandbox) -> None:
    result = sandbox.run(FAKE_CURL_MODE="empty")
    assert result.returncode != 0
    assert "empty or not a regular file" in result.stderr
    sandbox.assert_no_install_or_temporary_files()


def test_checksum_mismatch_reports_both_digests_and_does_not_install(sandbox: Sandbox) -> None:
    result = sandbox.run(FAKE_CURL_MODE="mismatch")
    expected = hashlib.sha256(PAYLOAD).hexdigest()
    actual = hashlib.sha256(b"different bytes").hexdigest()
    assert result.returncode != 0
    assert "wheel checksum mismatch" in result.stderr
    assert URL in result.stderr
    assert expected in result.stderr
    assert actual in result.stderr
    sandbox.assert_no_install_or_temporary_files()


def test_malformed_digest_calculation_does_not_install(sandbox: Sandbox) -> None:
    sandbox.remove_command("python3")
    wrapper = sandbox.bin / "python3"
    _write_executable(
        wrapper,
        f"""#!/bin/sh
case "$2" in
  *os.path.realpath*) printf '%s\n' '{wrapper}' ;;
  *hashlib*) printf '%s\n' 'NOT-A-DIGEST' ;;
  *) exit 1 ;;
esac
""",
    )
    result = sandbox.run()
    assert result.returncode != 0
    assert "malformed digest" in result.stderr
    sandbox.assert_no_install_or_temporary_files()


def test_interruption_cleans_temporary_files(sandbox: Sandbox) -> None:
    result = sandbox.run(FAKE_CURL_MODE="interrupt")
    assert result.returncode != 0
    sandbox.assert_no_install_or_temporary_files()


def test_success_uses_verified_local_wheel_exact_python_and_isolated_uv(
    sandbox: Sandbox,
) -> None:
    result = sandbox.run()
    assert result.returncode == 0, result.stderr
    assert sandbox.curl_request.read_text().strip() == URL
    call = sandbox.calls.read_text().strip()
    assert call.startswith("tool install ")
    assert "--force" not in call
    assert "--no-python-downloads" in call
    assert f"--python {Path(sys.executable).resolve()}" in call
    match = re.search(r"(/[^ ]+/castles-install\.[^ ]+/castles-0\.1\.4-py3-none-any\.whl)", call)
    assert match is not None
    assert not Path(match.group(1)).exists()
    assert (sandbox.tool_bin / "castles").read_text().startswith("#!/bin/sh")
    assert list(sandbox.temporary.iterdir()) == []
    assert "Checksum verified." in result.stdout
    assert "castles --version" in result.stdout
    assert "  castles setup\n" in result.stdout
    assert "castles setup /path/" not in result.stdout
    assert "castles scan" in result.stdout
    assert "castles results" in result.stdout
    assert not (sandbox.root / "home").exists()
    assert not (sandbox.root / "xdg-config").exists()
    assert not (sandbox.root / "xdg-state").exists()


def test_success_reports_tool_directory_when_not_on_path(sandbox: Sandbox) -> None:
    sandbox.environment["PATH"] = str(sandbox.bin)
    result = sandbox.run()
    assert result.returncode == 0, result.stderr
    assert f"The executable directory is not on PATH: {sandbox.tool_bin}" in result.stdout


def test_matching_uv_managed_install_is_idempotent(sandbox: Sandbox) -> None:
    sandbox.install_managed(VERSION)
    result = sandbox.run(FAKE_CURL_MODE="failure")
    assert result.returncode == 0, result.stderr
    assert f"Castles {VERSION} is already installed." in result.stdout
    assert not sandbox.curl_request.exists()
    sandbox.assert_no_install_or_temporary_files()


def test_different_uv_managed_version_uses_scoped_reinstall(sandbox: Sandbox) -> None:
    sandbox.install_managed("0.1.1")
    result = sandbox.run()
    assert result.returncode == 0, result.stderr
    call = sandbox.calls.read_text()
    assert "tool install --reinstall" in call
    assert "--force" not in call


def test_install_failure_and_post_install_mismatch_fail_closed(sandbox: Sandbox) -> None:
    failed = sandbox.run(FAKE_UV_INSTALL_FAIL="1")
    assert failed.returncode != 0
    assert "uv could not install" in failed.stderr
    assert list(sandbox.temporary.iterdir()) == []

    sandbox.calls.unlink()
    mismatch = sandbox.run(FAKE_UV_RESULT_VERSION="0.1.1")
    assert mismatch.returncode != 0
    assert "post-install validation failed" in mismatch.stderr
    assert list(sandbox.temporary.iterdir()) == []
