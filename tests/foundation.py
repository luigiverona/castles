from typer.testing import CliRunner

from castles import __version__
from castles.cli.main import app


def test_version() -> None:
    result = CliRunner().invoke(app, ["--version"])
    assert result.exit_code == 0
    assert result.stdout == f"Castles {__version__}\n"


def test_help() -> None:
    result = CliRunner().invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "Discover mailbox entities" in result.stdout
