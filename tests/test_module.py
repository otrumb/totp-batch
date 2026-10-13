import runpy
import sys
from importlib.metadata import entry_points, metadata, requires

import pytest


def test_package_module_exposes_cli_help(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # Given
    monkeypatch.setattr(sys, "argv", ["totp_batch", "--help"])
    # When
    with pytest.raises(SystemExit) as completion:
        _ = runpy.run_module("totp_batch", run_name="__main__")
    # Then
    assert completion.value.code == 0
    assert "--stdin" in capsys.readouterr().out


def test_installed_distribution_has_expected_cli_identity() -> None:
    # Given / When
    project = metadata("totp-batch")
    scripts = entry_points(group="console_scripts", name="totp-batch")
    # Then
    assert project["Name"] == "totp-batch"
    assert project["Author"] == "otrumb"
    assert next(iter(scripts)).value == "totp_batch.cli:main"
    assert requires("totp-batch") is None
