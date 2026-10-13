import os
import subprocess
import sys
from dataclasses import dataclass

import pytest

from totp_batch.cli import main


@dataclass(frozen=True, slots=True)
class CommandResult:
    returncode: int
    stdout: str
    stderr: str


def run_cli(args: tuple[str, ...], stdin_data: str = "") -> CommandResult:
    environment = os.environ.copy()
    _ = environment.pop("TOTP_SECRET", None)
    completed = subprocess.run(
        [sys.executable, "-m", "totp_batch", *args],
        input=stdin_data,
        text=True,
        capture_output=True,
        check=False,
        env=environment,
    )
    return CommandResult(completed.returncode, completed.stdout, completed.stderr)


def test_help_exposes_only_supported_input_and_output_options() -> None:
    # Given / When
    result = run_cli(("--help",))
    # Then
    assert result.returncode == 0
    assert "--stdin" in result.stdout
    assert "--json" in result.stdout
    assert "--at" not in result.stdout
    assert "--file" not in result.stdout
    assert "--uri" not in result.stdout
    assert "--secret" not in result.stdout


@pytest.mark.parametrize(
    "option",
    [
        "--file",
        "--uri",
        "--secret",
        "--at",
        "--env",
        "--clipboard",
        "--qr",
        "--watch",
        "--hotp",
        "--verify",
        "--generate",
        "--seed",
    ],
)
def test_forbidden_input_option_is_usage_error(option: str) -> None:
    # Given / When
    result = run_cli((option, "value"))
    # Then
    assert result.returncode == 2


@pytest.mark.parametrize(
    "args",
    [
        ("SENTINEL_SECRET_MATERIAL",),
        ("--secret", "SENTINEL_SECRET_MATERIAL"),
    ],
    ids=("positional", "option-value"),
)
def test_usage_error_does_not_echo_rejected_secret_like_argv(
    args: tuple[str, ...],
) -> None:
    # Given / When
    result = run_cli(args)
    # Then
    assert result.returncode == 2
    assert "SENTINEL_SECRET_MATERIAL" not in result.stderr
    assert result.stdout == ""


def test_batch_is_fully_validated_before_any_output() -> None:
    # Given
    raw = '{"label":"alpha","secret":"AAAAAAAAAAAAAAAAAAAAAAAAAA"}\n{}\n'
    # When
    result = run_cli(("--stdin",), raw)
    # Then
    assert result.returncode == 2
    assert result.stdout == ""


def test_stdin_rejects_terminal_source(monkeypatch: pytest.MonkeyPatch) -> None:
    # Given
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(sys, "argv", ["totp-batch", "--stdin"])
    # When
    exit_code = main()
    # Then
    assert exit_code == 2


def test_default_mode_uses_hidden_prompt(monkeypatch: pytest.MonkeyPatch) -> None:
    # Given
    prompted = False

    def hidden_prompt(_: str) -> str:
        nonlocal prompted
        prompted = True
        raise KeyboardInterrupt

    monkeypatch.setattr("getpass.getpass", hidden_prompt)
    monkeypatch.setattr(sys, "argv", ["totp-batch"])
    monkeypatch.setenv("TOTP_SECRET", "AAAAAAAAAAAAAAAAAAAAAAAAAA")
    # When
    exit_code = main()
    # Then
    assert prompted
    assert exit_code == 130


def test_single_success_uses_internal_clock_and_code_only_output(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # Given
    def hidden_prompt(_: str) -> str:
        return "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"

    monkeypatch.setattr("getpass.getpass", hidden_prompt)
    monkeypatch.setattr(sys, "argv", ["totp-batch"])
    # When
    exit_code = main(clock=lambda: 59)
    # Then
    assert exit_code == 0
    assert capsys.readouterr().out == "287082\n"


@pytest.mark.parametrize(("args", "expected"), [(("--help",), 0), (("--bad",), 2)])
def test_stable_nonruntime_exit_codes(args: tuple[str, ...], expected: int) -> None:
    # Given / When
    result = run_cli(args)
    # Then
    assert result.returncode == expected


def test_interruption_has_stable_exit_code() -> None:
    # Given
    script = "from totp_batch.cli import main; raise SystemExit(main())"
    # When
    completed = subprocess.run(
        [sys.executable, "-c", script], capture_output=True, text=True, check=False
    )
    # Then
    assert completed.returncode == 130


@pytest.mark.parametrize(
    "failure_setup",
    [
        "import os; os.close(1)",
        (
            "import sys; "
            "sys.stdout.write=lambda _: (_ for _ in ()).throw(BrokenPipeError())"
        ),
    ],
    ids=("closed", "broken"),
)
def test_output_failure_is_controlled_without_traceback_or_code_on_stderr(
    failure_setup: str,
) -> None:
    # Given
    script = (
        f"{failure_setup}; from totp_batch.cli import main; raise SystemExit(main())"
    )
    # When
    completed = subprocess.run(
        [sys.executable, "-c", script, "--stdin"],
        input=b'{"label":"alpha","secret":"AAAAAAAAAAAAAAAAAAAAAAAAAA"}\n',
        capture_output=True,
        check=False,
    )
    stderr = completed.stderr.decode()
    # Then
    assert completed.returncode == 1
    assert "Traceback" not in stderr
    assert "012345" not in stderr
