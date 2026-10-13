import argparse
import getpass
import io
import json
import os
import sys
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Final, Never, TextIO, TypedDict, override

from totp_batch.core import CoreInputError, generate_batch, totp
from totp_batch.input import (
    InputError,
    parse_batch,
    parse_single_stdin,
    read_hidden_secret,
)
from totp_batch.model import OUTPUT_SCHEMA, BatchRecord, GeneratedCode, OtpParameters

MAX_STDIN_BYTES: Final = 256 * 1024
DEFAULT_GETPASS: Final = getpass.getpass


class JsonCode(TypedDict):
    label: str | None
    code: str
    generated_at: int
    window_start: int
    window_end: int


class JsonOutput(TypedDict):
    schema: str
    codes: list[JsonCode]


@dataclass(frozen=True, slots=True)
class CliOptions:
    stdin: bool
    json: bool


class CliNamespace(argparse.Namespace):
    stdin: bool
    json: bool

    def __init__(self) -> None:
        super().__init__()
        self.stdin = False
        self.json = False


class SecretSafeArgumentParser(argparse.ArgumentParser):
    @override
    def error(self, message: str) -> Never:
        del message
        self.print_usage(sys.stderr)
        self.exit(2, f"{self.prog}: error: invalid arguments\n")


@dataclass(frozen=True, slots=True)
class SingleInput:
    secret: bytes


@dataclass(frozen=True, slots=True)
class BatchInput:
    records: tuple[BatchRecord, ...]


type ParsedInput = SingleInput | BatchInput


def render_plain(codes: Sequence[GeneratedCode], *, batch: bool) -> str:
    if batch:
        return "".join(f"{code.label}\t{code.code}\n" for code in codes)
    return "".join(f"{code.code}\n" for code in codes)


def render_json(codes: Sequence[GeneratedCode]) -> str:
    document = JsonOutput(
        schema=OUTPUT_SCHEMA,
        codes=[
            JsonCode(
                label=code.label,
                code=code.code,
                generated_at=code.generated_at,
                window_start=code.window_start,
                window_end=code.window_end,
            )
            for code in codes
        ],
    )
    return json.dumps(document, ensure_ascii=True, separators=(",", ":")) + "\n"


def _parse_options() -> CliOptions | int:
    parser = SecretSafeArgumentParser(
        prog="totp-batch",
        description="Generate TOTP codes offline.",
        allow_abbrev=False,
    )
    _ = parser.add_argument(
        "--stdin", action="store_true", help="read one secret or JSON Lines batch"
    )
    _ = parser.add_argument("--json", action="store_true", help="emit JSON output")
    namespace = CliNamespace()
    try:
        _ = parser.parse_args(namespace=namespace)
    except SystemExit as error:
        match error.code:
            case int(code):
                return code
            case str():
                return 2
            case None:
                return 0
    return CliOptions(
        stdin=namespace.stdin,
        json=namespace.json,
    )


def _silence_stdout() -> TextIO:
    descriptor = os.open(os.devnull, os.O_WRONLY)
    return io.TextIOWrapper(io.FileIO(descriptor, closefd=True), write_through=True)


def _read_input(options: CliOptions) -> ParsedInput:
    if not options.stdin:
        if getpass.getpass is DEFAULT_GETPASS and not sys.stderr.isatty():
            raise EOFError
        return SingleInput(read_hidden_secret(getpass.getpass))
    if sys.stdin.isatty():
        raise InputError(category="--stdin requires redirected input")
    raw = sys.stdin.buffer.read(MAX_STDIN_BYTES + 1)
    if raw.lstrip(b" \t\r\n").startswith(b"{"):
        return BatchInput(parse_batch(raw))
    return SingleInput(parse_single_stdin(raw))


def _generate(
    parsed: ParsedInput, timestamp: int
) -> tuple[tuple[GeneratedCode, ...], bool]:
    match parsed:
        case BatchInput(records=records):
            return generate_batch(records, timestamp), True
        case SingleInput(secret=secret):
            parameters = OtpParameters()
            window_start = (timestamp // parameters.period) * parameters.period
            return (
                (
                    GeneratedCode(
                        label=None,
                        code=totp(secret, timestamp, parameters),
                        generated_at=timestamp,
                        window_start=window_start,
                        window_end=window_start + parameters.period,
                    ),
                ),
                False,
            )


def _run(options: CliOptions, clock: Callable[[], int] | None) -> str | int:
    try:
        parsed = _read_input(options)
        timestamp = (time.time_ns() // 1_000_000_000) if clock is None else clock()
        codes, batch = _generate(parsed, timestamp)
        return render_json(codes) if options.json else render_plain(codes, batch=batch)
    except KeyboardInterrupt:
        return 130
    except EOFError:
        return 130
    except (CoreInputError, InputError):
        return 2
    except OSError:
        return 1


def main(*, clock: Callable[[], int] | None = None) -> int:
    options = _parse_options()
    if isinstance(options, int):
        return options
    output = _run(options, clock)
    if isinstance(output, int):
        return output
    try:
        _ = sys.stdout.write(output)
        _ = sys.stdout.flush()
    except OSError:
        try:
            sys.stdout = _silence_stdout()
        except OSError:
            return 1
        return 1
    return 0
