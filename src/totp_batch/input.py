import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import Final, override

from totp_batch.core import CoreInputError, decode_base32
from totp_batch.model import Algorithm, BatchRecord, OtpParameters

MAX_BATCH_BYTES: Final = 256 * 1024
MAX_LINE_BYTES: Final = 2048
MAX_RECORDS: Final = 100
MAX_PERIOD_SECONDS: Final = 86_400
UNICODE_ESCAPE_LENGTH: Final = 4
CONTROL_CHARACTER_LIMIT: Final = 0x20
HIGH_SURROGATE_START: Final = 0xD800
LOW_SURROGATE_END: Final = 0xDFFF
LABEL_PATTERN: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z", re.ASCII)
RECORD_KEYS: Final = frozenset({"label", "secret", "algorithm", "digits", "period"})

type JsonField = str | int


def _unicode_escape(text: str, start: int) -> tuple[str, int]:
    digits = text[start : start + UNICODE_ESCAPE_LENGTH]
    if len(digits) != UNICODE_ESCAPE_LENGTH or any(
        digit not in "0123456789abcdefABCDEF" for digit in digits
    ):
        raise InputError(category="invalid JSON unicode escape")
    codepoint = int(digits, 16)
    if HIGH_SURROGATE_START <= codepoint <= LOW_SURROGATE_END:
        raise InputError(category="invalid JSON unicode escape")
    return chr(codepoint), start + UNICODE_ESCAPE_LENGTH


@dataclass(frozen=True, slots=True)
class InputError(Exception):
    category: str

    @override
    def __str__(self) -> str:
        return self.category


def read_hidden_secret(prompt: Callable[[str], str]) -> bytes:
    return decode_base32(prompt("Base32 secret: "))


def parse_single_stdin(raw: bytes) -> bytes:
    if raw.endswith(b"\r\n"):
        encoded = raw[:-2]
    elif raw.endswith(b"\n"):
        encoded = raw[:-1]
    else:
        encoded = raw
    if not encoded or b"\r" in encoded or b"\n" in encoded:
        raise InputError(category="stdin must contain one Base32 line")
    try:
        return decode_base32(encoded.decode("ascii"))
    except (UnicodeDecodeError, CoreInputError):
        raise InputError(category="invalid Base32 stdin") from None


def _json_string(text: str, start: int) -> tuple[str, int]:
    if start >= len(text) or text[start] != '"':
        raise InputError(category="JSON string expected")
    result: list[str] = []
    index = start + 1
    escapes: Final = {
        '"': '"',
        "\\": "\\",
        "/": "/",
        "b": "\b",
        "f": "\f",
        "n": "\n",
        "r": "\r",
        "t": "\t",
    }
    while index < len(text):
        character = text[index]
        if character == '"':
            return "".join(result), index + 1
        if ord(character) < CONTROL_CHARACTER_LIMIT:
            raise InputError(category="invalid JSON string")
        if character != "\\":
            result.append(character)
            index += 1
            continue
        index += 1
        if index >= len(text):
            raise InputError(category="invalid JSON escape")
        escape = text[index]
        if escape == "u":
            character, index = _unicode_escape(text, index + 1)
            result.append(character)
            continue
        replacement = escapes.get(escape)
        if replacement is None:
            raise InputError(category="invalid JSON escape")
        result.append(replacement)
        index += 1
    raise InputError(category="unterminated JSON string")


def _skip_space(text: str, start: int) -> int:
    index = start
    while index < len(text) and text[index] in " \t\r\n":
        index += 1
    return index


def _json_value(text: str, start: int) -> tuple[JsonField, int]:
    index = _skip_space(text, start)
    if index < len(text) and text[index] == '"':
        return _json_string(text, index)
    match = re.match(r"-?(?:0|[1-9][0-9]*)", text[index:])
    if match is None:
        raise InputError(category="record values must be strings or integers")
    return int(match.group()), index + match.end()


def _json_object(text: str) -> dict[str, JsonField]:
    index = _skip_space(text, 0)
    if index >= len(text) or text[index] != "{":
        raise InputError(category="JSON object expected")
    index = _skip_space(text, index + 1)
    result: dict[str, JsonField] = {}
    while index < len(text) and text[index] != "}":
        key, index = _json_string(text, index)
        if key in result:
            raise InputError(category="duplicate JSON key")
        index = _skip_space(text, index)
        if index >= len(text) or text[index] != ":":
            raise InputError(category="JSON colon expected")
        value, index = _json_value(text, index + 1)
        result[key] = value
        index = _skip_space(text, index)
        if index < len(text) and text[index] == ",":
            index = _skip_space(text, index + 1)
            if index >= len(text) or text[index] == "}":
                raise InputError(category="JSON member expected")
            continue
        break
    if index >= len(text) or text[index] != "}":
        raise InputError(category="JSON object terminator expected")
    if _skip_space(text, index + 1) != len(text):
        raise InputError(category="trailing JSON content")
    return result


def _parse_record(line: bytes) -> BatchRecord:
    try:
        value = _json_object(line.decode("utf-8"))
    except UnicodeDecodeError:
        raise InputError(category="invalid JSON record") from None
    if set(value) - RECORD_KEYS:
        raise InputError(category="record must be a known-key object")
    label = value.get("label")
    encoded = value.get("secret")
    algorithm = value.get("algorithm", Algorithm.SHA1.value)
    digits = value.get("digits", 6)
    period = value.get("period", 30)
    if not isinstance(label, str) or LABEL_PATTERN.fullmatch(label) is None:
        raise InputError(category="invalid label")
    if not isinstance(encoded, str):
        raise InputError(category="invalid secret field")
    if not isinstance(algorithm, str):
        raise InputError(category="invalid algorithm")
    try:
        parsed_algorithm = Algorithm(algorithm)
    except ValueError:
        raise InputError(category="invalid algorithm") from None
    if type(digits) is not int or digits not in (6, 8):
        raise InputError(category="invalid digits")
    if type(period) is not int or not 1 <= period <= MAX_PERIOD_SECONDS:
        raise InputError(category="invalid period")
    try:
        secret = decode_base32(encoded)
    except CoreInputError:
        raise InputError(category="invalid secret field") from None
    return BatchRecord(label, secret, OtpParameters(parsed_algorithm, digits, period))


def parse_batch(raw: bytes) -> tuple[BatchRecord, ...]:
    if not raw or len(raw) > MAX_BATCH_BYTES or raw.startswith(b"\xef\xbb\xbf"):
        raise InputError(category="invalid batch size or encoding")
    lines = raw.split(b"\n")
    if lines[-1] == b"":
        _ = lines.pop()
    if not lines or len(lines) > MAX_RECORDS:
        raise InputError(category="batch must contain 1..100 records")
    records: list[BatchRecord] = []
    labels: set[str] = set()
    secrets: set[bytes] = set()
    for raw_line in lines:
        line = raw_line[:-1] if raw_line.endswith(b"\r") else raw_line
        if not line or len(line) > MAX_LINE_BYTES:
            raise InputError(category="invalid JSON line size")
        record = _parse_record(line)
        normalized_label = record.label.casefold()
        if normalized_label in labels or record.secret in secrets:
            raise InputError(category="duplicate label or secret")
        labels.add(normalized_label)
        secrets.add(record.secret)
        records.append(record)
    return tuple(records)
