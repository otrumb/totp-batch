import base64

import pytest

from totp_batch.input import (
    InputError,
    parse_batch,
    parse_single_stdin,
    read_hidden_secret,
)

SECRET = base64.b32encode(bytes(range(16))).decode("ascii")
VALID_RECORD = f'{{"label":"alpha","secret":"{SECRET}"}}'


def test_hidden_reader_decodes_secret_when_prompt_succeeds() -> None:
    # Given
    def prompt(_: str) -> str:
        return SECRET

    # When
    decoded = read_hidden_secret(prompt)
    # Then
    assert decoded == bytes(range(16))


@pytest.mark.parametrize("failure", [EOFError(), KeyboardInterrupt(), OSError()])
def test_hidden_reader_propagates_terminal_failure_without_fallback(
    failure: EOFError | KeyboardInterrupt | OSError,
) -> None:
    # Given
    def prompt(_: str) -> str:
        raise failure

    # When / Then
    with pytest.raises(type(failure)):
        _ = read_hidden_secret(prompt)


@pytest.mark.parametrize("suffix", [b"", b"\n"])
def test_single_stdin_accepts_only_optional_final_newline(suffix: bytes) -> None:
    # Given
    raw = SECRET.encode("ascii") + suffix
    # When
    decoded = parse_single_stdin(raw)
    # Then
    assert decoded == bytes(range(16))


@pytest.mark.parametrize(
    "raw", [b" " + SECRET.encode(), SECRET.encode() + b" ", SECRET.encode() + b"\n\n"]
)
def test_single_stdin_rejects_surrounding_content(raw: bytes) -> None:
    # Given / When / Then
    with pytest.raises(InputError):
        _ = parse_single_stdin(raw)


def test_batch_accepts_flat_record_with_all_optional_fields() -> None:
    # Given
    raw = (
        f'{{"label":"alpha-1","secret":"{SECRET}","algorithm":"SHA256",'
        '"digits":8,"period":60}\n'
    ).encode()
    # When
    records = parse_batch(raw)
    # Then
    assert records[0].label == "alpha-1"


@pytest.mark.parametrize(
    "raw",
    [
        b"\n",
        b"\xef\xbb\xbf" + VALID_RECORD.encode(),
        b"#comment\n",
        b"{}\n",
        f'{{"label":"alpha","secret":"{SECRET}","extra":1}}\n'.encode(),
        f'{{"label":"alpha","label":"beta","secret":"{SECRET}"}}\n'.encode(),
        f'{{"label":"alpha","secret":{{"value":"{SECRET}"}}}}\n'.encode(),
        f'{{"label":"alpha","secret":"{SECRET}","digits":NaN}}\n'.encode(),
        f'{{"label":"alpha","secret":"{SECRET}","digits":true}}\n'.encode(),
        b"\xff\n",
    ],
)
def test_batch_rejects_noncanonical_json_lines(raw: bytes) -> None:
    # Given / When / Then
    with pytest.raises(InputError):
        _ = parse_batch(raw)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("label", '""'),
        ("label", '"bad label"'),
        ("label", '"-alpha"'),
        ("label", f'"{"a" * 65}"'),
        ("label", '"álpha"'),
        ("algorithm", '"MD5"'),
        ("digits", "7"),
        ("period", "0"),
        ("period", "86401"),
    ],
)
def test_batch_rejects_invalid_field_contract(field: str, value: str) -> None:
    # Given
    raw = f'{{"label":"alpha","secret":"{SECRET}","{field}":{value}}}\n'.encode()
    # When / Then
    with pytest.raises(InputError):
        _ = parse_batch(raw)


def test_batch_accepts_maximum_length_ascii_label() -> None:
    # Given
    label = "a" + ("-" * 63)
    raw = f'{{"label":"{label}","secret":"{SECRET}"}}\n'.encode()
    # When
    records = parse_batch(raw)
    # Then
    assert records[0].label == label


@pytest.mark.parametrize(
    "raw",
    [
        (VALID_RECORD + "\n" + VALID_RECORD.replace("alpha", "ALPHA") + "\n").encode(),
        (VALID_RECORD + "\n" + VALID_RECORD.replace("alpha", "beta") + "\n").encode(),
    ],
)
def test_batch_rejects_duplicate_label_or_decoded_secret(raw: bytes) -> None:
    # Given / When / Then
    with pytest.raises(InputError):
        _ = parse_batch(raw)


@pytest.mark.parametrize(
    "raw",
    [
        ((VALID_RECORD + "\n") * 101).encode(),
        (b" " * 2049) + b"\n",
        (b" " * 2048 + b"\n") * 100 + (b" " * 51201),
    ],
    ids=("records", "line", "total"),
)
def test_batch_enforces_record_line_and_total_limits(raw: bytes) -> None:
    # Given / When / Then
    with pytest.raises(InputError):
        _ = parse_batch(raw)
