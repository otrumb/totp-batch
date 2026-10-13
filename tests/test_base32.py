import base64

import pytest

from totp_batch.core import CoreInputError, decode_base32

SYNTHETIC_SECRET = bytes(range(16))
ENCODED_SECRET = base64.b32encode(SYNTHETIC_SECRET).decode("ascii")


@pytest.mark.parametrize(
    "encoded", [ENCODED_SECRET, ENCODED_SECRET.rstrip("="), ENCODED_SECRET.lower()]
)
def test_base32_accepts_canonical_padded_unpadded_and_lowercase(encoded: str) -> None:
    # Given
    expected = SYNTHETIC_SECRET
    # When
    decoded = decode_base32(encoded)
    # Then
    assert decoded == expected


@pytest.mark.parametrize(
    "encoded",
    [
        ENCODED_SECRET[:-7] + "1======",
        ENCODED_SECRET[:-7] + "F======",
        ENCODED_SECRET.rstrip("=") + "=",
        ENCODED_SECRET + "=",
        f" {ENCODED_SECRET}",
        f"{ENCODED_SECRET} ",
        f"{ENCODED_SECRET}\n",
        f"{ENCODED_SECRET}\x00",
        f"{ENCODED_SECRET}é",
    ],
)
def test_base32_rejects_invalid_text_without_echoing_input(encoded: str) -> None:
    # Given
    source = encoded
    # When
    with pytest.raises(CoreInputError) as raised:
        _ = decode_base32(source)
    # Then
    assert source not in str(raised.value)


@pytest.mark.parametrize("size", [15, 65])
def test_base32_rejects_decoded_secret_outside_size_bounds(size: int) -> None:
    # Given
    encoded = base64.b32encode(bytes(size)).decode("ascii")
    # When
    with pytest.raises(CoreInputError) as raised:
        _ = decode_base32(encoded)
    # Then
    assert encoded not in str(raised.value)
