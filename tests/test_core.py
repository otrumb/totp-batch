import pytest

from totp_batch.core import CoreInputError, generate_batch, hotp, totp
from totp_batch.model import Algorithm, BatchRecord, OtpParameters

RFC_4226_SECRET = b"12345678901234567890"
RFC_4226_CODES = (
    "755224",
    "287082",
    "359152",
    "969429",
    "338314",
    "254676",
    "287922",
    "162583",
    "399871",
    "520489",
)
RFC_6238_SECRETS = {
    Algorithm.SHA1: b"12345678901234567890",
    Algorithm.SHA256: b"12345678901234567890123456789012",
    Algorithm.SHA512: (
        b"1234567890123456789012345678901234567890123456789012345678901234"
    ),
}
RFC_6238_VECTORS = (
    (59, "94287082", "46119246", "90693936"),
    (1111111109, "07081804", "68084774", "25091201"),
    (1111111111, "14050471", "67062674", "99943326"),
    (1234567890, "89005924", "91819424", "93441116"),
    (2000000000, "69279037", "90698825", "38618901"),
    (20000000000, "65353130", "77737706", "47863826"),
)


@pytest.mark.parametrize(("counter", "expected"), tuple(enumerate(RFC_4226_CODES)))
def test_hotp_matches_rfc_4226_when_counter_is_public_vector(
    counter: int, expected: str
) -> None:
    # Given
    parameters = OtpParameters(digits=6)
    # When
    code = hotp(RFC_4226_SECRET, counter, parameters)
    # Then
    assert code == expected


@pytest.mark.parametrize(
    ("timestamp", "algorithm", "expected"),
    [
        (timestamp, algorithm, expected)
        for timestamp, sha1, sha256, sha512 in RFC_6238_VECTORS
        for algorithm, expected in (
            (Algorithm.SHA1, sha1),
            (Algorithm.SHA256, sha256),
            (Algorithm.SHA512, sha512),
        )
    ],
)
def test_totp_matches_rfc_6238_when_using_eight_digits(
    timestamp: int, algorithm: Algorithm, expected: str
) -> None:
    # Given
    parameters = OtpParameters(algorithm=algorithm, digits=8)
    # When
    code = totp(RFC_6238_SECRETS[algorithm], timestamp, parameters)
    # Then
    assert code == expected


@pytest.mark.parametrize(("timestamp", "expected"), [(29, "755224"), (30, "287082")])
def test_totp_changes_at_step_boundary(timestamp: int, expected: str) -> None:
    # Given
    parameters = OtpParameters(digits=6, period=30)
    # When
    code = totp(RFC_4226_SECRET, timestamp, parameters)
    # Then
    assert code == expected


def test_totp_preserves_leading_zero_when_vector_starts_with_zero() -> None:
    # Given
    parameters = OtpParameters(algorithm=Algorithm.SHA1, digits=8)
    # When
    code = totp(RFC_6238_SECRETS[Algorithm.SHA1], 1111111109, parameters)
    # Then
    assert code == "07081804"


def test_batch_uses_one_timestamp_for_every_record() -> None:
    # Given
    records = (
        BatchRecord("alpha", RFC_4226_SECRET, OtpParameters()),
        BatchRecord("beta", RFC_4226_SECRET + b"x", OtpParameters()),
    )
    # When
    codes = generate_batch(records, 60)
    # Then
    assert {code.generated_at for code in codes} == {60}


@pytest.mark.parametrize("counter", [-1, 2**64])
def test_hotp_rejects_counter_outside_unsigned_64_bit_range(counter: int) -> None:
    # Given
    parameters = OtpParameters()
    # When / Then
    with pytest.raises(CoreInputError):
        _ = hotp(RFC_4226_SECRET, counter, parameters)


@pytest.mark.parametrize("timestamp", [-1, (2**64) * 30])
def test_totp_rejects_timestamp_with_counter_outside_unsigned_64_bit_range(
    timestamp: int,
) -> None:
    # Given
    parameters = OtpParameters()
    # When / Then
    with pytest.raises(CoreInputError):
        _ = totp(RFC_4226_SECRET, timestamp, parameters)
