import base64
import binascii
import hmac
from collections.abc import Sequence
from dataclasses import dataclass
from typing import override

from totp_batch.model import BatchRecord, GeneratedCode, OtpParameters

MIN_SECRET_BYTES = 16
MAX_SECRET_BYTES = 64
MAX_PERIOD_SECONDS = 86_400


@dataclass(frozen=True, slots=True)
class CoreInputError(Exception):
    category: str

    @override
    def __str__(self) -> str:
        return self.category


def decode_base32(encoded: str) -> bytes:
    try:
        normalized = encoded.upper().encode("ascii")
    except UnicodeEncodeError:
        raise CoreInputError(category="invalid Base32 secret") from None
    unpadded = normalized.rstrip(b"=")
    supplied_padding = normalized[len(unpadded) :]
    canonical_padding = b"=" * (-len(unpadded) % 8)
    if not unpadded or supplied_padding not in (b"", canonical_padding):
        raise CoreInputError(category="invalid Base32 secret")
    try:
        secret = base64.b32decode(unpadded + canonical_padding)
    except binascii.Error:
        raise CoreInputError(category="invalid Base32 secret") from None
    if base64.b32encode(secret) != unpadded + canonical_padding:
        raise CoreInputError(category="invalid Base32 secret")
    if not MIN_SECRET_BYTES <= len(secret) <= MAX_SECRET_BYTES:
        raise CoreInputError(category="secret length outside 16..64 bytes")
    return secret


def hotp(secret: bytes, counter: int, parameters: OtpParameters) -> str:
    if not 0 <= counter < 2**64:
        raise CoreInputError(category="counter outside unsigned 64-bit range")
    if parameters.digits not in (6, 8):
        raise CoreInputError(category="digits must be 6 or 8")
    mac = hmac.digest(
        secret, counter.to_bytes(8, "big"), parameters.algorithm.value.lower()
    )
    offset = mac[-1] & 0x0F
    binary = int.from_bytes(mac[offset : offset + 4], "big") & 0x7FFFFFFF
    return f"{binary % (10**parameters.digits):0{parameters.digits}d}"


def totp(secret: bytes, timestamp: int, parameters: OtpParameters) -> str:
    if not 1 <= parameters.period <= MAX_PERIOD_SECONDS:
        raise CoreInputError(category="period outside 1..86400 seconds")
    if timestamp < 0:
        raise CoreInputError(category="timestamp must be nonnegative")
    return hotp(secret, timestamp // parameters.period, parameters)


def generate_batch(
    records: Sequence[BatchRecord], timestamp: int
) -> tuple[GeneratedCode, ...]:
    generated: list[GeneratedCode] = []
    for record in records:
        window_start = (
            timestamp // record.parameters.period
        ) * record.parameters.period
        generated.append(
            GeneratedCode(
                label=record.label,
                code=totp(record.secret, timestamp, record.parameters),
                generated_at=timestamp,
                window_start=window_start,
                window_end=window_start + record.parameters.period,
            )
        )
    return tuple(generated)
