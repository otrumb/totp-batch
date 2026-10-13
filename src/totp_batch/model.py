from dataclasses import dataclass
from enum import StrEnum, unique
from typing import Final

INPUT_SCHEMA: Final = "totp-batch/input/v1"
OUTPUT_SCHEMA: Final = "totp-batch/output/v1"


@unique
class Algorithm(StrEnum):
    SHA1 = "SHA1"
    SHA256 = "SHA256"
    SHA512 = "SHA512"


@dataclass(frozen=True, slots=True)
class OtpParameters:
    algorithm: Algorithm = Algorithm.SHA1
    digits: int = 6
    period: int = 30


@dataclass(frozen=True, slots=True)
class BatchRecord:
    label: str
    secret: bytes
    parameters: OtpParameters


@dataclass(frozen=True, slots=True)
class GeneratedCode:
    label: str | None
    code: str
    generated_at: int
    window_start: int
    window_end: int
