from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from CVEVerdict.result import FailureKind, Result, fail, ok


@dataclass(frozen=True, slots=True)
class Cpe23:
    """Represents a Well-Formed CPE 2.3 formatted string."""
    part: str         # 'a' (application), 'o' (OS), 'h' (hardware)
    vendor: str
    product: str
    version: str
    update: str
    edition: str
    language: str
    sw_edition: str
    target_sw: str
    target_hw: str
    other: str
    raw: str

    @property
    def is_application(self) -> bool:
        return self.part == "a"

    @property
    def is_operating_system(self) -> bool:
        return self.part == "o"

    @property
    def is_hardware(self) -> bool:
        return self.part == "h"


def _tokenize_cpe(cpe_str: str) -> list[str]:
    """
    Splits CPE on unescaped colons by walking the string.
    Respects backslash escapes like '\\:' so colons in names don't shift fields.
    """
    tokens: list[str] = []
    current_chars: list[str] = []
    escaped = False

    for char in cpe_str:
        if escaped:
            current_chars.append(char)
            escaped = False
        elif char == "\\":
            current_chars.append(char)
            escaped = True
        elif char == ":":
            tokens.append("".join(current_chars))
            current_chars = []
        else:
            current_chars.append(char)

    tokens.append("".join(current_chars))
    return tokens


def parse_cpe23(cpe_str: str) -> Result[Cpe23]:
    """
    Parses a CPE 2.3 string into a Cpe23 dataclass.
    Expected format: cpe:2.3:part:vendor:product:version:update:edition:language:sw_edition:target_sw:target_hw:other
    """
    if not cpe_str or not isinstance(cpe_str, str):
        return fail(FailureKind.INVALID_RESPONSE, "CPE string cannot be empty.")

    tokens = _tokenize_cpe(cpe_str.strip())

    # Format check: must start with 'cpe' and '2.3'
    if len(tokens) < 2 or tokens[0] != "cpe" or tokens[1] != "2.3":
        return fail(
            FailureKind.INVALID_RESPONSE,
            f"Invalid CPE prefix. Expected 'cpe:2.3:...', got '{cpe_str[:20]}'.",
        )

    # After 'cpe' and '2.3', there must be exactly 11 fields
    fields = tokens[2:]
    if len(fields) != 11:
        return fail(
            FailureKind.INVALID_RESPONSE,
            f"Expected exactly 11 fields in CPE 2.3, found {len(fields)}: '{cpe_str}'.",
        )

    part = fields[0]
    if part not in ("a", "o", "h"):
        return fail(
            FailureKind.INVALID_RESPONSE,
            f"Invalid CPE part '{part}'. Must be 'a' (application), 'o' (os), or 'h' (hardware).",
        )

    cpe_obj = Cpe23(
        part=part,
        vendor=fields[1],
        product=fields[2],
        version=fields[3],
        update=fields[4],
        edition=fields[5],
        language=fields[6],
        sw_edition=fields[7],
        target_sw=fields[8],
        target_hw=fields[9],
        other=fields[10],
        raw=cpe_str,
    )
    return ok(cpe_obj)