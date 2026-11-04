from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Generic, TypeVar, Union

T = TypeVar("T")


class FailureKind(StrEnum):
    TIMEOUT = "timeout"
    RATE_LIMITED = "rate_limited"
    NOT_FOUND = "not_found"
    NETWORK = "network"
    INVALID_RESPONSE = "invalid_response"


@dataclass(frozen=True, slots=True)
class Success(Generic[T]):
    """Represents a successful outcome carrying a value."""
    value: T

    @property
    def is_success(self) -> bool:
        return True

    @property
    def is_failure(self) -> bool:
        return False

    def unwrap(self) -> T:
        return self.value

    def __bool__(self) -> bool:
        return True


@dataclass(frozen=True, slots=True)
class Failure:
    """Represents an expected failure with an explicit category and message."""
    kind: FailureKind
    message: str
    details: Any = None

    @property
    def is_success(self) -> bool:
        return False

    @property
    def is_failure(self) -> bool:
        return True

    def unwrap(self) -> Any:
        raise RuntimeError(f"Called unwrap on a Failure [{self.kind}]: {self.message}")

    def __bool__(self) -> bool:
        return False


# Type alias for type hints: Result[T]
Result = Union[Success[T], Failure]


# Ergonomic factory functions
def ok(value: T) -> Success[T]:
    return Success(value)


def fail(kind: FailureKind, message: str, details: Any = None) -> Failure:
    return Failure(kind=kind, message=message, details=details)