import pytest
from CVEVerdict.result import Failure, FailureKind, Success, fail, ok


def test_success_behavior():
    res = ok("cve-data")
    assert res.is_success is True
    assert res.is_failure is False
    assert bool(res) is True
    assert res.unwrap() == "cve-data"


def test_failure_behavior():
    res = fail(FailureKind.RATE_LIMITED, "NVD rate limit hit", details={"retry_after": 30})
    assert res.is_success is False
    assert res.is_failure is True
    assert bool(res) is False
    assert res.kind == FailureKind.RATE_LIMITED
    assert res.kind == "rate_limited"  # StrEnum allows direct string comparison

    with pytest.raises(RuntimeError, match="Called unwrap on a Failure"):
        res.unwrap()


def test_pattern_matching():
    def process_result(res):
        match res:
            case Success(value):
                return f"Got: {value}"
            case Failure(FailureKind.NOT_FOUND, msg):
                return f"Missing: {msg}"
            case Failure(kind, msg):
                return f"Failed [{kind}]: {msg}"

    assert process_result(ok(42)) == "Got: 42"
    assert process_result(fail(FailureKind.NOT_FOUND, "CVE-0000")) == "Missing: CVE-0000"
    assert process_result(fail(FailureKind.TIMEOUT, "timed out")) == "Failed [timeout]: timed out"