from CVEVerdict.parsing.cpe import parse_cpe23
from CVEVerdict.result import FailureKind


def test_parse_valid_standard_cpe():
    cpe_str = "cpe:2.3:a:google:chrome:116.0.5845.187:*:*:*:*:*:*:*"
    res = parse_cpe23(cpe_str)
    assert res.is_success
    cpe = res.unwrap()
    assert cpe.part == "a"
    assert cpe.is_application is True
    assert cpe.is_operating_system is False
    assert cpe.vendor == "google"
    assert cpe.product == "chrome"
    assert cpe.version == "116.0.5845.187"
    assert cpe.update == "*"


def test_parse_cpe_with_escaped_colon():
    # Vendor or product containing an escaped colon: "product\:with_colon"
    cpe_str = r"cpe:2.3:a:vendor:product\:with_colon:1.0:*:*:*:*:*:*:*"
    res = parse_cpe23(cpe_str)
    assert res.is_success
    cpe = res.unwrap()
    assert cpe.vendor == "vendor"
    assert cpe.product == r"product\:with_colon"
    assert cpe.version == "1.0"


def test_parse_preserves_dash_and_asterisk():
    # Testing that '-' (NA) and '*' (Any) are kept intact
    cpe_str = "cpe:2.3:a:mozilla:firefox:117.0:-:*:*:*:*:*:*"
    res = parse_cpe23(cpe_str)
    assert res.is_success
    cpe = res.unwrap()
    assert cpe.update == "-"
    assert cpe.edition == "*"


def test_reject_wrong_prefix():
    res = parse_cpe23("cpe:2.2:a:google:chrome:1.0:*:*:*:*:*:*:*")
    assert res.is_failure
    assert res.kind == FailureKind.INVALID_RESPONSE
    assert "Invalid CPE prefix" in res.message


def test_reject_wrong_field_count():
    # Only 10 fields after prefix instead of 11
    res = parse_cpe23("cpe:2.3:a:google:chrome:1.0:*:*:*:*:*:*")
    assert res.is_failure
    assert res.kind == FailureKind.INVALID_RESPONSE
    assert "Expected exactly 11 fields" in res.message


def test_reject_invalid_part():
    # 'x' is not a valid part
    res = parse_cpe23("cpe:2.3:x:google:chrome:1.0:*:*:*:*:*:*:*")
    assert res.is_failure
    assert "Invalid CPE part" in res.message