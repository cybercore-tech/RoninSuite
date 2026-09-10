import pytest

from ronin.core.cvss import base_score, severity_for

CASES = {
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H": 9.8,
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H": 7.5,
    "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N": 3.1,
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N": 6.1,
    "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H": 7.8,
    "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H": 8.8,
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H": 10.0,
}


@pytest.mark.parametrize("vector,expected", CASES.items())
def test_base_score(vector, expected):
    assert base_score(vector) == expected


def test_prefixless_vector():
    assert base_score("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") == 9.8


def test_bands():
    assert severity_for(0.0) == "info"
    assert severity_for(3.9) == "low"
    assert severity_for(4.0) == "medium"
    assert severity_for(7.0) == "high"
    assert severity_for(9.0) == "critical"


def test_invalid_vector():
    with pytest.raises(ValueError):
        base_score("CVSS:3.1/AV:N/AC:L")
