"""Tests for compliance tracker."""
from blueteam.compliance.nist_800_171 import CONTROLS


def test_all_110_controls():
    assert len(CONTROLS) == 110


def test_control_structure():
    for ctrl in CONTROLS:
        assert "control_id" in ctrl
        assert "family" in ctrl
        assert "family_id" in ctrl
        assert "requirement" in ctrl
        assert ctrl["control_id"].startswith("3.")


def test_all_14_families():
    families = {c["family_id"] for c in CONTROLS}
    expected = {"AC", "AT", "AU", "CM", "IA", "IR", "MA", "MP", "PS", "PE", "RA", "CA", "SC", "SI"}
    assert families == expected


def test_family_counts():
    from collections import Counter
    counts = Counter(c["family_id"] for c in CONTROLS)
    assert counts["AC"] == 22
    assert counts["AU"] == 9
    assert counts["SC"] == 16
    assert counts["SI"] == 7
    assert counts["IA"] == 11


def test_control_ids_unique():
    ids = [c["control_id"] for c in CONTROLS]
    assert len(ids) == len(set(ids))
