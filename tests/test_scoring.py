"""Test risk scoring."""

from binscan.utils.scoring import RiskScorer


def test_clean_file_scores_zero():
    results = {
        "suspicious_strings": [],
        "yara_matches": [],
        "packer_detected": None,
        "entropy": 5.0,
        "imports": {},
    }
    scoring = RiskScorer.score(results)
    assert scoring["score"] == 0
    assert scoring["level"] == "CLEAN"


def test_yara_match_high_score():
    results = {
        "suspicious_strings": [],
        "yara_matches": ["DarkComet_RAT", "Suspicious_API"],
        "packer_detected": None,
        "entropy": 5.0,
        "imports": {},
    }
    scoring = RiskScorer.score(results)
    assert scoring["score"] >= 60
    assert scoring["level"] in ("HIGH", "CRITICAL")


def test_score_capped_at_100():
    results = {
        "suspicious_strings": ["a"] * 100,
        "yara_matches": ["r1", "r2", "r3", "r4", "r5"],
        "packer_detected": "UPX",
        "entropy": 7.9,
        "imports": {},
    }
    scoring = RiskScorer.score(results)
    assert scoring["score"] <= 100


def test_api_combo_detected():
    results = {
        "suspicious_strings": [],
        "yara_matches": [],
        "packer_detected": None,
        "entropy": 5.0,
        "imports": {
            "kernel32.dll": [
                "CreateRemoteThread",
                "VirtualAllocEx",
                "WriteProcessMemory",
            ]
        },
    }
    scoring = RiskScorer.score(results)
    assert scoring["score"] >= 15
    assert any("API combo" in r for r in scoring["reasons"])