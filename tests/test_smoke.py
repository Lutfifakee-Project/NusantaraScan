"""Smoke test - pastikan package bisa di-import & CLI jalan."""

import subprocess
import sys
from pathlib import Path


def test_import_package():
    import binscan
    assert binscan.__version__
    assert binscan.__version__ == "0.3.0"


def test_cli_help():
    result = subprocess.run(
        [sys.executable, "-m", "binscan.cli", "--help"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    assert "usage" in result.stdout.lower() or "binscan" in result.stdout.lower()


def test_main_help():
    """Test main.py help via subprocess."""
    result = subprocess.run(
        [sys.executable, "main.py", "--help"],
        capture_output=True,
        text=True,
        cwd=Path(__file__).parent.parent,
    )
    assert result.returncode == 0


def test_scan_self():
    """Scan file kecil (requirements.txt) sebagai smoke test."""
    sample = Path(__file__).parent.parent / "requirements.txt"
    if not sample.exists():
        return
    result = subprocess.run(
        [sys.executable, "main.py", str(sample)],
        capture_output=True,
        text=True,
        cwd=Path(__file__).parent.parent,
    )
    assert "completed" in result.stdout.lower()