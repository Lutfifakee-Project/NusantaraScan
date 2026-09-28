"""Test validators."""

import tempfile
from pathlib import Path

import pytest

from binscan.utils.validators import (
    ValidationError,
    validate_file,
    validate_directory,
    validate_rule_path,
)


def test_validate_file_ok():
    with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
        f.write(b"x" * 100)
        tmp_path = f.name
    try:
        result = validate_file(tmp_path)
        assert result.exists()
    finally:
        Path(tmp_path).unlink(missing_ok=True)


def test_validate_file_not_found():
    with pytest.raises(ValidationError):
        validate_file("tidak_ada_file_xyz.bin")


def test_validate_file_empty():
    with tempfile.NamedTemporaryFile(delete=False) as f:
        tmp_path = f.name
    try:
        with pytest.raises(ValidationError):
            validate_file(tmp_path)
    finally:
        Path(tmp_path).unlink(missing_ok=True)


def test_validate_directory_ok():
    result = validate_directory(".")
    assert result.is_dir()


def test_validate_rule_path_not_found():
    with pytest.raises(ValidationError):
        validate_rule_path("tidak_ada_rule_xyz.yar")