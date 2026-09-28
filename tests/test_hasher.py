"""Test hasher utilities."""

import hashlib
import tempfile
from pathlib import Path

from binscan.utils.hasher import FileHasher


def test_md5_matches_hashlib():
    with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
        data = b"hello nusantarascan"
        f.write(data)
        tmp_path = f.name

    try:
        hasher = FileHasher(tmp_path)
        expected = hashlib.md5(data).hexdigest()
        assert hasher.md5() == expected
    finally:
        Path(tmp_path).unlink(missing_ok=True)


def test_all_hashes_returns_dict():
    with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
        f.write(b"test content")
        tmp_path = f.name

    try:
        hasher = FileHasher(tmp_path)
        result = hasher.all_hashes()
        assert "md5" in result
        assert "sha1" in result
        assert "sha256" in result
        assert len(result["md5"]) == 32
        assert len(result["sha1"]) == 40
        assert len(result["sha256"]) == 64
    finally:
        Path(tmp_path).unlink(missing_ok=True)