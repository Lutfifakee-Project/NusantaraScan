"""
File hashing utilities.
"""

import hashlib


class FileHasher:
    """Hitung hash file dengan streaming."""

    CHUNK_SIZE = 8192

    def __init__(self, filepath: str):
        self.filepath = filepath

    def _hash(self, algo: str) -> str:
        h = hashlib.new(algo)
        with open(self.filepath, "rb") as f:
            for chunk in iter(lambda: f.read(self.CHUNK_SIZE), b""):
                h.update(chunk)
        return h.hexdigest()

    def md5(self) -> str:
        return self._hash("md5")

    def sha1(self) -> str:
        return self._hash("sha1")

    def sha256(self) -> str:
        return self._hash("sha256")

    def all_hashes(self) -> dict:
        md5 = hashlib.md5()
        sha1 = hashlib.sha1()
        sha256 = hashlib.sha256()
        with open(self.filepath, "rb") as f:
            for chunk in iter(lambda: f.read(self.CHUNK_SIZE), b""):
                md5.update(chunk)
                sha1.update(chunk)
                sha256.update(chunk)
        return {
            "md5": md5.hexdigest(),
            "sha1": sha1.hexdigest(),
            "sha256": sha256.hexdigest(),
        }