"""
File hashing utilities
"""

import hashlib

class FileHasher:
    """Calculate file hashes"""
    
    def __init__(self, filepath):
        self.filepath = filepath
    
    def md5(self):
        """Calculate MD5 hash"""
        hash_md5 = hashlib.md5()
        with open(self.filepath, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_md5.update(chunk)
        return hash_md5.hexdigest()
    
    def sha1(self):
        """Calculate SHA1 hash"""
        hash_sha1 = hashlib.sha1()
        with open(self.filepath, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_sha1.update(chunk)
        return hash_sha1.hexdigest()
    
    def sha256(self):
        """Calculate SHA256 hash"""
        hash_sha256 = hashlib.sha256()
        with open(self.filepath, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_sha256.update(chunk)
        return hash_sha256.hexdigest()