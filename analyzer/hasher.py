"""
File hashing module for generating MD5, SHA1, and SHA256 hashes.
"""

import hashlib
from pathlib import Path
from typing import Tuple, Optional


def hash_file(file_path: str, chunk_size: int = 8192) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """
    Calculate MD5, SHA1, and SHA256 hashes for a file.
    Uses streaming to handle large files efficiently.
    
    Args:
        file_path: Path to the file to hash
        chunk_size: Size of chunks to read (default 8KB)
    
    Returns:
        Tuple of (md5, sha1, sha256) hex digests, or None values on error
    """
    md5_hash = hashlib.md5()
    sha1_hash = hashlib.sha1()
    sha256_hash = hashlib.sha256()
    
    try:
        path = Path(file_path)
        if not path.is_file():
            return None, None, None
        
        with open(file_path, 'rb') as f:
            while chunk := f.read(chunk_size):
                md5_hash.update(chunk)
                sha1_hash.update(chunk)
                sha256_hash.update(chunk)
        
        return md5_hash.hexdigest(), sha1_hash.hexdigest(), sha256_hash.hexdigest()
    
    except (IOError, OSError, PermissionError):
        return None, None, None


def hash_bytes(data: bytes) -> Tuple[str, str, str]:
    """
    Calculate hashes for in-memory data.
    
    Args:
        data: Bytes to hash
    
    Returns:
        Tuple of (md5, sha1, sha256) hex digests
    """
    return (
        hashlib.md5(data).hexdigest(),
        hashlib.sha1(data).hexdigest(),
        hashlib.sha256(data).hexdigest()
    )


class HashCache:
    """
    Cache for file hashes to avoid recomputation.
    Uses file path + size + mtime as cache key.
    """
    
    def __init__(self):
        self._cache = {}
    
    def _get_key(self, file_path: str) -> Optional[str]:
        """Generate cache key from file path and metadata."""
        try:
            path = Path(file_path)
            stat = path.stat()
            return f"{file_path}:{stat.st_size}:{stat.st_mtime}"
        except (OSError, IOError):
            return None
    
    def get(self, file_path: str) -> Optional[Tuple[str, str, str]]:
        """Get cached hashes if available."""
        key = self._get_key(file_path)
        if key:
            return self._cache.get(key)
        return None
    
    def set(self, file_path: str, hashes: Tuple[str, str, str]) -> None:
        """Cache hashes for a file."""
        key = self._get_key(file_path)
        if key:
            self._cache[key] = hashes
    
    def get_or_compute(self, file_path: str) -> Tuple[Optional[str], Optional[str], Optional[str]]:
        """Get cached hashes or compute and cache them."""
        cached = self.get(file_path)
        if cached:
            return cached
        
        hashes = hash_file(file_path)
        if all(h is not None for h in hashes):
            self.set(file_path, hashes)
        return hashes
