"""
File hashing module for generating MD5, SHA1, and SHA256 hashes.
Optimized for large archives with 100k+ files.
"""

import hashlib
import mmap
import os
from pathlib import Path
from typing import Tuple, Optional, List
from concurrent.futures import ThreadPoolExecutor, as_completed

# Threshold for memory-mapped hashing (10MB)
MMAP_THRESHOLD = 10 * 1024 * 1024
# Threshold for small file batching (4KB)
SMALL_FILE_THRESHOLD = 4 * 1024
# Chunk size for streaming
CHUNK_SIZE = 64 * 1024  # 64KB chunks for better throughput


def hash_file(file_path: str, chunk_size: int = CHUNK_SIZE) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """
    Calculate MD5, SHA1, and SHA256 hashes for a file.
    Uses memory mapping for large files and streaming for others.
    
    Args:
        file_path: Path to the file to hash
        chunk_size: Size of chunks to read (default 64KB)
    
    Returns:
        Tuple of (md5, sha1, sha256) hex digests, or None values on error
    """
    try:
        path = Path(file_path)
        if not path.is_file():
            return None, None, None
        
        file_size = path.stat().st_size
        
        # Use memory-mapped hashing for large files
        if file_size >= MMAP_THRESHOLD:
            return _hash_file_mmap(file_path, file_size)
        
        # Standard streaming for smaller files
        return _hash_file_streaming(file_path, chunk_size)
    
    except (IOError, OSError, PermissionError):
        return None, None, None


def _hash_file_mmap(file_path: str, file_size: int) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """Hash a large file using memory mapping to avoid loading into RAM."""
    md5_hash = hashlib.md5()
    sha1_hash = hashlib.sha1()
    sha256_hash = hashlib.sha256()
    
    try:
        with open(file_path, 'rb') as f:
            # Memory-map the file
            with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                # Process in chunks to update hash incrementally
                for offset in range(0, file_size, CHUNK_SIZE):
                    chunk = mm[offset:offset + CHUNK_SIZE]
                    md5_hash.update(chunk)
                    sha1_hash.update(chunk)
                    sha256_hash.update(chunk)
        
        return md5_hash.hexdigest(), sha1_hash.hexdigest(), sha256_hash.hexdigest()
    except (IOError, OSError, ValueError):
        # Fall back to streaming if mmap fails (e.g., empty file)
        return _hash_file_streaming(file_path, CHUNK_SIZE)


def _hash_file_streaming(file_path: str, chunk_size: int) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """Hash a file using streaming reads."""
    md5_hash = hashlib.md5()
    sha1_hash = hashlib.sha1()
    sha256_hash = hashlib.sha256()
    
    try:
        with open(file_path, 'rb') as f:
            while chunk := f.read(chunk_size):
                md5_hash.update(chunk)
                sha1_hash.update(chunk)
                sha256_hash.update(chunk)
        
        return md5_hash.hexdigest(), sha1_hash.hexdigest(), sha256_hash.hexdigest()
    except (IOError, OSError, PermissionError):
        return None, None, None


def hash_small_file(file_path: str) -> Tuple[str, Optional[str], Optional[str], Optional[str]]:
    """
    Hash a small file by reading entirely into memory.
    Returns (file_path, md5, sha1, sha256) for batch processing.
    """
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
        return (
            file_path,
            hashlib.md5(data).hexdigest(),
            hashlib.sha1(data).hexdigest(),
            hashlib.sha256(data).hexdigest()
        )
    except (IOError, OSError, PermissionError):
        return file_path, None, None, None


def hash_files_batch(file_paths: List[str], max_workers: int = 8) -> dict:
    """
    Hash multiple small files in parallel batches.
    More efficient than hashing one by one for many small files.
    
    Args:
        file_paths: List of file paths to hash
        max_workers: Number of parallel workers
    
    Returns:
        Dict mapping file_path -> (md5, sha1, sha256)
    """
    results = {}
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(hash_small_file, fp): fp for fp in file_paths}
        for future in as_completed(futures):
            try:
                file_path, md5, sha1, sha256 = future.result()
                results[file_path] = (md5, sha1, sha256)
            except Exception:
                fp = futures[future]
                results[fp] = (None, None, None)
    
    return results


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
    Supports batching small files for efficiency.
    """
    
    def __init__(self):
        self._cache = {}
        self._pending_small_files: List[Tuple[str, str]] = []  # (file_path, cache_key)
    
    def _get_key(self, file_path: str) -> Optional[Tuple[str, int]]:
        """Generate cache key from file path and metadata. Returns (key, size)."""
        try:
            path = Path(file_path)
            stat = path.stat()
            return f"{file_path}:{stat.st_size}:{stat.st_mtime}", stat.st_size
        except (OSError, IOError):
            return None, 0
    
    def get(self, file_path: str) -> Optional[Tuple[str, str, str]]:
        """Get cached hashes if available."""
        result = self._get_key(file_path)
        if result[0]:
            return self._cache.get(result[0])
        return None
    
    def set(self, file_path: str, hashes: Tuple[str, str, str]) -> None:
        """Cache hashes for a file."""
        result = self._get_key(file_path)
        if result[0]:
            self._cache[result[0]] = hashes
    
    def get_or_compute(self, file_path: str) -> Tuple[Optional[str], Optional[str], Optional[str]]:
        """Get cached hashes or compute and cache them."""
        cached = self.get(file_path)
        if cached:
            return cached
        
        hashes = hash_file(file_path)
        if all(h is not None for h in hashes):
            self.set(file_path, hashes)
        return hashes
    
    def queue_small_file(self, file_path: str) -> bool:
        """
        Queue a small file for batch hashing.
        Returns True if file was queued, False if it should be hashed individually.
        """
        result = self._get_key(file_path)
        if result[0] is None:
            return False
        
        key, size = result
        if key in self._cache:
            return False  # Already cached
        
        if size <= SMALL_FILE_THRESHOLD:
            self._pending_small_files.append((file_path, key))
            return True
        return False
    
    def flush_batch(self, max_workers: int = 8) -> int:
        """
        Process all queued small files in batch.
        Returns number of files processed.
        """
        if not self._pending_small_files:
            return 0
        
        file_paths = [fp for fp, _ in self._pending_small_files]
        key_map = {fp: key for fp, key in self._pending_small_files}
        
        results = hash_files_batch(file_paths, max_workers)
        
        for file_path, hashes in results.items():
            if all(h is not None for h in hashes):
                key = key_map.get(file_path)
                if key:
                    self._cache[key] = hashes
        
        count = len(self._pending_small_files)
        self._pending_small_files = []
        return count
    
    def get_pending_count(self) -> int:
        """Get number of files queued for batch processing."""
        return len(self._pending_small_files)
