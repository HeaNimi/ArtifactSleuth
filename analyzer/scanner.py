"""
Core file scanner module.
Recursively scans directories and archives, collecting file information.
"""

import os
import logging
import concurrent.futures
import threading
from pathlib import Path
from typing import List, Optional, Callable
from tqdm import tqdm

from .metadata import FileInfo, get_file_metadata, calculate_risk_score
from .hasher import HashCache
from .archive_handler import (
    is_archive, 
    extract_archive, 
    temp_extract_dir,
    ArchiveError
)


class FileScanner:
    """
    Recursive file scanner that handles both directories and archives.
    """
    
    def __init__(
        self,
        hash_files: bool = True,
        max_archive_depth: int = 5,
        progress_callback: Optional[Callable[[str], None]] = None
    ):
        """
        Initialize the scanner.
        
        Args:
            hash_files: Whether to compute file hashes
            max_archive_depth: Maximum depth for nested archive extraction
            progress_callback: Optional callback for progress updates
        """
        self.hash_files = hash_files
        self.max_archive_depth = max_archive_depth
        self.progress_callback = progress_callback
        self.hash_cache = HashCache()
        self.files: List[FileInfo] = []
        self.password_protected_archives: List[str] = []
        self.errors: List[str] = []
        self.errors: List[str] = []
        self.logger = logging.getLogger(__name__)
        self._lock = threading.Lock()
        self._executor = None
        self._futures = []
    
    def _update_progress(self, message: str) -> None:
        """Update progress if callback is set."""
        if self.progress_callback:
            self.progress_callback(message)
    
    def scan(self, path: str) -> List[FileInfo]:
        """
        Scan a path (file or directory) and return list of FileInfo objects.
        
        Args:
            path: Path to scan
        
        Returns:
            List of FileInfo objects for all discovered files
        """
        self.files = []
        self.password_protected_archives = []
        self.errors = []
        self._futures = []
        
        path = Path(path).resolve()
        
        if not path.exists():
            raise FileNotFoundError(f"Path does not exist: {path}")
            
        # Use a maximum of 8 worker threads for I/O bound tasks
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
            self._executor = executor
            
            if path.is_file():
                self._scan_file(str(path), str(path.parent))
            else:
                self._scan_directory(str(path), str(path))
            
            # Wait for all submitted tasks to complete
            # We need to loop because tasks might submit more tasks (recursive scanning)
            # However, since we're using a context manager, we can collect futures as we go
            # But simpler approach for recursion: just let the main thread wait?
            # No, with recursion via futures, we need to track them.
            
            # A simple way to handle recursive parallel scanning:
            # We'll just wait for the initial futures, but since they spawn more...
            # The context manager __exit__ will wait for all futures to complete.
            pass
        
        # Calculate risk scores for all files (CPU bound, do sequentially or parallel separately)
        # We'll do it sequentially here for simplicity as it's fast
        for file_info in self.files:
            calculate_risk_score(file_info)
        
        return self.files
    
    def _submit_task(self, fn, *args, **kwargs):
        """Submit a task to the executor if active, otherwise run inline."""
        if self._executor:
            self._executor.submit(fn, *args, **kwargs)
        else:
            fn(*args, **kwargs)

    def _scan_directory(self, dir_path: str, scan_root: str, archive_path: Optional[str] = None) -> None:
        """
        Recursively scan a directory.
        
        Args:
            dir_path: Directory to scan
            scan_root: Root directory of the scan
            archive_path: Path of parent archive if scanning extracted contents
        """
        try:
            entries = list(os.scandir(dir_path))
        except PermissionError:
            err_msg = f"Permission denied: {dir_path}"
            with self._lock:
                self.errors.append(err_msg)
            self.logger.error(err_msg)
            return
        except OSError as e:
            err_msg = f"Error scanning {dir_path}: {e}"
            with self._lock:
                self.errors.append(err_msg)
            self.logger.error(err_msg)
            return
        
        for entry in entries:
            try:
                if entry.is_file(follow_symlinks=False):
                    self._submit_task(self._scan_file, entry.path, scan_root, archive_path)
                elif entry.is_dir(follow_symlinks=False):
                    self._submit_task(self._scan_directory, entry.path, scan_root, archive_path)
            except PermissionError:
                err_msg = f"Permission denied: {entry.path}"
                with self._lock:
                    self.errors.append(err_msg)
                self.logger.error(err_msg)
            except OSError as e:
                err_msg = f"Error accessing {entry.path}: {e}"
                with self._lock:
                    self.errors.append(err_msg)
                self.logger.error(err_msg)
    
    def _scan_file(
        self, 
        file_path: str, 
        scan_root: str, 
        archive_path: Optional[str] = None,
        archive_depth: int = 0
    ) -> None:
        """
        Scan a single file.
        
        Args:
            file_path: Path to the file
            scan_root: Root directory of the scan
            archive_path: Path of parent archive if file was extracted
            archive_depth: Current depth of archive nesting
        """
        self._update_progress(f"Scanning: {Path(file_path).name}")
        
        try:
            # Get file metadata
            file_info = get_file_metadata(file_path, scan_root, archive_path)
            
            # Compute hashes if enabled
            if self.hash_files and not file_info.is_directory:
                md5, sha1, sha256 = self.hash_cache.get_or_compute(file_path)
                file_info.md5 = md5
                file_info.sha1 = sha1
                file_info.sha256 = sha256
            
            with self._lock:
                self.files.append(file_info)
            
            # Handle archives
            if is_archive(file_path) and archive_depth < self.max_archive_depth:
                # We do NOT submit archives to the pool to avoid exhausting workers with blocking tasks
                # Instead, process them directly or spawn a new task? 
                # Processing directly in this thread (which is already a worker) is fine.
                self._scan_archive(file_path, scan_root, archive_depth)
        
        except PermissionError:
            err_msg = f"Permission denied: {file_path}"
            with self._lock:
                self.errors.append(err_msg)
            self.logger.error(err_msg)
        except OSError as e:
            err_msg = f"Error scanning {file_path}: {e}"
            with self._lock:
                self.errors.append(err_msg)
            self.logger.error(err_msg)
    
    def _scan_archive(self, archive_path: str, scan_root: str, archive_depth: int) -> None:
        """
        Extract and scan an archive.
        
        Args:
            archive_path: Path to the archive
            scan_root: Root directory of the scan
            archive_depth: Current depth of archive nesting
        """
        self._update_progress(f"Extracting: {Path(archive_path).name}")
        
        try:
            with temp_extract_dir() as temp_dir:
                files, is_password_protected = extract_archive(archive_path, temp_dir)
                
                if is_password_protected:
                    with self._lock:
                        self.password_protected_archives.append(archive_path)
                        # Update the archive's FileInfo
                        for file_info in self.files:
                            if file_info.path == archive_path:
                                file_info.is_password_protected = True
                                break
                    return
                
                # Calculate relative archive path for tracking
                try:
                    rel_archive = str(Path(archive_path).relative_to(scan_root))
                except ValueError:
                    rel_archive = Path(archive_path).name
                
                # Scan extracted contents
                for extracted_file in files:
                    self._scan_file(
                        extracted_file, 
                        temp_dir, 
                        rel_archive,
                        archive_depth + 1
                    )
        
        except ArchiveError as e:
            with self._lock:
                self.errors.append(str(e))
        except Exception as e:
            err_msg = f"Error extracting {archive_path}: {e}"
            with self._lock:
                self.errors.append(err_msg)
    
    def get_summary(self) -> dict:
        """Get summary statistics of the scan."""
        total_files = len(self.files)
        total_size = sum(f.size for f in self.files if not f.is_directory)
        
        # Count by file type
        extensions = {}
        for f in self.files:
            if not f.is_directory:
                ext = Path(f.name).suffix.lower() or '(no extension)'
                extensions[ext] = extensions.get(ext, 0) + 1
        
        # Risk summary
        high_risk = sum(1 for f in self.files if f.risk_score >= 50)
        medium_risk = sum(1 for f in self.files if 25 <= f.risk_score < 50)
        low_risk = sum(1 for f in self.files if 0 < f.risk_score < 25)
        
        return {
            'total_files': total_files,
            'total_size': total_size,
            'total_size_human': self._human_size(total_size),
            'extensions': dict(sorted(extensions.items(), key=lambda x: -x[1])),
            'password_protected_archives': len(self.password_protected_archives),
            'password_protected_archive_paths': self.password_protected_archives,
            'errors': len(self.errors),
            'error_messages': self.errors,
            'high_risk_count': high_risk,
            'medium_risk_count': medium_risk,
            'low_risk_count': low_risk,
        }
    
    @staticmethod
    def _human_size(size: int) -> str:
        """Convert size to human-readable format."""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size < 1024.0:
                return f"{size:.1f} {unit}"
            size /= 1024.0
        return f"{size:.1f} PB"


def scan_path(
    path: str,
    hash_files: bool = True,
    max_archive_depth: int = 5,
    show_progress: bool = True
) -> tuple:
    """
    Convenience function to scan a path.
    
    Args:
        path: Path to scan
        hash_files: Whether to compute file hashes
        max_archive_depth: Maximum depth for nested archives
        show_progress: Whether to show progress bar
    
    Returns:
        Tuple of (list of FileInfo, summary dict)
    """
    scanner = FileScanner(
        hash_files=hash_files,
        max_archive_depth=max_archive_depth
    )
    
    if show_progress:
        with tqdm(desc="Scanning files", unit=" files") as pbar:
            def progress(msg):
                pbar.set_postfix_str(msg[:40])
                pbar.update(1)
            scanner.progress_callback = progress
            files = scanner.scan(path)
            if pbar.n < len(files):
                pbar.total = len(files)
                pbar.update(len(files) - pbar.n)
    else:
        files = scanner.scan(path)
    
    return files, scanner.get_summary()
