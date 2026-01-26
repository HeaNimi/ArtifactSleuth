"""
Core file scanner module.
Recursively scans directories and archives, collecting file information.
Optimized for large archives with 100k+ files.
"""

import os
import logging
import concurrent.futures
import threading
import time
import queue
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Callable, Generator, Iterator
from tqdm import tqdm

from .metadata import FileInfo, get_file_metadata, calculate_risk_score
from .hasher import HashCache, SMALL_FILE_THRESHOLD
from .archive_handler import (
    is_archive, 
    extract_archive, 
    temp_extract_dir,
    ArchiveError
)


class FileScanner:
    """
    Recursive file scanner that handles both directories and archives.
    Optimized for large archives with shallow-first scanning and async archive extraction.
    """
    
    def __init__(
        self,
        hash_files: bool = True,
        max_archive_depth: int = 5,
        progress_callback: Optional[Callable[[str], None]] = None,
        batch_small_files: bool = True,
        small_file_batch_size: int = 500
    ):
        """
        Initialize the scanner.
        
        Args:
            hash_files: Whether to compute file hashes
            max_archive_depth: Maximum depth for nested archive extraction
            progress_callback: Optional callback for progress updates
            batch_small_files: Whether to batch hash small files for efficiency
            small_file_batch_size: Number of small files to batch before flushing
        """
        self.hash_files = hash_files
        self.max_archive_depth = max_archive_depth
        self.progress_callback = progress_callback
        self.batch_small_files = batch_small_files
        self.small_file_batch_size = small_file_batch_size
        self.hash_cache = HashCache()
        self.files: List[FileInfo] = []
        self.password_protected_archives: List[str] = []
        self.errors: List[str] = []
        self.logger = logging.getLogger(__name__)
        self._lock = threading.Lock()
        self._executor = None
        self._futures = []
        # Queue for deferred archive processing (shallow-first strategy)
        self._archive_queue: queue.Queue = queue.Queue()
    
    def _update_progress(self, message: str) -> None:
        """Update progress if callback is set."""
        if self.progress_callback:
            self.progress_callback(message)
    
    def scan(self, path: str) -> List[FileInfo]:
        """
        Scan a path (file or directory) and return list of FileInfo objects.
        Uses shallow-first strategy: scans all top-level files first, then processes archives.
        
        Args:
            path: Path to scan
        
        Returns:
            List of FileInfo objects for all discovered files
        """
        self.files = []
        self.password_protected_archives = []
        self.errors = []
        self._futures = []
        self._archive_queue = queue.Queue()
        start_wall = datetime.now()
        start_time = time.perf_counter()
        self.logger.info(f"Starting scan at {start_wall.isoformat()} | path={path}")
        
        path = Path(path).resolve()
        
        if not path.exists():
            raise FileNotFoundError(f"Path does not exist: {path}")
        
        # Phase 1: Shallow scan - collect all files first (fast)
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
            self._executor = executor
            
            if path.is_file():
                self._scan_file_shallow(str(path), str(path.parent))
            else:
                self._scan_directory(str(path), str(path))
            
            # Wait for shallow scan to complete
            executor.shutdown(wait=True)
        
        # Flush any pending small file batches
        if self.batch_small_files and self.hash_cache.get_pending_count() > 0:
            self.hash_cache.flush_batch()
        
        # Phase 2: Process archives (deeper scan)
        self._process_archive_queue()
        
        # Calculate risk scores for all files
        for file_info in self.files:
            calculate_risk_score(file_info)

        elapsed = time.perf_counter() - start_time
        summary = self.get_summary()
        files_scanned = summary['total_files']
        total_size = summary['total_size']
        files_per_sec = files_scanned / elapsed if elapsed > 0 else files_scanned
        bytes_per_sec = total_size / elapsed if elapsed > 0 else total_size
        self.logger.info(
            "Scan completed in %.2fs | files=%d | speed=%.2f files/s | throughput=%s/s | data=%s | errors=%d | password_protected_archives=%d"
            % (
                elapsed,
                files_scanned,
                files_per_sec,
                self._human_size(bytes_per_sec),
                summary['total_size_human'],
                summary['errors'],
                summary['password_protected_archives'],
            )
        )
        
        return self.files
    
    def scan_iter(self, path: str) -> Generator[FileInfo, None, None]:
        """
        Generator-based scanning for memory-efficient processing.
        Yields FileInfo objects as they are discovered.
        Useful for incremental CSV/JSON writing with very large datasets.
        
        Args:
            path: Path to scan
        
        Yields:
            FileInfo objects as they are discovered
        """
        self.password_protected_archives = []
        self.errors = []
        self._archive_queue = queue.Queue()
        
        path = Path(path).resolve()
        
        if not path.exists():
            raise FileNotFoundError(f"Path does not exist: {path}")
        
        # Yield files from shallow scan
        yield from self._scan_directory_iter(str(path), str(path))
        
        # Yield files from archive processing
        yield from self._process_archive_queue_iter()
    
    def _submit_task(self, fn, *args, **kwargs):
        """Submit a task to the executor if active, otherwise run inline."""
        if self._executor:
            self._executor.submit(fn, *args, **kwargs)
        else:
            fn(*args, **kwargs)
    
    def _scan_file_shallow(
        self, 
        file_path: str, 
        scan_root: str, 
        archive_path: Optional[str] = None,
        archive_depth: int = 0
    ) -> None:
        """
        Scan a single file (shallow mode - queues archives for later).
        
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
                # Try to batch small files
                file_size = file_info.size or 0
                if self.batch_small_files and file_size <= SMALL_FILE_THRESHOLD:
                    if self.hash_cache.queue_small_file(file_path):
                        # File queued for batch processing
                        # Flush batch if threshold reached
                        if self.hash_cache.get_pending_count() >= self.small_file_batch_size:
                            self.hash_cache.flush_batch()
                    else:
                        # Already cached or error, try to get
                        cached = self.hash_cache.get(file_path)
                        if cached:
                            file_info.md5, file_info.sha1, file_info.sha256 = cached
                else:
                    # Normal hashing for larger files
                    md5, sha1, sha256 = self.hash_cache.get_or_compute(file_path)
                    file_info.md5 = md5
                    file_info.sha1 = sha1
                    file_info.sha256 = sha256
            
            with self._lock:
                self.files.append(file_info)
            
            # Queue archives for later processing (shallow-first strategy)
            if is_archive(file_path) and archive_depth < self.max_archive_depth:
                self._archive_queue.put((file_path, scan_root, archive_depth))
        
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
                    self._submit_task(self._scan_file_shallow, entry.path, scan_root, archive_path)
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
                
                # Scan extracted contents synchronously within the temp dir context
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
    
    def _process_archive_queue(self) -> None:
        """
        Process all queued archives using parallel extraction.
        Called after shallow scan completes.
        """
        if self._archive_queue.empty():
            return
        
        self._update_progress("Processing archives...")
        
        # Process archives with a thread pool for parallel extraction
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
            futures = []
            
            while not self._archive_queue.empty():
                try:
                    archive_path, scan_root, archive_depth = self._archive_queue.get_nowait()
                    future = executor.submit(
                        self._extract_and_scan_archive,
                        archive_path, scan_root, archive_depth
                    )
                    futures.append(future)
                except queue.Empty:
                    break
            
            # Wait for all archive processing to complete
            for future in concurrent.futures.as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    err_msg = f"Archive processing error: {e}"
                    self.logger.error(err_msg)
                    with self._lock:
                        self.errors.append(err_msg)
    
    def _extract_and_scan_archive(self, archive_path: str, scan_root: str, archive_depth: int) -> None:
        """
        Extract and scan an archive, adding any nested archives back to the queue.
        """
        self._update_progress(f"Extracting: {Path(archive_path).name}")
        
        try:
            with temp_extract_dir() as temp_dir:
                files, is_password_protected = extract_archive(archive_path, temp_dir)
                
                if is_password_protected:
                    self.logger.info(f"Password protected archive: {archive_path}")
                    with self._lock:
                        self.password_protected_archives.append(archive_path)
                        for file_info in self.files:
                            if file_info.path == archive_path:
                                file_info.is_password_protected = True
                                break
                    return
                
                self.logger.info(f"Extracted {len(files)} files from {archive_path}")
                
                try:
                    rel_archive = str(Path(archive_path).relative_to(scan_root))
                except ValueError:
                    rel_archive = Path(archive_path).name
                
                # Scan extracted files
                for extracted_file in files:
                    file_info = get_file_metadata(extracted_file, temp_dir, rel_archive)
                    
                    if self.hash_files and not file_info.is_directory:
                        md5, sha1, sha256 = self.hash_cache.get_or_compute(extracted_file)
                        file_info.md5 = md5
                        file_info.sha1 = sha1
                        file_info.sha256 = sha256
                    
                    with self._lock:
                        self.files.append(file_info)
                    
                    # Queue nested archives
                    if is_archive(extracted_file) and archive_depth + 1 < self.max_archive_depth:
                        self._archive_queue.put((extracted_file, temp_dir, archive_depth + 1))
                
                # Process any nested archives found (recursively)
                self._process_nested_archives(temp_dir, archive_depth + 1)
        
        except ArchiveError as e:
            err_msg = str(e)
            self.logger.error(f"Archive error for {archive_path}: {err_msg}")
            with self._lock:
                self.errors.append(err_msg)
        except Exception as e:
            err_msg = f"Error extracting {archive_path}: {e}"
            self.logger.error(err_msg)
            with self._lock:
                self.errors.append(err_msg)
    
    def _process_nested_archives(self, temp_dir: str, archive_depth: int) -> None:
        """Process any nested archives that were queued during extraction."""
        nested_archives = []
        
        # Collect archives that belong to this temp_dir
        temp_queue = queue.Queue()
        while not self._archive_queue.empty():
            try:
                item = self._archive_queue.get_nowait()
                if item[1] == temp_dir:
                    nested_archives.append(item)
                else:
                    temp_queue.put(item)
            except queue.Empty:
                break
        
        # Put back items that don't belong to this temp_dir
        while not temp_queue.empty():
            try:
                self._archive_queue.put(temp_queue.get_nowait())
            except queue.Empty:
                break
        
        # Process nested archives
        for archive_path, scan_root, depth in nested_archives:
            self._scan_archive(archive_path, scan_root, depth)
    
    def _scan_directory_iter(
        self, 
        dir_path: str, 
        scan_root: str, 
        archive_path: Optional[str] = None
    ) -> Generator[FileInfo, None, None]:
        """
        Generator-based directory scanning.
        Yields FileInfo objects as they are discovered.
        """
        try:
            entries = list(os.scandir(dir_path))
        except (PermissionError, OSError) as e:
            self.errors.append(f"Error scanning {dir_path}: {e}")
            return
        
        for entry in entries:
            try:
                if entry.is_file(follow_symlinks=False):
                    file_info = get_file_metadata(entry.path, scan_root, archive_path)
                    
                    if self.hash_files and not file_info.is_directory:
                        md5, sha1, sha256 = self.hash_cache.get_or_compute(entry.path)
                        file_info.md5 = md5
                        file_info.sha1 = sha1
                        file_info.sha256 = sha256
                    
                    calculate_risk_score(file_info)
                    yield file_info
                    
                    # Queue archives for later
                    if is_archive(entry.path):
                        self._archive_queue.put((entry.path, scan_root, 0))
                
                elif entry.is_dir(follow_symlinks=False):
                    yield from self._scan_directory_iter(entry.path, scan_root, archive_path)
            
            except (PermissionError, OSError) as e:
                self.errors.append(f"Error accessing {entry.path}: {e}")
    
    def _process_archive_queue_iter(self) -> Generator[FileInfo, None, None]:
        """
        Generator-based archive queue processing.
        Yields FileInfo objects from archived files.
        """
        while not self._archive_queue.empty():
            try:
                archive_path, scan_root, archive_depth = self._archive_queue.get_nowait()
            except queue.Empty:
                break
            
            try:
                with temp_extract_dir() as temp_dir:
                    files, is_password_protected = extract_archive(archive_path, temp_dir)
                    
                    if is_password_protected:
                        self.password_protected_archives.append(archive_path)
                        continue
                    
                    try:
                        rel_archive = str(Path(archive_path).relative_to(scan_root))
                    except ValueError:
                        rel_archive = Path(archive_path).name
                    
                    for extracted_file in files:
                        file_info = get_file_metadata(extracted_file, temp_dir, rel_archive)
                        
                        if self.hash_files and not file_info.is_directory:
                            md5, sha1, sha256 = self.hash_cache.get_or_compute(extracted_file)
                            file_info.md5 = md5
                            file_info.sha1 = sha1
                            file_info.sha256 = sha256
                        
                        calculate_risk_score(file_info)
                        yield file_info
                        
                        # Queue nested archives
                        if is_archive(extracted_file) and archive_depth + 1 < self.max_archive_depth:
                            self._archive_queue.put((extracted_file, temp_dir, archive_depth + 1))
            
            except (ArchiveError, Exception) as e:
                self.errors.append(f"Error extracting {archive_path}: {e}")
    
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
