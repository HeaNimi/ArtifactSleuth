"""
Archive extraction module.
Supports ZIP, 7z, RAR, TAR, GZ, BZ2, XZ formats.
Optimized for large archives (20GB+).
"""

import os
import zipfile
import tarfile
import tempfile
import shutil
import logging
from pathlib import Path
from typing import List, Tuple, Optional, Generator
from contextlib import contextmanager

logger = logging.getLogger(__name__)

# Optional imports for additional formats
try:
    import py7zr
    HAS_7Z = True
except ImportError:
    HAS_7Z = False

try:
    import rarfile
    # Check if unrar tool is available
    try:
        rarfile.UNRAR_TOOL = rarfile.UNRAR_TOOL or 'unrar'
        # Try to find unrar in common locations on Windows
        if os.name == 'nt':
            common_paths = [
                r'C:\Program Files\WinRAR\UnRAR.exe',
                r'C:\Program Files (x86)\WinRAR\UnRAR.exe',
                os.path.join(os.path.dirname(__file__), '..', 'bin', 'UnRAR.exe'),
            ]
            for path in common_paths:
                if os.path.exists(path):
                    rarfile.UNRAR_TOOL = path
                    break
        HAS_RAR = True
        HAS_RAR_TOOL = rarfile.tool_setup() is not None
    except Exception:
        HAS_RAR = True
        HAS_RAR_TOOL = False
except ImportError:
    HAS_RAR = False
    HAS_RAR_TOOL = False


class ArchiveError(Exception):
    """Custom exception for archive-related errors."""
    pass


class PasswordProtectedError(ArchiveError):
    """Exception for password-protected archives."""
    pass


def is_archive(file_path: str) -> bool:
    """Check if a file is a supported archive format."""
    path = Path(file_path)
    suffix = path.suffix.lower()
    
    # Check compound extensions like .tar.gz
    if len(path.suffixes) >= 2:
        compound = ''.join(path.suffixes[-2:]).lower()
        if compound in {'.tar.gz', '.tar.bz2', '.tar.xz'}:
            return True
    
    return suffix in {'.zip', '.7z', '.rar', '.tar', '.gz', '.bz2', '.xz', '.tgz', '.apk', '.jar'}


def get_archive_type(file_path: str) -> Optional[str]:
    """Determine the archive type based on extension and magic bytes."""
    path = Path(file_path)
    suffix = path.suffix.lower()
    
    # Check compound extensions
    if len(path.suffixes) >= 2:
        compound = ''.join(path.suffixes[-2:]).lower()
        if compound in {'.tar.gz', '.tar.bz2', '.tar.xz'}:
            return 'tar'
    
    if suffix == '.tgz':
        return 'tar'
    
    type_map = {
        '.zip': 'zip',
        '.apk': 'zip',
        '.jar': 'zip',
        '.7z': '7z',
        '.rar': 'rar',
        '.tar': 'tar',
        '.gz': 'gzip',
        '.bz2': 'bzip2',
        '.xz': 'xz',
    }
    
    return type_map.get(suffix)


@contextmanager
def temp_extract_dir():
    """Create a temporary directory for extraction that auto-cleans."""
    temp_dir = tempfile.mkdtemp(prefix='usb_forensic_')
    try:
        yield temp_dir
    finally:
        try:
            shutil.rmtree(temp_dir)
        except (OSError, IOError):
            pass


def extract_zip(archive_path: str, extract_to: str) -> Tuple[List[str], bool]:
    """
    Extract a ZIP archive.
    
    Returns:
        Tuple of (list of extracted file paths, is_password_protected)
    """
    extracted_files = []
    
    try:
        with zipfile.ZipFile(archive_path, 'r') as zf:
            # Check for password protection
            for info in zf.infolist():
                if info.flag_bits & 0x1:  # Encrypted flag
                    return [], True
            
            # Extract all files
            for info in zf.infolist():
                if info.is_dir():
                    continue
                try:
                    extracted_path = zf.extract(info, extract_to)
                    extracted_files.append(extracted_path)
                except (RuntimeError, zipfile.BadZipFile) as e:
                    if 'password' in str(e).lower() or 'encrypted' in str(e).lower():
                        return [], True
                    # Skip problematic files
                    continue
    
    except zipfile.BadZipFile:
        raise ArchiveError(f"Invalid or corrupted ZIP file: {archive_path}")
    except RuntimeError as e:
        if 'password' in str(e).lower():
            return [], True
        raise ArchiveError(f"Error extracting ZIP: {e}")
    
    return extracted_files, False


def extract_7z(archive_path: str, extract_to: str) -> Tuple[List[str], bool]:
    """
    Extract a 7z archive.
    
    Returns:
        Tuple of (list of extracted file paths, is_password_protected)
    """
    if not HAS_7Z:
        raise ArchiveError("py7zr not installed. Install with: pip install py7zr")
    
    extracted_files = []
    
    try:
        with py7zr.SevenZipFile(archive_path, mode='r') as szf:
            # Check for password protection
            if szf.needs_password():
                return [], True
            
            szf.extractall(path=extract_to)
            
            # Get list of extracted files
            for root, _, files in os.walk(extract_to):
                for file in files:
                    extracted_files.append(os.path.join(root, file))
    
    except py7zr.exceptions.PasswordRequired:
        return [], True
    except Exception as e:
        if 'password' in str(e).lower():
            return [], True
        raise ArchiveError(f"Error extracting 7z: {e}")
    
    return extracted_files, False


def extract_rar(archive_path: str, extract_to: str) -> Tuple[List[str], bool]:
    """
    Extract a RAR archive.
    
    Returns:
        Tuple of (list of extracted file paths, is_password_protected)
    """
    if not HAS_RAR:
        raise ArchiveError("rarfile not installed. Install with: pip install rarfile")
    
    if not HAS_RAR_TOOL:
        raise ArchiveError(
            "RAR extraction requires UnRAR tool. "
            "Install WinRAR or download UnRAR from https://www.rarlab.com/rar_add.htm "
            "and add to PATH or C:\\Program Files\\WinRAR\\"
        )
    
    extracted_files = []
    
    try:
        with rarfile.RarFile(archive_path, 'r') as rf:
            # Check for password protection
            if rf.needs_password():
                return [], True
            
            rf.extractall(extract_to)
            
            # Get list of extracted files
            for info in rf.infolist():
                if not info.is_dir():
                    extracted_files.append(os.path.join(extract_to, info.filename))
    
    except rarfile.PasswordRequired:
        return [], True
    except rarfile.BadRarFile:
        raise ArchiveError(f"Invalid or corrupted RAR file: {archive_path}")
    except Exception as e:
        if 'password' in str(e).lower():
            return [], True
        raise ArchiveError(f"Error extracting RAR: {e}")
    
    return extracted_files, False


def extract_tar(archive_path: str, extract_to: str) -> Tuple[List[str], bool]:
    """
    Extract a TAR archive (including .tar.gz, .tar.bz2, .tar.xz, .tgz).
    TAR archives don't support password protection.
    Handles large archives (20GB+) with streaming extraction.
    
    Returns:
        Tuple of (list of extracted file paths, is_password_protected)
    """
    extracted_files = []
    
    # Determine compression mode - try auto-detect first for reliability
    path = Path(archive_path)
    suffix = path.suffix.lower()
    
    # Mode detection order: try specific mode first, fall back to auto-detect
    modes_to_try = []
    
    if suffix == '.tgz' or archive_path.endswith('.tar.gz'):
        modes_to_try = ['r:gz', 'r:*', 'r']
    elif archive_path.endswith('.tar.bz2'):
        modes_to_try = ['r:bz2', 'r:*', 'r']
    elif archive_path.endswith('.tar.xz'):
        modes_to_try = ['r:xz', 'r:*', 'r']
    elif suffix == '.gz':
        modes_to_try = ['r:gz', 'r:*', 'r']
    elif suffix == '.bz2':
        modes_to_try = ['r:bz2', 'r:*', 'r']
    elif suffix == '.xz':
        modes_to_try = ['r:xz', 'r:*', 'r']
    elif suffix == '.tar':
        modes_to_try = ['r', 'r:*']
    else:
        modes_to_try = ['r:*', 'r']
    
    tf = None
    last_error = None
    
    for mode in modes_to_try:
        try:
            tf = tarfile.open(archive_path, mode)
            break
        except (tarfile.TarError, OSError, EOFError) as e:
            last_error = e
            continue
    
    if tf is None:
        raise ArchiveError(f"Error opening TAR archive (tried modes {modes_to_try}): {last_error}")
    
    try:
        # For large archives, iterate without loading full member list
        file_count = 0
        max_files = 500000  # Safety limit for very large archives
        
        for member in tf:
            if file_count >= max_files:
                logger.warning(f"TAR archive has more than {max_files} files, stopping extraction")
                break
            
            if member.isdir():
                continue
            
            # Security check
            if member.name.startswith('/') or '..' in member.name:
                continue
            
            # Skip very large individual files (>4GB) to avoid memory issues
            if member.size > 4 * 1024 * 1024 * 1024:
                logger.warning(f"Skipping large file in TAR: {member.name} ({member.size} bytes)")
                continue
            
            try:
                tf.extract(member, extract_to, set_attrs=False)
                extracted_files.append(os.path.join(extract_to, member.name))
                file_count += 1
            except (tarfile.TarError, OSError, IOError) as e:
                logger.debug(f"Failed to extract {member.name}: {e}")
                continue
    finally:
        tf.close()
    
    return extracted_files, False


def extract_archive(archive_path: str, extract_to: str) -> Tuple[List[str], bool]:
    """
    Extract an archive to a directory.
    
    Args:
        archive_path: Path to the archive file
        extract_to: Directory to extract to
    
    Returns:
        Tuple of (list of extracted file paths, is_password_protected)
    
    Raises:
        ArchiveError: If extraction fails
    """
    archive_type = get_archive_type(archive_path)
    
    if archive_type == 'zip':
        return extract_zip(archive_path, extract_to)
    elif archive_type == '7z':
        return extract_7z(archive_path, extract_to)
    elif archive_type == 'rar':
        return extract_rar(archive_path, extract_to)
    elif archive_type in {'tar', 'gzip', 'bzip2', 'xz'}:
        return extract_tar(archive_path, extract_to)
    else:
        raise ArchiveError(f"Unsupported archive format: {archive_path}")


def iter_archive_contents(archive_path: str) -> Generator[Tuple[str, int], None, None]:
    """
    Iterate over archive contents without extracting.
    Yields (filename, size) tuples.
    """
    archive_type = get_archive_type(archive_path)
    
    try:
        if archive_type == 'zip':
            with zipfile.ZipFile(archive_path, 'r') as zf:
                for info in zf.infolist():
                    if not info.is_dir():
                        yield info.filename, info.file_size
        
        elif archive_type == '7z' and HAS_7Z:
            with py7zr.SevenZipFile(archive_path, mode='r') as szf:
                for name, info in szf.archiveinfo().files.items():
                    if not info.is_directory:
                        yield name, info.uncompressed
        
        elif archive_type == 'rar' and HAS_RAR:
            with rarfile.RarFile(archive_path, 'r') as rf:
                for info in rf.infolist():
                    if not info.is_dir():
                        yield info.filename, info.file_size
        
        elif archive_type in {'tar', 'gzip', 'bzip2', 'xz'}:
            with tarfile.open(archive_path, 'r:*') as tf:
                for member in tf.getmembers():
                    if not member.isdir():
                        yield member.name, member.size
    
    except Exception:
        # If we can't iterate, just return empty
        return
