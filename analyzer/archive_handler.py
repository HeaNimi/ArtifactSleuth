"""
Archive extraction module.
Supports ZIP, 7z, RAR, TAR, GZ, BZ2, XZ formats.
"""

import os
import zipfile
import tarfile
import tempfile
import shutil
from pathlib import Path
from typing import List, Tuple, Optional, Generator
from contextlib import contextmanager

# Optional imports for additional formats
try:
    import py7zr
    HAS_7Z = True
except ImportError:
    HAS_7Z = False

try:
    import rarfile
    HAS_RAR = True
except ImportError:
    HAS_RAR = False


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
    
    Returns:
        Tuple of (list of extracted file paths, is_password_protected)
    """
    extracted_files = []
    
    # Determine compression mode
    path = Path(archive_path)
    suffix = path.suffix.lower()
    
    if suffix == '.tgz' or archive_path.endswith('.tar.gz'):
        mode = 'r:gz'
    elif archive_path.endswith('.tar.bz2'):
        mode = 'r:bz2'
    elif archive_path.endswith('.tar.xz'):
        mode = 'r:xz'
    elif suffix == '.gz':
        mode = 'r:gz'
    elif suffix == '.bz2':
        mode = 'r:bz2'
    elif suffix == '.xz':
        mode = 'r:xz'
    else:
        mode = 'r'
    
    try:
        with tarfile.open(archive_path, mode) as tf:
            # Security: filter out absolute paths and path traversal
            for member in tf.getmembers():
                if member.isdir():
                    continue
                # Security check
                if member.name.startswith('/') or '..' in member.name:
                    continue
                
                try:
                    tf.extract(member, extract_to)
                    extracted_files.append(os.path.join(extract_to, member.name))
                except (tarfile.TarError, OSError):
                    continue
    
    except tarfile.TarError as e:
        raise ArchiveError(f"Error extracting TAR: {e}")
    
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
