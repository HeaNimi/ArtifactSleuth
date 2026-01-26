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

# Magic byte signatures for archive detection
MAGIC_SIGNATURES = {
    b'PK\x03\x04': 'zip',           # ZIP/APK/JAR
    b'PK\x05\x06': 'zip',           # Empty ZIP
    b'PK\x07\x08': 'zip',           # Spanned ZIP
    b'Rar!\x1a\x07': 'rar',         # RAR
    b"7z\xbc\xaf'\x1c": '7z',       # 7z
    b'\x1f\x8b': 'gzip',            # GZIP
    b'BZh': 'bzip2',                # BZIP2
    b'\xfd7zXZ\x00': 'xz',          # XZ
}

def detect_archive_by_magic(file_path: str) -> Optional[str]:
    """Detect archive type by reading magic bytes from file header."""
    try:
        with open(file_path, 'rb') as f:
            header = f.read(16)
        
        if not header:
            return None
        
        # Check known signatures
        for sig, archive_type in MAGIC_SIGNATURES.items():
            if header.startswith(sig):
                return archive_type
        
        # TAR has magic at offset 257
        try:
            with open(file_path, 'rb') as f:
                f.seek(257)
                tar_magic = f.read(8)
                if tar_magic.startswith(b'ustar'):
                    return 'tar'
        except (OSError, IOError):
            pass
        
        # Check for uncompressed TAR (old format) - look for null bytes pattern
        # First 100 bytes is filename, should be mostly printable or null
        if len(header) >= 2 and header[0:2] != b'\x00\x00':
            # Could be old-style TAR, but we can't be sure
            pass
        
        return None
    except (OSError, IOError):
        return None

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
    """Check if a file is a supported archive format using extension and magic bytes."""
    path = Path(file_path)
    suffix = path.suffix.lower()
    
    # Check by extension first (fast path)
    # Check compound extensions like .tar.gz
    if len(path.suffixes) >= 2:
        compound = ''.join(path.suffixes[-2:]).lower()
        if compound in {'.tar.gz', '.tar.bz2', '.tar.xz'}:
            return True
    
    if suffix in {'.zip', '.7z', '.rar', '.tar', '.gz', '.bz2', '.xz', '.tgz', '.apk', '.jar'}:
        return True
    
    # For files without archive extension, check magic bytes
    magic_type = detect_archive_by_magic(file_path)
    if magic_type:
        return True
    
    return False


def get_archive_type(file_path: str) -> Optional[str]:
    """Determine the archive type based on extension and magic bytes."""
    path = Path(file_path)
    suffix = path.suffix.lower()
    
    # Check compound extensions
    if len(path.suffixes) >= 2:
        compound = ''.join(path.suffixes[-2:]).lower()
        if compound in {'.tar.gz', '.tar.bz2', '.tar.xz'}:
            # Verify with magic bytes - these should start with gzip/bz2/xz magic
            magic_type = detect_archive_by_magic(file_path)
            if magic_type in {'gzip', 'bzip2', 'xz'}:
                return 'tar'  # Compressed tar
            elif magic_type == 'tar':
                return 'tar'  # Already uncompressed
            elif magic_type:
                # File is actually a different type (e.g., ZIP mislabeled as .tar.gz)
                logger.warning(f"File {path.name} has extension {compound} but is actually {magic_type}")
                return magic_type
            # Fall through to extension-based if magic detection fails
            return 'tar'
    
    if suffix == '.tgz':
        magic_type = detect_archive_by_magic(file_path)
        if magic_type == 'gzip':
            return 'tar'
        elif magic_type and magic_type != 'tar':
            logger.warning(f"File {path.name} has extension .tgz but is actually {magic_type}")
            return magic_type
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
    
    extension_type = type_map.get(suffix)
    
    # Verify with magic bytes for common mislabeled files
    if extension_type:
        magic_type = detect_archive_by_magic(file_path)
        if magic_type and magic_type != extension_type:
            # Special case: .gz file might contain tar (tar.gz with single extension)
            if extension_type == 'gzip' and magic_type == 'gzip':
                return 'gzip'
            # File type doesn't match extension
            logger.warning(f"File {path.name} has extension {suffix} but is actually {magic_type}")
            return magic_type
    
    return extension_type


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
    
    # First, verify the file is actually a TAR/compressed archive using magic bytes
    magic_type = detect_archive_by_magic(archive_path)
    path = Path(archive_path)
    suffix = path.suffix.lower()
    
    # Check if file is actually a different archive type
    if magic_type and magic_type not in {'tar', 'gzip', 'bzip2', 'xz'}:
        raise ArchiveError(
            f"File {path.name} has TAR-like extension but is actually a {magic_type.upper()} file. "
            f"Magic bytes indicate: {magic_type}"
        )
    
    # Mode detection order: try specific mode first, fall back to auto-detect
    modes_to_try = []
    
    # Use magic type to determine mode if available
    if magic_type == 'gzip':
        modes_to_try = ['r:gz', 'r:*']
    elif magic_type == 'bzip2':
        modes_to_try = ['r:bz2', 'r:*']
    elif magic_type == 'xz':
        modes_to_try = ['r:xz', 'r:*']
    elif magic_type == 'tar':
        modes_to_try = ['r', 'r:*']
    elif suffix == '.tgz' or archive_path.endswith('.tar.gz'):
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
        # Provide helpful error message
        if magic_type is None:
            raise ArchiveError(
                f"Cannot open {path.name}: File does not appear to be a valid archive. "
                f"No recognized archive magic bytes found. "
                f"The file may be corrupted, empty, or not an archive at all."
            )
        else:
            raise ArchiveError(
                f"Error opening TAR archive {path.name} (detected type: {magic_type}): {last_error}"
            )
    
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


def extract_gzip(archive_path: str, extract_to: str) -> Tuple[List[str], bool]:
    """
    Extract a standalone GZIP file (not tar.gz).
    Simply decompresses the .gz file to extract_to directory.
    
    Returns:
        Tuple of (list of extracted file paths, is_password_protected)
    """
    import gzip
    
    path = Path(archive_path)
    # Output filename: remove .gz extension
    output_name = path.stem if path.suffix.lower() == '.gz' else path.name + '.decompressed'
    output_path = os.path.join(extract_to, output_name)
    
    try:
        with gzip.open(archive_path, 'rb') as gz_in:
            with open(output_path, 'wb') as f_out:
                # Stream in chunks for large files
                while True:
                    chunk = gz_in.read(64 * 1024)
                    if not chunk:
                        break
                    f_out.write(chunk)
        return [output_path], False
    except Exception as e:
        raise ArchiveError(f"Error extracting GZIP file: {e}")


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
    magic_type = detect_archive_by_magic(archive_path)
    
    # Use magic type to correct misidentified files
    if magic_type and magic_type != archive_type:
        logger.info(f"File {Path(archive_path).name}: extension suggests {archive_type}, magic bytes indicate {magic_type}")
        # Trust magic bytes over extension for actual extraction
        if magic_type in {'zip', '7z', 'rar'}:
            archive_type = magic_type
    
    if archive_type == 'zip':
        return extract_zip(archive_path, extract_to)
    elif archive_type == '7z':
        return extract_7z(archive_path, extract_to)
    elif archive_type == 'rar':
        return extract_rar(archive_path, extract_to)
    elif archive_type == 'tar':
        return extract_tar(archive_path, extract_to)
    elif archive_type == 'gzip':
        # Check if this is a tar.gz or standalone gzip
        # Try tar extraction first, fall back to simple gzip decompress
        try:
            return extract_tar(archive_path, extract_to)
        except ArchiveError:
            # Not a tar.gz, try as standalone gzip
            logger.debug(f"File {Path(archive_path).name} is not tar.gz, trying standalone gzip")
            return extract_gzip(archive_path, extract_to)
    elif archive_type in {'bzip2', 'xz'}:
        # Similar handling for bz2/xz - could be tar.bz2 or standalone
        try:
            return extract_tar(archive_path, extract_to)
        except ArchiveError:
            # For now, we don't have standalone bz2/xz handlers
            raise ArchiveError(f"File appears to be standalone {archive_type}, not a tar archive")
    else:
        # Last resort: check magic bytes for unknown extensions
        if magic_type:
            logger.warning(f"Unknown extension for {archive_path}, but detected as {magic_type}")
            if magic_type == 'zip':
                return extract_zip(archive_path, extract_to)
            elif magic_type == '7z':
                return extract_7z(archive_path, extract_to)
            elif magic_type == 'rar':
                return extract_rar(archive_path, extract_to)
            elif magic_type in {'tar', 'gzip', 'bzip2', 'xz'}:
                return extract_tar(archive_path, extract_to)
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
