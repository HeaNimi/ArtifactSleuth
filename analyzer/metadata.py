"""
File metadata extraction module.
Includes extended metadata like Owner, Author, and document properties.
"""

import os
import stat
import ctypes
import platform
import socket
from datetime import datetime
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any
from pathlib import Path
import zipfile
import xml.etree.ElementTree as ET

try:
    import magic
    HAS_MAGIC = True
except ImportError:
    HAS_MAGIC = False

# Windows-specific imports for file owner and registry
try:
    import win32security
    import win32api
    import win32con
    import winreg
    import win32file
    import win32crypt
    HAS_WIN32 = True
except ImportError:
    HAS_WIN32 = False


# MIME type to extension mapping for mismatch detection
MIME_TO_EXTENSIONS = {
    # Documents
    'application/pdf': ['.pdf'],
    'application/msword': ['.doc'],
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document': ['.docx'],
    'application/vnd.ms-excel': ['.xls'],
    'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet': ['.xlsx'],
    'application/vnd.ms-powerpoint': ['.ppt'],
    'application/vnd.openxmlformats-officedocument.presentationml.presentation': ['.pptx'],
    'application/rtf': ['.rtf'],
    'text/plain': ['.txt', '.log', '.md', '.csv', '.ini', '.cfg', '.conf'],
    'text/html': ['.html', '.htm'],
    'text/css': ['.css'],
    'text/javascript': ['.js'],
    'application/json': ['.json'],
    'application/xml': ['.xml'],
    
    # Images
    'image/jpeg': ['.jpg', '.jpeg'],
    'image/png': ['.png'],
    'image/gif': ['.gif'],
    'image/bmp': ['.bmp'],
    'image/webp': ['.webp'],
    'image/svg+xml': ['.svg'],
    'image/x-icon': ['.ico'],
    
    # Audio/Video
    'audio/mpeg': ['.mp3'],
    'audio/wav': ['.wav'],
    'video/mp4': ['.mp4'],
    'video/x-msvideo': ['.avi'],
    'video/quicktime': ['.mov'],
    
    # Archives
    'application/zip': ['.zip', '.docx', '.xlsx', '.pptx', '.odt', '.ods', '.jar', '.apk'],
    'application/x-rar-compressed': ['.rar'],
    'application/x-7z-compressed': ['.7z'],
    'application/gzip': ['.gz', '.tgz'],
    'application/x-tar': ['.tar'],
    
    # Executables
    'application/x-executable': ['.exe', '.dll', '.so'],
    'application/x-dosexec': ['.exe', '.dll', '.sys', '.scr'],
    'application/x-msi': ['.msi'],
    
    # Other
    'application/octet-stream': None,  # Generic binary, skip check
}


@dataclass
class FileInfo:
    """Represents information about a scanned file."""
    path: str                                   # Full path to the file
    name: str                                   # File name
    relative_path: str                          # Path relative to scan root
    size: int                                   # Size in bytes
    created_time: Optional[datetime] = None     # Creation timestamp
    modified_time: Optional[datetime] = None    # Modification timestamp
    accessed_time: Optional[datetime] = None    # Access timestamp
    is_directory: bool = False                  # Is this a directory?
    is_archive: bool = False                    # Is this an archive?
    is_password_protected: bool = False         # Password protected archive?
    archive_path: Optional[str] = None          # Path of parent archive (if extracted)
    mime_type: Optional[str] = None             # MIME type
    file_type: Optional[str] = None             # Human-readable file type (generic)
    friendly_type: Optional[str] = None         # Windows friendly type description
    permissions: Optional[str] = None           # File permissions string
    
    # Extended metadata
    owner: Optional[str] = None                 # File owner (Windows)
    attributes: Optional[str] = None            # File attributes (R/H/S/A)
    computer: Optional[str] = None              # Computer name
    parent_folder: Optional[str] = None         # Parent folder path
    extension_mismatch: bool = False            # MIME type doesn't match extension
    expected_extensions: Optional[str] = None   # Expected extensions for MIME type
    
    # Document properties (for Office files)
    doc_author: Optional[str] = None
    doc_last_modified_by: Optional[str] = None
    doc_title: Optional[str] = None
    doc_subject: Optional[str] = None
    doc_keywords: Optional[str] = None
    doc_created: Optional[str] = None
    doc_modified: Optional[str] = None
    doc_company: Optional[str] = None
    doc_manager: Optional[str] = None
    doc_category: Optional[str] = None
    doc_comments: Optional[str] = None
    
    # Hashes (populated by hasher module)
    md5: Optional[str] = None
    sha1: Optional[str] = None
    sha256: Optional[str] = None
    
    # VirusTotal results (populated by virustotal module)
    vt_detected: Optional[bool] = None
    vt_detection_ratio: Optional[str] = None
    vt_link: Optional[str] = None
    vt_error: Optional[str] = None
    
    # Document analysis results (populated by document_analyzer module)
    doc_has_macros: Optional[bool] = None
    doc_has_javascript: Optional[bool] = None
    doc_suspicious_elements: List[str] = field(default_factory=list)
    doc_analysis_error: Optional[str] = None
    
    # Executable analysis results (populated by executable_analyzer module)
    exe_domains: List[str] = field(default_factory=list)
    exe_ips: List[str] = field(default_factory=list)
    exe_urls: List[str] = field(default_factory=list)
    exe_suspicious_imports: List[str] = field(default_factory=list)
    exe_suspicious_imports: List[str] = field(default_factory=list)
    exe_analysis_error: Optional[str] = None
    signature_info: Dict[str, Any] = field(default_factory=dict)  # Digital signature details
    
    # PE-specific metadata (populated via pywin32)
    exe_company: Optional[str] = None
    exe_product: Optional[str] = None
    exe_description: Optional[str] = None
    exe_version: Optional[str] = None
    is_signed: Optional[bool] = None
    sig_subject: Optional[str] = None
    sig_issuer: Optional[str] = None
    
    # Risk assessment
    risk_score: int = 0  # 0-100, higher = more suspicious
    risk_reasons: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON/CSV export."""
        return {
            'path': self.path,
            'name': self.name,
            'relative_path': self.relative_path,
            'size': self.size,
            'size_human': self._human_readable_size(),
            'created_time': self.created_time.isoformat() if self.created_time else None,
            'modified_time': self.modified_time.isoformat() if self.modified_time else None,
            'accessed_time': self.accessed_time.isoformat() if self.accessed_time else None,
            'is_directory': self.is_directory,
            'is_archive': self.is_archive,
            'is_password_protected': self.is_password_protected,
            'archive_path': self.archive_path,
            'mime_type': self.mime_type,
            'file_type': self.file_type,
            'friendly_type': self.friendly_type,
            'permissions': self.permissions,
            'owner': self.owner,
            'attributes': self.attributes,
            'computer': self.computer,
            'parent_folder': self.parent_folder,
            'extension_mismatch': self.extension_mismatch,
            'expected_extensions': self.expected_extensions,
            'doc_author': self.doc_author,
            'doc_last_modified_by': self.doc_last_modified_by,
            'doc_title': self.doc_title,
            'doc_subject': self.doc_subject,
            'doc_keywords': self.doc_keywords,
            'doc_created': self.doc_created,
            'doc_modified': self.doc_modified,
            'doc_company': self.doc_company,
            'doc_manager': self.doc_manager,
            'doc_category': self.doc_category,
            'doc_comments': self.doc_comments,
            'md5': self.md5,
            'sha1': self.sha1,
            'sha256': self.sha256,
            'vt_detected': self.vt_detected,
            'vt_detection_ratio': self.vt_detection_ratio,
            'vt_link': self.vt_link,
            'vt_error': self.vt_error,
            'doc_has_macros': self.doc_has_macros,
            'doc_has_javascript': self.doc_has_javascript,
            'doc_suspicious_elements': self.doc_suspicious_elements,
            'doc_analysis_error': self.doc_analysis_error,
            'exe_domains': self.exe_domains,
            'exe_ips': self.exe_ips,
            'exe_urls': self.exe_urls,
            'exe_suspicious_imports': self.exe_suspicious_imports,
            'exe_analysis_error': self.exe_analysis_error,
            'signature_info': self.signature_info,
            'exe_company': self.exe_company,
            'exe_product': self.exe_product,
            'exe_description': self.exe_description,
            'exe_version': self.exe_version,
            'is_signed': self.is_signed,
            'sig_subject': self.sig_subject,
            'sig_issuer': self.sig_issuer,
            'risk_score': self.risk_score,
            'risk_reasons': self.risk_reasons,
        }
    
    def _human_readable_size(self) -> str:
        """Convert size to human-readable format."""
        size = self.size
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size < 1024.0:
                return f"{size:.1f} {unit}"
            size /= 1024.0
        return f"{size:.1f} PB"


# Cache for file owner lookups to avoid repeated slow calls
_owner_cache: Dict[str, Optional[str]] = {}
# Cache for friendly file type lookups
_file_type_cache: Dict[str, str] = {}

def get_file_owner(file_path: str) -> Optional[str]:
    """
    Get the file owner on Windows.
    Tries pywin32 first, falls back to dir /q command if not available.
    """
    # Check cache first
    if file_path in _owner_cache:
        return _owner_cache[file_path]
    
    owner = None
    
    # Method 1: Try pywin32 (fastest)
    if HAS_WIN32:
        try:
            sd = win32security.GetFileSecurity(
                file_path, 
                win32security.OWNER_SECURITY_INFORMATION
            )
            owner_sid = sd.GetSecurityDescriptorOwner()
            name, domain, _ = win32security.LookupAccountSid(None, owner_sid)
            owner = f"{domain}\\{name}" if domain else name
        except Exception:
            pass
    
    # Method 2: Fallback to dir /q (works on standard Windows without deps)
    if owner is None:
        try:
            import subprocess
            
            # Escape the path for cmd
            path = str(Path(file_path).resolve())
            
            # dir /q /n returns owner info. /n ensures long list format.
            # Output format:
            # 01/23/2026  01:22 PM                14 DOMAIN\User          filename.ext
            
            # Using partial matching on the file name line
            cmd = ['cmd', '/c', 'dir', '/q', '/n', path]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0
            )
            
            if result.returncode == 0:
                stdout = result.stdout
                filename = Path(path).name
                
                for line in stdout.splitlines():
                    # Check if line ends with filename (heuristically)
                    if not line.strip().endswith(filename):
                        continue
                        
                    parts = line.split()
                    if len(parts) < 4:
                        continue
                        
                    # Parse from left to right to find Size field
                    # Format: DATE TIME [AM/PM] [DIR/SIZE] OWNER FILENAME
                    owner_index = -1
                    
                    for i, part in enumerate(parts):
                        # Skip Date/Time parts
                        if '/' in part or '-' in part or ':' in part:
                            continue
                        if part.upper() in ('AM', 'PM'):
                            continue
                            
                        # Found Size or <DIR>
                        if part == '<DIR>' or part.replace(',', '').isdigit():
                            # Owner is typically the next field
                            if i + 1 < len(parts):
                                owner = parts[i + 1]
                                # Verify it's not part of the filename - usually owner doesn't have spaces in this view
                                # unless it's "BUILTIN\Administrators" etc.
                                break
                    
                    if owner:
                        break
        except Exception:
            pass
    
    # Cache the result
    _owner_cache[file_path] = owner
    return owner

def get_friendly_file_type(extension: str) -> str:
    """Get Windows friendly file type description from registry."""
    if not extension:
        return "File"
        
    ext = extension.lower()
    if ext in _file_type_cache:
        return _file_type_cache[ext]
    
    description = f"{ext.upper()} File"
    
    if HAS_WIN32:
        try:
            # 1. Look up the class name for the extension
            with winreg.OpenKey(winreg.HKEY_CLASSES_ROOT, ext) as key:
                class_name = winreg.QueryValue(key, None)
            
            if class_name:
                # 2. Look up the description for the class name
                with winreg.OpenKey(winreg.HKEY_CLASSES_ROOT, class_name) as key:
                    desc = winreg.QueryValue(key, None)
                    if desc:
                        description = desc
        except Exception:
            pass
            
    _file_type_cache[ext] = description
    return description

def get_file_attributes(file_path: str) -> Optional[str]:
    """Get Windows file attributes (R/H/S/A)."""
    if not HAS_WIN32:
        return None
        
    try:
        attrs = win32api.GetFileAttributes(file_path)
        result = []
        if attrs & win32con.FILE_ATTRIBUTE_READONLY:
            result.append("R")
        if attrs & win32con.FILE_ATTRIBUTE_HIDDEN:
            result.append("H")
        if attrs & win32con.FILE_ATTRIBUTE_SYSTEM:
            result.append("S")
        if attrs & win32con.FILE_ATTRIBUTE_ARCHIVE:
            result.append("A")
        if attrs & win32con.FILE_ATTRIBUTE_COMPRESSED:
            result.append("C")
        if attrs & win32con.FILE_ATTRIBUTE_ENCRYPTED:
            result.append("E")
            
        return "".join(result) if result else "N" # Normal
    except Exception:
        return None

def check_extension_mismatch(file_path: str, mime_type: Optional[str]) -> tuple:
    """
    Check if the file extension matches the detected MIME type.
    
    Returns:
        Tuple of (is_mismatch, expected_extensions)
    """
    if not mime_type:
        return False, None
    
    path = Path(file_path)
    ext = path.suffix.lower()
    
    expected = MIME_TO_EXTENSIONS.get(mime_type)
    
    # Skip check for generic binary or unknown MIME types
    if expected is None:
        return False, None
    
    if ext not in expected:
        return True, ', '.join(expected)
    
    return False, None


def extract_office_properties(file_path: str) -> Dict[str, Optional[str]]:
    """
    Extract document properties from Office files (docx, xlsx, pptx).
    These are stored in docProps/core.xml and docProps/app.xml inside the ZIP.
    """
    props = {
        'author': None,
        'last_modified_by': None,
        'title': None,
        'subject': None,
        'keywords': None,
        'created': None,
        'modified': None,
        'company': None,
        'manager': None,
        'category': None,
        'comments': None,
    }
    
    path = Path(file_path)
    if path.suffix.lower() not in {'.docx', '.xlsx', '.pptx', '.odt', '.ods', '.odp'}:
        return props
    
    try:
        with zipfile.ZipFile(file_path, 'r') as zf:
            # Core properties (author, title, etc.)
            if 'docProps/core.xml' in zf.namelist():
                core_xml = zf.read('docProps/core.xml')
                root = ET.fromstring(core_xml)
                
                # Define namespaces
                ns = {
                    'cp': 'http://schemas.openxmlformats.org/package/2006/metadata/core-properties',
                    'dc': 'http://purl.org/dc/elements/1.1/',
                    'dcterms': 'http://purl.org/dc/terms/',
                }
                
                # Extract properties
                creator = root.find('.//dc:creator', ns)
                if creator is not None and creator.text:
                    props['author'] = creator.text
                
                last_mod_by = root.find('.//cp:lastModifiedBy', ns)
                if last_mod_by is not None and last_mod_by.text:
                    props['last_modified_by'] = last_mod_by.text
                
                title = root.find('.//dc:title', ns)
                if title is not None and title.text:
                    props['title'] = title.text
                
                subject = root.find('.//dc:subject', ns)
                if subject is not None and subject.text:
                    props['subject'] = subject.text
                
                keywords = root.find('.//cp:keywords', ns)
                if keywords is not None and keywords.text:
                    props['keywords'] = keywords.text
                
                created = root.find('.//dcterms:created', ns)
                if created is not None and created.text:
                    props['created'] = created.text
                
                modified = root.find('.//dcterms:modified', ns)
                if modified is not None and modified.text:
                    props['modified'] = modified.text
                
                category = root.find('.//cp:category', ns)
                if category is not None and category.text:
                    props['category'] = category.text
                
                description = root.find('.//dc:description', ns)
                if description is not None and description.text:
                    props['comments'] = description.text
            
            # App properties (company, manager, etc.)
            if 'docProps/app.xml' in zf.namelist():
                app_xml = zf.read('docProps/app.xml')
                root = ET.fromstring(app_xml)
                
                ns = {
                    'ep': 'http://schemas.openxmlformats.org/officeDocument/2006/extended-properties',
                }
                
                company = root.find('.//ep:Company', ns)
                if company is not None and company.text:
                    props['company'] = company.text
                
                manager = root.find('.//ep:Manager', ns)
                if manager is not None and manager.text:
                    props['manager'] = manager.text
    
    except Exception:
        pass
    
    return props


def extract_exe_info(file_path: str) -> Dict[str, Any]:
    """
    Extract PE version information and check digital signature using pywin32.
    """
    info = {
        'company': None,
        'product': None,
        'description': None,
        'version': None,
        'is_signed': False,
        'sig_subject': None,
        'sig_issuer': None
    }
    
    if not HAS_WIN32:
        return info
        
    ext = Path(file_path).suffix.lower()
    if ext not in {'.exe', '.dll', '.sys', '.scr', '.ocx', '.drv'}:
        return info
        
    # 1. Extract Version Info
    try:
        size = win32api.GetFileVersionInfoSize(file_path)
        if size > 0:
            res = win32api.GetFileVersionInfo(file_path, "\\")
            # Extract standard parts
            info['version'] = "{}.{}.{}.{}".format(
                res['FileVersionMS'] >> 16, res['FileVersionMS'] & 0xFFFF,
                res['FileVersionLS'] >> 16, res['FileVersionLS'] & 0xFFFF
            )
            
            # Extract strings (need to find the right language/codepage first)
            lang, codepage = win32api.GetFileVersionInfo(file_path, "\\VarFileInfo\\Translation")[0]
            str_info_path = u"\\StringFileInfo\\%04X%04X\\%s"
            
            def get_str(name):
                try:
                    return win32api.GetFileVersionInfo(file_path, str_info_path % (lang, codepage, name))
                except:
                    return None
            
            info['company'] = get_str("CompanyName")
            info['product'] = get_str("ProductName")
            info['description'] = get_str("FileDescription")
    except Exception:
        pass
        
    # 2. Check Digital Signature (Simple check)
    try:
        # CryptQueryObject can tell us if a file has a certificate
        # This is a bit advanced for a single call but works for "is signed" detection
        with open(file_path, 'rb') as f:
            content = f.read()
            
        # We check for PKCS#7 signature in the file
        # In a real forensic tool, we'd use WinVerifyTrust, but pywin32 
        # doesn't wrap it simply. win32crypt is our best bet.
        try:
            # Check if it's even a candidate for signing
            # This is a heuristic: check if it has a security directory (PKCS#7)
            # using the raw bytes since we want to avoid extra pefile dependencies here
            # if we can, but we already have pefile in the project.
            
            # Using win32crypt to query the object
            msg_handle, _, _, _ = win32crypt.CryptQueryObject(
                win32crypt.CERT_QUERY_OBJECT_FILE,
                file_path,
                win32crypt.CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
                win32crypt.CERT_QUERY_FORMAT_FLAG_ALL,
                0
            )
            if msg_handle:
                info['is_signed'] = True
                # Further extraction of subject/issuer would require iterating certificates 
                # in the message, which is quite verbose in pywin32.
                # For now, "True" is a huge improvement.
        except:
            pass
    except Exception:
        pass
        
    return info


def get_file_stats_win32(file_path: str) -> Dict[str, Any]:
    """Get file stats using native win32file for maximum accuracy."""
    if not HAS_WIN32:
        return {}
        
    try:
        # GetFileAttributesEx provides most info in one call
        data = win32file.GetFileAttributesEx(file_path)
        # attributes, creation_time, last_access_time, last_write_time, size
        return {
            'attributes': data[0],
            'created': datetime.fromtimestamp(data[1].timestamp()),
            'accessed': datetime.fromtimestamp(data[2].timestamp()),
            'modified': datetime.fromtimestamp(data[3].timestamp()),
            'size': data[4]
        }
    except Exception:
        return {}


def get_file_metadata(file_path: str, scan_root: str, archive_path: Optional[str] = None) -> FileInfo:
    """
    Extract metadata from a file.
    
    Args:
        file_path: Full path to the file
        scan_root: Root directory of the scan
        archive_path: Path of parent archive if file was extracted
    
    Returns:
        FileInfo object with metadata
    """
    path = Path(file_path)
    
    # Try pywin32 first for metadata if on Windows
    win32_stats = get_file_stats_win32(file_path)
    
    if win32_stats:
        size = win32_stats['size']
        created_time = win32_stats['created']
        modified_time = win32_stats['modified']
        accessed_time = win32_stats['accessed']
    else:
        stat_info = os.stat(file_path)
        size = stat_info.st_size
        created_time = datetime.fromtimestamp(stat_info.st_ctime)
        modified_time = datetime.fromtimestamp(stat_info.st_mtime)
        accessed_time = datetime.fromtimestamp(stat_info.st_atime)
    
    # Calculate relative path
    try:
        relative_path = str(path.relative_to(scan_root))
    except ValueError:
        relative_path = path.name
    
    # If from archive, include archive path in relative path (using / like a file path)
    if archive_path:
        relative_path = f"{archive_path}/{relative_path}"
    
    
    # Get permissions
    try:
        mode = os.stat(file_path).st_mode
        permissions = stat.filemode(mode)
    except:
        permissions = None
    
    # Get file owner (Windows)
    owner = get_file_owner(file_path)
    
    # Get file attributes
    attributes = get_file_attributes(file_path)
    
    # Get friendly file type
    friendly_type = get_friendly_file_type(path.suffix)
    
    # Get computer name
    computer = platform.node()
    
    # Get parent folder
    parent_folder = str(path.parent)
    
    # Get file type using python-magic if available
    mime_type = None
    file_type = None
    if HAS_MAGIC and path.is_file():
        try:
            mime_type = magic.from_file(str(path), mime=True)
            file_type = magic.from_file(str(path))
        except Exception:
            pass
    
    # Check extension mismatch
    extension_mismatch, expected_extensions = check_extension_mismatch(file_path, mime_type)
    
    # Check if archive
    archive_extensions = {'.zip', '.7z', '.rar', '.tar', '.gz', '.bz2', '.xz', '.tgz', '.tar.gz', '.tar.bz2', '.apk', '.jar'}
    is_archive = path.suffix.lower() in archive_extensions or (
        len(path.suffixes) >= 2 and ''.join(path.suffixes[-2:]).lower() in archive_extensions
    )
    
    # Extract Office document properties
    office_props = extract_office_properties(file_path)
    
    # Extract Executable information (using pywin32)
    exe_info = extract_exe_info(file_path)
    
    return FileInfo(
        path=str(path),
        name=path.name,
        relative_path=relative_path,
        size=size,
        created_time=created_time,
        modified_time=modified_time,
        accessed_time=accessed_time,
        is_directory=path.is_dir(),
        is_archive=is_archive,
        archive_path=archive_path,
        mime_type=mime_type,
        file_type=file_type,
        friendly_type=friendly_type,
        permissions=permissions,
        owner=owner,
        attributes=attributes,
        computer=computer,
        parent_folder=parent_folder,
        extension_mismatch=extension_mismatch,
        expected_extensions=expected_extensions,
        doc_author=office_props['author'],
        doc_last_modified_by=office_props['last_modified_by'],
        doc_title=office_props['title'],
        doc_subject=office_props['subject'],
        doc_keywords=office_props['keywords'],
        doc_created=office_props['created'],
        doc_modified=office_props['modified'],
        doc_company=office_props['company'],
        doc_manager=office_props['manager'],
        doc_category=office_props['category'],
        doc_comments=office_props['comments'],
        exe_company=exe_info['company'],
        exe_product=exe_info['product'],
        exe_description=exe_info['description'],
        exe_version=exe_info['version'],
        is_signed=exe_info['is_signed'],
        sig_subject=exe_info['sig_subject'],
        sig_issuer=exe_info['sig_issuer']
    )


def calculate_risk_score(file_info: FileInfo) -> None:
    """
    Calculate risk score based on analysis results.
    Modifies the FileInfo object in place.
    """
    score = 0
    reasons = []
    
    # VirusTotal detection
    if file_info.vt_detected:
        score += 50
        reasons.append(f"VirusTotal detected: {file_info.vt_detection_ratio}")
    
    # Extension mismatch (potential file spoofing)
    if file_info.extension_mismatch:
        score += 15
        reasons.append(f"Extension mismatch! Expected: {file_info.expected_extensions}")
    
    # Document analysis
    if file_info.doc_has_macros:
        score += 20
        reasons.append("Contains macros")
    
    if file_info.doc_has_javascript:
        score += 25
        reasons.append("Contains JavaScript")
    
    if file_info.doc_suspicious_elements:
        score += 10 * len(file_info.doc_suspicious_elements)
        for elem in file_info.doc_suspicious_elements:
            reasons.append(f"Suspicious element: {elem}")
    
    # Executable analysis
    if file_info.exe_suspicious_imports:
        score += 5 * len(file_info.exe_suspicious_imports)
        reasons.append(f"Suspicious imports: {len(file_info.exe_suspicious_imports)}")
    
    if file_info.exe_domains or file_info.exe_ips:
        # Having network indicators isn't necessarily bad, but worth noting
        score += 5
        reasons.append(f"Network indicators: {len(file_info.exe_domains)} domains, {len(file_info.exe_ips)} IPs")
    
    # Suspicious file extensions
    suspicious_extensions = {'.exe', '.dll', '.scr', '.bat', '.cmd', '.ps1', '.vbs', '.js', '.hta', '.msi', '.apk', '.jar'}
    ext = Path(file_info.name).suffix.lower()
    if ext in suspicious_extensions:
        score += 5
        reasons.append(f"Executable/Mobile file type: {ext}")
    
    # APK/Android specific indicators
    if file_info.name.lower() == 'classes.dex':
        score += 10
        reasons.append("Android Executable (DEX)")
    
    if file_info.name.lower().endswith('.so') and file_info.archive_path and '.apk' in file_info.archive_path.lower():
        score += 5
        reasons.append("Android Native Library (SO)")
    
    # Cap at 100
    file_info.risk_score = min(score, 100)
    file_info.risk_reasons = reasons
