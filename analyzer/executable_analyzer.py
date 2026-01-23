"""
Executable analysis module for PE files (.exe, .dll, .sys, .scr).
Extracts strings, domains, IPs, URLs, and identifies suspicious imports.
"""

import re
import logging
from pathlib import Path
from typing import List, Tuple, Optional, Dict, Any, Set

logger = logging.getLogger(__name__)

try:
    import pefile
    HAS_PEFILE = True
except ImportError:
    HAS_PEFILE = False


# Regex patterns for extracting network indicators
IP_PATTERN = re.compile(
    r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
    r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
)

# More restrictive domain pattern to reduce false positives
DOMAIN_PATTERN = re.compile(
    r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)'
    r'+(?:com|net|org|io|info|biz|gov|edu|mil|co|uk|de|ru|cn|jp|br|au|in|fr|it|nl|es|pl|kr|'
    r'xyz|top|pw|cc|tk|ml|ga|cf|gq|ws|su|to|me|tv|asia|mobi|tel|name|pro|aero|coop|museum)\b',
    re.IGNORECASE
)

URL_PATTERN = re.compile(
    r'https?://[^\s<>"\'{}|\^`\[\]\\]+',
    re.IGNORECASE
)

# IPv6 pattern (simplified)
IPV6_PATTERN = re.compile(
    r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|'
    r'\b(?:[0-9a-fA-F]{1,4}:){1,7}:\b|'
    r'\b(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}\b'
)

# Suspicious imports that might indicate malicious behavior
SUSPICIOUS_IMPORTS = {
    # Process manipulation
    'CreateRemoteThread': 'Remote thread injection',
    'VirtualAllocEx': 'Remote memory allocation',
    'WriteProcessMemory': 'Process memory writing',
    'ReadProcessMemory': 'Process memory reading',
    'OpenProcess': 'Process handle access',
    'NtUnmapViewOfSection': 'Process hollowing technique',
    'SetThreadContext': 'Thread context manipulation',
    'QueueUserAPC': 'APC injection',
    
    # Code injection
    'LoadLibraryA': 'Dynamic library loading',
    'LoadLibraryW': 'Dynamic library loading',
    'GetProcAddress': 'Dynamic function resolution',
    'VirtualProtect': 'Memory protection changes',
    'VirtualProtectEx': 'Remote memory protection changes',
    
    # Keylogging/Input capture
    'GetAsyncKeyState': 'Keyboard state monitoring',
    'GetKeyState': 'Key state checking',
    'SetWindowsHookEx': 'System-wide hooks',
    'GetClipboardData': 'Clipboard access',
    
    # Anti-debugging
    'IsDebuggerPresent': 'Debugger detection',
    'CheckRemoteDebuggerPresent': 'Remote debugger detection',
    'NtQueryInformationProcess': 'Process info query (anti-debug)',
    'OutputDebugString': 'Debug string output',
    
    # Network
    'WSAStartup': 'Network initialization',
    'socket': 'Socket creation',
    'connect': 'Network connection',
    'send': 'Network send',
    'recv': 'Network receive',
    'InternetOpenA': 'Internet connection',
    'InternetOpenW': 'Internet connection',
    'InternetOpenUrlA': 'URL connection',
    'InternetOpenUrlW': 'URL connection',
    'HttpOpenRequestA': 'HTTP request',
    'HttpOpenRequestW': 'HTTP request',
    'URLDownloadToFileA': 'File download',
    'URLDownloadToFileW': 'File download',
    
    # File operations
    'CreateFileA': 'File access',
    'CreateFileW': 'File access',
    'DeleteFileA': 'File deletion',
    'DeleteFileW': 'File deletion',
    'MoveFileA': 'File moving',
    'MoveFileW': 'File moving',
    
    # Registry
    'RegOpenKeyExA': 'Registry access',
    'RegOpenKeyExW': 'Registry access',
    'RegSetValueExA': 'Registry modification',
    'RegSetValueExW': 'Registry modification',
    'RegDeleteKeyA': 'Registry deletion',
    'RegDeleteKeyW': 'Registry deletion',
    
    # Service manipulation
    'OpenSCManager': 'Service manager access',
    'CreateService': 'Service creation',
    'StartService': 'Service starting',
    
    # Privilege escalation
    'AdjustTokenPrivileges': 'Privilege adjustment',
    'OpenProcessToken': 'Process token access',
    'LookupPrivilegeValue': 'Privilege lookup',
    
    # Cryptography (could be ransomware)
    'CryptEncrypt': 'Data encryption',
    'CryptDecrypt': 'Data decryption',
    'CryptGenKey': 'Crypto key generation',
    'CryptAcquireContext': 'Crypto context',
}

# Common false positive domains to ignore
IGNORE_DOMAINS = {
    'microsoft.com', 'windows.com', 'windowsupdate.com',
    'google.com', 'googleapis.com', 'gstatic.com',
    'apple.com', 'icloud.com',
    'adobe.com', 'acrobat.com',
    'example.com', 'localhost',
}

# Common false positive IPs to ignore
IGNORE_IPS = {
    '0.0.0.0', '127.0.0.1', '255.255.255.255',
    '192.168.0.0', '192.168.1.1', '10.0.0.1',
}


def extract_strings(file_path: str, min_length: int = 4) -> Tuple[List[str], List[str]]:
    """
    Extract ASCII and Unicode strings from a binary file.
    
    Args:
        file_path: Path to the binary file
        min_length: Minimum string length to extract
    
    Returns:
        Tuple of (ascii_strings, unicode_strings)
    """
    ascii_strings = []
    unicode_strings = []
    
    try:
        with open(file_path, 'rb') as f:
            content = f.read()
        
        # ASCII strings
        ascii_pattern = re.compile(rb'[\x20-\x7E]{' + str(min_length).encode() + rb',}')
        for match in ascii_pattern.finditer(content):
            try:
                ascii_strings.append(match.group().decode('ascii'))
            except:
                pass
        
        # Unicode (UTF-16LE) strings - common in Windows executables
        unicode_pattern = re.compile(
            rb'(?:[\x20-\x7E]\x00){' + str(min_length).encode() + rb',}'
        )
        for match in unicode_pattern.finditer(content):
            try:
                unicode_strings.append(match.group().decode('utf-16-le'))
            except:
                pass
    
    except Exception:
        pass
    
    return ascii_strings, unicode_strings


def extract_network_indicators(strings: List[str]) -> Tuple[Set[str], Set[str], Set[str]]:
    """
    Extract domains, IPs, and URLs from a list of strings.
    
    Returns:
        Tuple of (domains, ips, urls)
    """
    domains = set()
    ips = set()
    urls = set()
    
    for s in strings:
        # URLs
        for match in URL_PATTERN.finditer(s):
            url = match.group()
            urls.add(url)
        
        # IPs
        for match in IP_PATTERN.finditer(s):
            ip = match.group()
            if ip not in IGNORE_IPS and not ip.startswith('0.'):
                ips.add(ip)
        
        # IPv6
        for match in IPV6_PATTERN.finditer(s):
            ips.add(match.group())
        
        # Domains
        for match in DOMAIN_PATTERN.finditer(s):
            domain = match.group().lower()
            # Filter out version strings like "1.2.3.dll" and known safe domains
            if not any(domain.endswith(ext) for ext in ['.dll', '.exe', '.sys', '.ocx']):
                if domain not in IGNORE_DOMAINS and not any(domain.endswith('.' + d) for d in IGNORE_DOMAINS):
                    domains.add(domain)
    
    return domains, ips, urls


def analyze_pe_imports(file_path: str) -> Tuple[List[str], Optional[str]]:
    """
    Analyze PE file imports for suspicious functions.
    
    Returns:
        Tuple of (suspicious_imports_found, error)
    """
    suspicious_found = []
    error = None
    
    if not HAS_PEFILE:
        return suspicious_found, "pefile not installed"
    
    try:
        pe = pefile.PE(file_path, fast_load=True)
        pe.parse_data_directories(
            directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']]
        )
        
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    if imp.name:
                        func_name = imp.name.decode('utf-8', errors='ignore')
                        if func_name in SUSPICIOUS_IMPORTS:
                            desc = SUSPICIOUS_IMPORTS[func_name]
                            suspicious_found.append(f"{func_name}: {desc}")
        
        pe.close()
    
    except pefile.PEFormatError:
        error = "Invalid PE format"
        logger.error(f"Invalid PE format: {file_path}")
    except Exception as e:
        error = str(e)
        logger.error(f"Error analyzing PE imports {file_path}: {e}")
    
    return suspicious_found, error


def analyze_executable(file_path: str) -> Dict[str, Any]:
    """
    Analyze an executable file for network indicators and suspicious imports.
    
    Args:
        file_path: Path to the executable
    
    Returns:
        Dictionary with analysis results
    """
    result = {
        'domains': [],
        'ips': [],
        'urls': [],
        'suspicious_imports': [],
        'error': None,
        'analyzed': False
    }
    
    path = Path(file_path)
    ext = path.suffix.lower()
    
    # Only analyze PE files
    if ext not in {'.exe', '.dll', '.sys', '.scr', '.ocx', '.drv'}:
        return result
    
    result['analyzed'] = True
    
    # Extract strings
    ascii_strings, unicode_strings = extract_strings(file_path)
    all_strings = ascii_strings + unicode_strings
    
    # Extract network indicators
    domains, ips, urls = extract_network_indicators(all_strings)
    result['domains'] = sorted(list(domains))
    result['ips'] = sorted(list(ips))
    result['urls'] = sorted(list(urls))
    
    # Analyze imports
    # Analyze imports
    suspicious_imports, error = analyze_pe_imports(file_path)
    result['suspicious_imports'] = suspicious_imports
    if error:
        result['error'] = error
    
    # Analyze digital signature
    result['signature_info'] = extract_signature_info(file_path)
    
    return result


def extract_signature_info(file_path: str) -> Dict[str, Any]:
    """
    Extract digital signature information using pefile and PowerShell.
    """
    info = {
        'is_signed': False,
        'subject': None,
        'issuer': None,
        'status': None,
        'has_signature_directory': False
    }
    
    # 1. Check if PE has signature directory
    if HAS_PEFILE:
        try:
            pe = pefile.PE(file_path, fast_load=True)
            # Check Security Directory (index 4)
            if hasattr(pe, 'OPTIONAL_HEADER') and hasattr(pe.OPTIONAL_HEADER, 'DATA_DIRECTORY'):
                if len(pe.OPTIONAL_HEADER.DATA_DIRECTORY) > 4:
                    sec_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[4]
                    if sec_dir.VirtualAddress > 0 and sec_dir.Size > 0:
                        info['has_signature_directory'] = True
            pe.close()
        except Exception:
            pass
    
    # 2. If it looks signed (or even if we're not sure), try getting details via PowerShell
    # PowerShell Get-AuthenticodeSignature is robust and validates the chain including catalog signatures
    # We should always check on Windows for executables because catalog signatures (system files) 
    # don't have embedded Security Directory in PE header.
    import sys
    should_check_ps = True
    
    if should_check_ps:
        try:
            import subprocess
            import json
            
            # Helper PowerShell script to get signature details as JSON
            # Use a robust single-line PowerShell command to avoid multi-line parsing issues
            # We explicitly map properties to ensure JSON serialization works even if properties are complex objects
            ps_cmd = (
                f"$sig = Get-AuthenticodeSignature -FilePath '{file_path}'; "
                "$result = @{ "
                "Status = $sig.Status.ToString(); "
                "StatusInt = [int]$sig.Status; "
                "IsOSBinary = $sig.IsOSBinary; "
                "Subject = if ($sig.SignerCertificate) { $sig.SignerCertificate.Subject } else { $null }; "
                "Issuer = if ($sig.SignerCertificate) { $sig.SignerCertificate.Issuer } else { $null }; "
                "Thumbprint = if ($sig.SignerCertificate) { $sig.SignerCertificate.Thumbprint } else { $null }; "
                "NotBefore = if ($sig.SignerCertificate) { $sig.SignerCertificate.GetExpirationDateString() } else { $null }; "
                "NotAfter = if ($sig.SignerCertificate) { $sig.SignerCertificate.GetExpirationDateString() } else { $null } "
                "}; "
                "$result | ConvertTo-Json -Compress"
            )
            
            cmd = ['powershell', '-NoProfile', '-Command', ps_cmd]
            process = subprocess.run(
                cmd, 
                capture_output=True, 
                text=True, 
                creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0
            )
            
            if process.returncode == 0 and process.stdout.strip():
                try:
                    data = json.loads(process.stdout)
                    info['status'] = data.get('Status')
                    
                    # Map PowerShell status to boolean
                    info['is_signed'] = info['status'] == 'Valid'
                    
                    if 'Subject' in data:
                        # Subject often comes as "CN=Name, O=Org, ..."
                        # Let's try to extract just the CN if possible, otherwise keep full
                        info['subject'] = data['Subject']
                        # Parse CN for friendlier display
                        if 'CN=' in info['subject']:
                            import re
                            cn_match = re.search(r'CN=([^,]+)', info['subject'])
                            if cn_match:
                                info['signer_name'] = cn_match.group(1)
                                
                    info['issuer'] = data.get('Issuer')
                    info['thumbprint'] = data.get('Thumbprint')
                    info['valid_from'] = data.get('NotBefore')
                    info['valid_to'] = data.get('NotAfter')
                            
                except json.JSONDecodeError:
                    pass
        except Exception:
            pass
            
    return info


def is_executable(file_path: str) -> bool:
    """Check if a file is a supported executable type."""
    ext = Path(file_path).suffix.lower()
    return ext in {'.exe', '.dll', '.sys', '.scr', '.ocx', '.drv'}


def analyze_files_executables(files: list, progress_callback=None) -> None:
    """
    Analyze executable files and update FileInfo objects in place.
    
    Args:
        files: List of FileInfo objects
        progress_callback: Optional callback(current, total, message)
    """
    exe_files = [f for f in files if is_executable(f.path) and not f.is_directory]
    total = len(exe_files)
    
    for i, file_info in enumerate(exe_files):
        if progress_callback:
            progress_callback(i + 1, total, f"Analyzing {file_info.name}")
        
        result = analyze_executable(file_info.path)
        
        file_info.exe_domains = result['domains']
        file_info.exe_ips = result['ips']
        file_info.exe_urls = result['urls']
        file_info.exe_suspicious_imports = result['suspicious_imports']
        file_info.exe_analysis_error = result['error']
        
        # Populate signature info
        file_info.signature_info = result.get('signature_info', {})
        if file_info.signature_info:
            file_info.is_signed = file_info.signature_info.get('is_signed')
            # Use 'signer_name' if available (clean CN), else full 'subject'
            file_info.sig_subject = file_info.signature_info.get('signer_name') or file_info.signature_info.get('subject')
            file_info.sig_issuer = file_info.signature_info.get('issuer')
