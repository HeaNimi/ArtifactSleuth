"""
Windows Defender integration module.
Scans files using Windows Defender (MpCmdRun.exe) to detect malware.
"""

import os
import subprocess
import logging
from pathlib import Path
from typing import Optional, Dict, Any, Callable, List
import re


# Common paths where Windows Defender's MpCmdRun.exe is installed
MPCMDRUN_PATHS = [
    r"C:\Program Files\Windows Defender\MpCmdRun.exe",
    r"C:\ProgramData\Microsoft\Windows Defender\Platform\*\MpCmdRun.exe",
]


def find_mpcmdrun() -> Optional[str]:
    """
    Find the Windows Defender command-line tool (MpCmdRun.exe).
    
    Returns:
        Path to MpCmdRun.exe if found, None otherwise.
    """
    import glob
    
    for path_pattern in MPCMDRUN_PATHS:
        if '*' in path_pattern:
            # Glob pattern - find the most recent version
            matches = glob.glob(path_pattern)
            if matches:
                # Sort to get the latest version (usually highest version number)
                matches.sort(reverse=True)
                if os.path.exists(matches[0]):
                    return matches[0]
        else:
            if os.path.exists(path_pattern):
                return path_pattern
    
    return None


def is_defender_available() -> bool:
    """Check if Windows Defender is available on this system."""
    return find_mpcmdrun() is not None


def scan_file_with_defender(file_path: str, timeout: int = 60) -> Dict[str, Any]:
    """
    Scan a single file with Windows Defender.
    
    Args:
        file_path: Full path to the file to scan
        timeout: Maximum time to wait for scan (seconds)
    
    Returns:
        Dictionary with scan results:
        - scanned: bool - Whether scan was performed
        - detected: bool - Whether threat was detected
        - threat_name: str - Name of detected threat (if any)
        - error: str - Error message (if any)
    """
    result = {
        'scanned': False,
        'detected': False,
        'threat_name': None,
        'error': None,
    }
    
    mpcmdrun = find_mpcmdrun()
    if not mpcmdrun:
        result['error'] = "Windows Defender not found"
        return result
    
    if not os.path.exists(file_path):
        result['error'] = f"File not found: {file_path}"
        return result
    
    try:
        # MpCmdRun.exe -Scan -ScanType 3 -File "path"
        # ScanType 3 = Custom scan (single file)
        # Returns exit code 0 for clean, 2 for threat found
        cmd = [
            mpcmdrun,
            '-Scan',
            '-ScanType', '3',
            '-File', str(file_path),
            '-DisableRemediation'  # Don't quarantine, just detect
        ]
        
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0
        )
        
        result['scanned'] = True
        
        # Exit codes:
        # 0 = No threats found
        # 2 = Threat found
        if proc.returncode == 2:
            result['detected'] = True
            # Try to parse threat name from output
            # Output format varies but often contains "Threat" or the threat name
            output = proc.stdout + proc.stderr
            threat_match = re.search(r'Threat\s*:\s*(.+?)(?:\r?\n|$)', output, re.IGNORECASE)
            if threat_match:
                result['threat_name'] = threat_match.group(1).strip()
            else:
                # Try another pattern
                threat_match = re.search(r'found\s+(\S+)', output, re.IGNORECASE)
                if threat_match:
                    result['threat_name'] = threat_match.group(1).strip()
                else:
                    result['threat_name'] = "Threat detected"
        elif proc.returncode != 0:
            # Some other error
            result['error'] = f"Scan returned code {proc.returncode}"
            
    except subprocess.TimeoutExpired:
        result['error'] = f"Scan timed out after {timeout}s"
    except FileNotFoundError:
        result['error'] = "MpCmdRun.exe not found"
    except Exception as e:
        result['error'] = str(e)
    
    return result


def scan_files_with_defender(
    file_infos: List,
    progress_callback: Optional[Callable[[int, int, str], None]] = None,
    timeout_per_file: int = 30
) -> Dict[str, int]:
    """
    Scan multiple files with Windows Defender.
    Updates FileInfo objects in place with defender results.
    
    Args:
        file_infos: List of FileInfo objects to scan
        progress_callback: Optional callback(current, total, message)
        timeout_per_file: Timeout per file scan in seconds
    
    Returns:
        Dictionary with scan statistics
    """
    logger = logging.getLogger(__name__)
    
    stats = {
        'total_scanned': 0,
        'detected': 0,
        'errors': 0,
        'skipped': 0,
    }
    
    # Check if Defender is available
    if not is_defender_available():
        logger.warning("Windows Defender not available - skipping scan")
        stats['errors'] = len(file_infos)
        for fi in file_infos:
            fi.defender_error = "Windows Defender not available"
        return stats
    
    total = len(file_infos)
    
    for i, file_info in enumerate(file_infos):
        # Get actual path for scanning (handle virtual paths for extracted files)
        scan_path = file_info.path
        
        # Skip if path doesn't exist (might be virtual path for extracted file)
        if not os.path.exists(scan_path):
            # Try archive extracted files - they won't have physical path anymore
            stats['skipped'] += 1
            file_info.defender_scanned = False
            file_info.defender_error = "File not accessible for scan"
            if progress_callback:
                progress_callback(i + 1, total, f"Skipped: {file_info.name}")
            continue
        
        if progress_callback:
            progress_callback(i + 1, total, file_info.name)
        
        result = scan_file_with_defender(scan_path, timeout=timeout_per_file)
        
        file_info.defender_scanned = result['scanned']
        file_info.defender_detected = result['detected']
        file_info.defender_threat_name = result['threat_name']
        file_info.defender_error = result['error']
        
        if result['scanned']:
            stats['total_scanned'] += 1
            if result['detected']:
                stats['detected'] += 1
                logger.info(f"Defender detected threat in {file_info.name}: {result['threat_name']}")
        else:
            if result['error']:
                stats['errors'] += 1
                logger.debug(f"Defender scan error for {file_info.name}: {result['error']}")
    
    return stats


def scan_file_inline(file_path: str, file_info, timeout: int = 30) -> None:
    """
    Scan a single file inline and update FileInfo object.
    Used during archive extraction when files are temporarily available.
    
    Args:
        file_path: Actual filesystem path to scan
        file_info: FileInfo object to update
        timeout: Scan timeout in seconds
    """
    result = scan_file_with_defender(file_path, timeout=timeout)
    
    file_info.defender_scanned = result['scanned']
    file_info.defender_detected = result['detected']
    file_info.defender_threat_name = result['threat_name']
    file_info.defender_error = result['error']
