"""
Document analysis module for PDF and Office files.
Uses oletools for macro/script detection.
"""

import os
import re
import logging
import subprocess
from pathlib import Path
from typing import List, Tuple, Optional, Dict, Any

logger = logging.getLogger(__name__)

# Try to import oletools components
try:
    from oletools import oleid
    from oletools.olevba import VBA_Parser, TYPE_OLE, TYPE_OpenXML, TYPE_Word2003_XML, TYPE_MHTML
    HAS_OLEVBA = True
except ImportError:
    HAS_OLEVBA = False

try:
    from pdfid import pdfid
    HAS_PDFID = True
except ImportError:
    HAS_PDFID = False


# Suspicious PDF elements to look for
SUSPICIOUS_PDF_ELEMENTS = {
    '/JavaScript': 'Contains JavaScript',
    '/JS': 'Contains JavaScript reference',
    '/OpenAction': 'Auto-executes on open',
    '/AA': 'Additional actions defined',
    '/Launch': 'Can launch external applications',
    '/EmbeddedFile': 'Contains embedded files',
    '/XFA': 'Contains XML Forms (potential XSS)',
    '/AcroForm': 'Contains interactive form',
    '/JBIG2Decode': 'JBIG2 decoder (historical exploits)',
    '/RichMedia': 'Contains rich media (Flash)',
    '/ObjStm': 'Object streams (can hide content)',
    '/URI': 'Contains external URI references',
}

# Suspicious macro patterns
SUSPICIOUS_VBA_PATTERNS = [
    (r'Auto_?Open', 'Auto-executes on document open'),
    (r'Auto_?Close', 'Auto-executes on document close'),
    (r'Document_?Open', 'Auto-executes on document open'),
    (r'Workbook_?Open', 'Auto-executes on workbook open'),
    (r'Shell\s*\(', 'Can execute shell commands'),
    (r'WScript\.Shell', 'Can execute Windows scripts'),
    (r'PowerShell', 'References PowerShell'),
    (r'CreateObject', 'Creates COM objects'),
    (r'GetObject', 'Gets COM objects'),
    (r'Environ\s*\(', 'Reads environment variables'),
    (r'URLDownloadToFile', 'Downloads files from URLs'),
    (r'MSXML2\.XMLHTTP', 'HTTP requests capability'),
    (r'ADODB\.Stream', 'Binary file operations'),
    (r'Wscript\.Sleep', 'Sleep/delay execution'),
    (r'Chr\s*\(\s*\d+\s*\)', 'Character obfuscation'),
    (r'CallByName', 'Dynamic function calls'),
    (r'\.Run\s*', 'Executes commands'),
]


def analyze_pdf(file_path: str) -> Tuple[bool, bool, List[str], Optional[str]]:
    """
    Analyze a PDF file for suspicious elements.
    
    Args:
        file_path: Path to the PDF file
    
    Returns:
        Tuple of (has_javascript, has_macros, suspicious_elements, error)
    """
    has_javascript = False
    has_macros = False  # PDFs don't have macros in the traditional sense
    suspicious_elements = []
    error = None
    
    try:
        # Read the file and look for suspicious patterns
        with open(file_path, 'rb') as f:
            content = f.read()
        
        # Check for each suspicious element
        for element, description in SUSPICIOUS_PDF_ELEMENTS.items():
            if element.encode() in content:
                suspicious_elements.append(description)
                if 'JavaScript' in description:
                    has_javascript = True
        
        # Try using pdfid if available
        if HAS_PDFID:
            try:
                # pdfid returns a list of tuples (keyword, count)
                result = pdfid.PDFiD(file_path)
                for item in result.keywords:
                    if item.count > 0 and item.name in SUSPICIOUS_PDF_ELEMENTS:
                        desc = SUSPICIOUS_PDF_ELEMENTS[item.name]
                        if desc not in suspicious_elements:
                            suspicious_elements.append(f"{desc} (count: {item.count})")
            except Exception as e:
                # Fall back to our basic analysis
                pass
    
    except PermissionError:
        error = "Permission denied"
        logger.error(f"Permission denied analyzing PDF: {file_path}")
    except Exception as e:
        error = str(e)
        logger.error(f"Error analyzing PDF {file_path}: {e}")
    
    return has_javascript, has_macros, suspicious_elements, error


def analyze_office_document(file_path: str) -> Tuple[bool, bool, List[str], Optional[str]]:
    """
    Analyze an Office document (DOC, DOCX, XLS, XLSX, PPT, PPTX) for macros.
    
    Args:
        file_path: Path to the Office file
    
    Returns:
        Tuple of (has_javascript, has_macros, suspicious_elements, error)
    """
    has_javascript = False
    has_macros = False
    suspicious_elements = []
    error = None
    
    if not HAS_OLEVBA:
        return has_javascript, has_macros, suspicious_elements, "oletools not installed"
    
    try:
        vba_parser = VBA_Parser(file_path)
        
        if vba_parser.detect_vba_macros():
            has_macros = True
            suspicious_elements.append("Contains VBA macros")
            
            # Analyze the macros
            try:
                for (filename, stream_path, vba_filename, vba_code) in vba_parser.extract_macros():
                    # Check for suspicious patterns
                    for pattern, description in SUSPICIOUS_VBA_PATTERNS:
                        if re.search(pattern, vba_code, re.IGNORECASE):
                            if description not in suspicious_elements:
                                suspicious_elements.append(description)
                    
                    # Check for JavaScript in macro
                    if 'javascript' in vba_code.lower():
                        has_javascript = True
            except Exception:
                suspicious_elements.append("Could not fully analyze macro content")
        
        vba_parser.close()
    
    except Exception as e:
        error = str(e)
        logger.error(f"Error analyzing Office document {file_path}: {e}")
    
    return has_javascript, has_macros, suspicious_elements, error


def analyze_document(file_path: str) -> Dict[str, Any]:
    """
    Analyze a document file (PDF or Office) for malicious content.
    
    Args:
        file_path: Path to the document
    
    Returns:
        Dictionary with analysis results
    """
    path = Path(file_path)
    ext = path.suffix.lower()
    
    result = {
        'has_javascript': False,
        'has_macros': False,
        'suspicious_elements': [],
        'error': None,
        'analyzed': False
    }
    
    # PDF files
    if ext == '.pdf':
        js, macros, elements, error = analyze_pdf(file_path)
        result['has_javascript'] = js
        result['has_macros'] = macros
        result['suspicious_elements'] = elements
        result['error'] = error
        result['analyzed'] = True
    
    # Office documents
    elif ext in {'.doc', '.docx', '.docm', '.xls', '.xlsx', '.xlsm', '.ppt', '.pptx', '.pptm'}:
        js, macros, elements, error = analyze_office_document(file_path)
        result['has_javascript'] = js
        result['has_macros'] = macros
        result['suspicious_elements'] = elements
        result['error'] = error
        result['analyzed'] = True
    
    # RTF files (can contain OLE objects)
    elif ext == '.rtf':
        js, macros, elements, error = analyze_office_document(file_path)
        result['has_javascript'] = js
        result['has_macros'] = macros
        result['suspicious_elements'] = elements
        result['error'] = error
        result['analyzed'] = True
    
    return result


def is_document(file_path: str) -> bool:
    """Check if a file is a supported document type."""
    ext = Path(file_path).suffix.lower()
    return ext in {
        '.pdf', 
        '.doc', '.docx', '.docm',
        '.xls', '.xlsx', '.xlsm',
        '.ppt', '.pptx', '.pptm',
        '.rtf'
    }


def analyze_files_documents(files: list, progress_callback=None) -> None:
    """
    Analyze document files and update FileInfo objects in place.
    
    Args:
        files: List of FileInfo objects
        progress_callback: Optional callback(current, total, message)
    """
    doc_files = [f for f in files if is_document(f.path) and not f.is_directory]
    total = len(doc_files)
    
    for i, file_info in enumerate(doc_files):
        if progress_callback:
            progress_callback(i + 1, total, f"Analyzing {file_info.name}")
        
        result = analyze_document(file_info.path)
        
        file_info.doc_has_javascript = result['has_javascript']
        file_info.doc_has_macros = result['has_macros']
        file_info.doc_suspicious_elements = result['suspicious_elements']
        file_info.doc_analysis_error = result['error']
