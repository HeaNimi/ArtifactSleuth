# ArtifactSleuth - Code Flow Documentation

This document explains the internal code flow, file detection mechanisms, fallback methods, and architecture of the USB Forensic File Analyzer.

## Table of Contents

1. [High-Level Architecture](#high-level-architecture)
2. [Execution Flow](#execution-flow)
3. [File Detection Mechanisms](#file-detection-mechanisms)
4. [Archive Handling & Fallbacks](#archive-handling--fallbacks)
5. [File Hashing Strategies](#file-hashing-strategies)
6. [Analysis Modules](#analysis-modules)
7. [Risk Scoring](#risk-scoring)
8. [Report Generation](#report-generation)

---

## High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                           main.py                                    │
│                     (CLI Entry Point)                                │
└─────────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────────┐
│                         scanner.py                                   │
│              (FileScanner - Core Orchestrator)                       │
│                                                                      │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────────┐  │
│  │  Phase 1:    │  │  Phase 2:    │  │  Inline Analysis:        │  │
│  │  Shallow     │─▶│  Archive     │─▶│  - PE Analysis           │  │
│  │  Scan        │  │  Processing  │  │  - Document Analysis     │  │
│  └──────────────┘  └──────────────┘  └──────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
         │                   │                      │
         ▼                   ▼                      ▼
┌────────────────┐  ┌────────────────┐  ┌────────────────────────────┐
│  metadata.py   │  │ archive_       │  │ executable_analyzer.py     │
│  (FileInfo)    │  │ handler.py     │  │ document_analyzer.py       │
└────────────────┘  └────────────────┘  └────────────────────────────┘
         │                   │
         ▼                   ▼
┌────────────────┐  ┌────────────────┐
│  hasher.py     │  │ virustotal.py  │
│  (HashCache)   │  │ (API Lookups)  │
└────────────────┘  └────────────────┘
                          │
                          ▼
              ┌────────────────────────┐
              │  report_generator.py   │
              │  (HTML/CSV Output)     │
              └────────────────────────┘
```

---

## Execution Flow

### Phase 1: Initialization (`main.py`)

```
1. Parse command line arguments
2. Setup logging (optional --log flag)
3. Parse --exclude-archives into a set of extensions
4. Initialize FileScanner with configuration:
   - hash_files: bool
   - max_archive_depth: int (default: 5)
   - batch_small_files: bool (default: True)
   - exclude_archive_types: set (e.g., {'.apk', '.jar'})
```

### Phase 2: Shallow Scan (`scanner.py`)

The scanner uses a **shallow-first strategy** for optimal performance:

```
┌─────────────────────────────────────────────────┐
│           Shallow Scan (Fast)                   │
├─────────────────────────────────────────────────┤
│ 1. Walk directory tree with ThreadPoolExecutor  │
│    (8 workers)                                  │
│ 2. For each file:                               │
│    a. Extract metadata (get_file_metadata)      │
│    b. Compute hashes (if enabled)               │
│    c. If archive AND not excluded → queue       │
│ 3. Batch small files for efficient hashing      │
└─────────────────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────┐
│           Archive Processing (Deep)             │
├─────────────────────────────────────────────────┤
│ 1. Process archive queue with 4 workers         │
│ 2. For each archive:                            │
│    a. Check if extension is excluded → skip     │
│    b. Create temp directory                     │
│    c. Extract contents                          │
│    d. Scan extracted files                      │
│    e. Analyze PE/documents INLINE               │
│    f. Queue nested archives (if not excluded)   │
│    g. Cleanup temp directory                    │
└─────────────────────────────────────────────────┘
```

### Phase 3: Analysis (`main.py`)

```
┌─────────────────────────────────────────────┐
│ Document Analysis (Phase 2 in main.py)      │
│ - Only for files on disk (archive_path=None)│
│ - Uses oletools for Office macros           │
│ - Pattern matching for PDF analysis         │
└─────────────────────────────────────────────┘
                    │
                    ▼
┌─────────────────────────────────────────────┐
│ Executable Analysis (Phase 3 in main.py)    │
│ - Only for files on disk (archive_path=None)│
│ - Uses pefile for PE analysis               │
│ - String extraction for IOCs                │
└─────────────────────────────────────────────┘
                    │
                    ▼
┌─────────────────────────────────────────────┐
│ VirusTotal Lookups (Phase 4 in main.py)     │
│ - Optional, requires API key                │
│ - Rate-limited (4/min free, 500/min premium)│
└─────────────────────────────────────────────┘
```

### Phase 4: Report Generation

```
┌─────────────────────────────────────────────┐
│ Risk Score Calculation                      │
│ - Combines all analysis results             │
│ - Score 0-100 with reasons                  │
└─────────────────────────────────────────────┘
                    │
                    ▼
┌─────────────────────────────────────────────┐
│ Report Output                               │
│ - HTML: Interactive with search/pagination  │
│ - CSV: Flat export for spreadsheets         │
│ - Split reports: --split-report N           │
└─────────────────────────────────────────────┘
```

---

## File Detection Mechanisms

### 1. Extension-Based Detection (Fast Path)

```python
# archive_handler.py - is_archive()
archive_extensions = {
    '.zip', '.7z', '.rar', '.tar', '.gz', '.bz2', 
    '.xz', '.tgz', '.apk', '.jar'
}

# Compound extensions
compound_extensions = {'.tar.gz', '.tar.bz2', '.tar.xz'}
```

### 2. Magic Byte Detection (Verification)

When extension is ambiguous or missing, magic bytes are read from file headers:

```python
# archive_handler.py - MAGIC_SIGNATURES
MAGIC_SIGNATURES = {
    b'PK\x03\x04':      'zip',     # ZIP/APK/JAR (offset 0)
    b'PK\x05\x06':      'zip',     # Empty ZIP
    b'PK\x07\x08':      'zip',     # Spanned ZIP
    b'Rar!\x1a\x07':    'rar',     # RAR
    b"7z\xbc\xaf'\x1c": '7z',      # 7-Zip
    b'\x1f\x8b':        'gzip',    # GZIP
    b'BZh':             'bzip2',   # BZIP2
    b'\xfd7zXZ\x00':    'xz',      # XZ
}

# TAR has magic at offset 257
tar_magic = b'ustar'  # at offset 257
```

### 3. MIME Type Detection (python-magic)

```python
# metadata.py - uses libmagic
if HAS_MAGIC:
    mime_type = magic.from_file(file_path, mime=True)
    file_type = magic.from_file(file_path)
```

### 4. Extension Mismatch Detection

Compares MIME type against expected extensions:

```python
# metadata.py - MIME_TO_EXTENSIONS
MIME_TO_EXTENSIONS = {
    'application/pdf': ['.pdf'],
    'application/x-dosexec': ['.exe', '.dll', '.sys', '.scr'],
    'application/zip': ['.zip', '.docx', '.xlsx', '.pptx', '.jar', '.apk'],
    # ... more mappings
}

# Detection logic
def check_extension_mismatch(file_path, mime_type):
    actual_extension = Path(file_path).suffix.lower()
    expected = MIME_TO_EXTENSIONS.get(mime_type)
    if expected and actual_extension not in expected:
        return True, expected
    return False, None
```

### 5. File Type Detection Hierarchy

```
┌────────────────────────────────────────────────────────┐
│                  Detection Priority                     │
├────────────────────────────────────────────────────────┤
│ 1. Magic bytes (most reliable)                         │
│    └─ Read first 16 bytes + offset 257 for TAR         │
│                                                         │
│ 2. Extension (fast, but can be spoofed)                │
│    └─ Check single + compound extensions               │
│                                                         │
│ 3. MIME type via python-magic                          │
│    └─ Uses libmagic database                           │
│                                                         │
│ 4. Fallback to extension if magic unavailable          │
└────────────────────────────────────────────────────────┘
```

---

## Archive Handling & Fallbacks

### Archive Exclusion

The `--exclude-archives` option allows skipping extraction of specific archive types:

```bash
# Skip APK and JAR files (useful for Android forensics where you don't need internals)
python main.py /path --exclude-archives .apk,.jar

# Skip all compressed tarballs
python main.py /path --exclude-archives .tar.gz,.tar.bz2,.tar.xz,.tgz
```

**How it works:**

```python
# scanner.py - _should_exclude_archive()

def _should_exclude_archive(self, file_path: str) -> bool:
    """Check if archive should be skipped based on extension."""
    if not self.exclude_archive_types:
        return False
    
    path = Path(file_path)
    suffix = path.suffix.lower()
    
    # Check single extension (.apk, .jar, .zip)
    if suffix in self.exclude_archive_types:
        return True
    
    # Check compound extensions (.tar.gz, .tar.bz2)
    if len(path.suffixes) >= 2:
        compound = ''.join(path.suffixes[-2:]).lower()
        if compound in self.exclude_archive_types:
            return True
    
    return False
```

**Exclusion checkpoints:**

```
┌─────────────────────────────────────────────────────────┐
│          Archive Exclusion Check Points                  │
├─────────────────────────────────────────────────────────┤
│ 1. _scan_file_shallow() - Before queuing to archive Q   │
│ 2. _scan_file() - Before calling _scan_archive()        │
│ 3. _extract_and_scan_archive() - Nested archives        │
│ 4. _scan_directory_iter() - Generator-based scan        │
│ 5. _process_archive_queue_iter() - Generator archives   │
└─────────────────────────────────────────────────────────┘
```

**Note:** Excluded archives are still scanned as regular files (metadata, hashes), they're just not extracted.

### Archive Type Selection

```python
# archive_handler.py - get_archive_type()

def get_archive_type(file_path):
    # Step 1: Check compound extensions first
    if file_path.endswith('.tar.gz'):
        magic_type = detect_archive_by_magic(file_path)
        if magic_type in {'gzip', 'bzip2', 'xz'}:
            return 'tar'
        elif magic_type:  # Different type detected
            logger.warning(f"File mislabeled, actually {magic_type}")
            return magic_type  # Use detected type
        return 'tar'  # Fall back to extension
    
    # Step 2: Check single extensions
    extension_type = type_map.get(suffix)
    
    # Step 3: Verify with magic bytes
    magic_type = detect_archive_by_magic(file_path)
    if magic_type and magic_type != extension_type:
        logger.warning(f"Extension mismatch detected")
        return magic_type  # Trust magic bytes
    
    return extension_type
```

### Extraction Fallback Chain

#### ZIP Extraction

```
┌─────────────────────────────────────────────────────┐
│                  extract_zip()                       │
├─────────────────────────────────────────────────────┤
│ 1. Open with zipfile.ZipFile                        │
│ 2. Check encryption flag (flag_bits & 0x1)          │
│ 3. Extract each file individually                   │
│ 4. Handle RuntimeError for password-protected       │
│                                                     │
│ Fallback:                                           │
│ └─ Return ([], True) if password protected          │
│ └─ Raise ArchiveError if corrupted                  │
└─────────────────────────────────────────────────────┘
```

#### 7z Extraction

```
┌─────────────────────────────────────────────────────┐
│                  extract_7z()                        │
├─────────────────────────────────────────────────────┤
│ Requires: py7zr library                             │
│                                                     │
│ 1. Check HAS_7Z flag                                │
│ 2. Open with py7zr.SevenZipFile                     │
│ 3. Check needs_password()                           │
│ 4. extractall() to temp directory                   │
│ 5. Walk directory to collect file list              │
│                                                     │
│ Fallback:                                           │
│ └─ Raise ArchiveError if py7zr not installed        │
│ └─ Return ([], True) if password protected          │
└─────────────────────────────────────────────────────┘
```

#### RAR Extraction

```
┌─────────────────────────────────────────────────────┐
│                  extract_rar()                       │
├─────────────────────────────────────────────────────┤
│ Requires: rarfile library + UnRAR tool              │
│                                                     │
│ 1. Check HAS_RAR (library installed)                │
│ 2. Check HAS_RAR_TOOL (UnRAR available)             │
│    - Searches common paths:                         │
│      • C:\Program Files\WinRAR\UnRAR.exe            │
│      • C:\Program Files (x86)\WinRAR\UnRAR.exe      │
│      • ./bin/UnRAR.exe                              │
│ 3. Open with rarfile.RarFile                        │
│ 4. Check needs_password()                           │
│ 5. extractall() to temp directory                   │
│                                                     │
│ Fallback:                                           │
│ └─ Raise ArchiveError with install instructions     │
│ └─ Return ([], True) if password protected          │
└─────────────────────────────────────────────────────┘
```

#### TAR Extraction (Most Complex)

```
┌─────────────────────────────────────────────────────────────────┐
│                      extract_tar()                               │
├─────────────────────────────────────────────────────────────────┤
│ Step 1: Verify with magic bytes                                 │
│         └─ If magic shows different type → raise ArchiveError   │
│                                                                 │
│ Step 2: Determine compression mode from magic                   │
│         magic_type == 'gzip'  → modes = ['r:gz', 'r:*']        │
│         magic_type == 'bzip2' → modes = ['r:bz2', 'r:*']       │
│         magic_type == 'xz'    → modes = ['r:xz', 'r:*']        │
│         magic_type == 'tar'   → modes = ['r', 'r:*']           │
│                                                                 │
│ Step 3: Try each mode in order until success                    │
│         for mode in modes_to_try:                               │
│             try:                                                │
│                 tf = tarfile.open(archive_path, mode)           │
│                 break                                           │
│             except (TarError, EOFError):                        │
│                 continue                                        │
│                                                                 │
│ Step 4: Stream extraction with safety limits                    │
│         - max_files = 500,000                                   │
│         - skip files > 4GB                                      │
│         - skip paths with '..' or starting with '/'             │
│                                                                 │
│ Fallback Error Messages:                                        │
│ └─ "File does not appear to be a valid archive"                 │
│ └─ "No recognized archive magic bytes found"                    │
└─────────────────────────────────────────────────────────────────┘
```

### Archive Extraction Router

```python
# archive_handler.py - extract_archive()

def extract_archive(archive_path, extract_to):
    archive_type = get_archive_type(archive_path)
    magic_type = detect_archive_by_magic(archive_path)
    
    # Trust magic bytes over extension
    if magic_type and magic_type != archive_type:
        if magic_type in {'zip', '7z', 'rar'}:
            archive_type = magic_type
    
    # Route to appropriate extractor
    if archive_type == 'zip':
        return extract_zip(...)
    elif archive_type == '7z':
        return extract_7z(...)
    elif archive_type == 'rar':
        return extract_rar(...)
    elif archive_type == 'tar':
        return extract_tar(...)
    elif archive_type == 'gzip':
        try:
            return extract_tar(...)  # Try tar.gz first
        except ArchiveError:
            return extract_gzip(...)  # Fall back to standalone gzip
    elif archive_type in {'bzip2', 'xz'}:
        try:
            return extract_tar(...)  # Try tar.bz2/tar.xz first
        except ArchiveError:
            raise  # No standalone handler yet
```

---

## File Hashing Strategies

### Hashing Threshold Selection

```
┌────────────────────────────────────────────────────────┐
│              File Size Thresholds                       │
├────────────────────────────────────────────────────────┤
│ SMALL_FILE_THRESHOLD = 4 KB                            │
│ └─ Files ≤ 4KB → Batch hashing (read entire file)      │
│                                                         │
│ MMAP_THRESHOLD = 10 MB                                 │
│ └─ Files ≥ 10MB → Memory-mapped hashing                │
│                                                         │
│ Between 4KB and 10MB → Streaming (64KB chunks)         │
└────────────────────────────────────────────────────────┘
```

### Hashing Methods

```python
# hasher.py

# 1. Small File Batching (≤4KB)
def hash_small_file(file_path):
    with open(file_path, 'rb') as f:
        data = f.read()  # Read entire file
    return (
        hashlib.md5(data).hexdigest(),
        hashlib.sha1(data).hexdigest(),
        hashlib.sha256(data).hexdigest()
    )

# 2. Memory-Mapped Hashing (≥10MB)
def _hash_file_mmap(file_path, file_size):
    with open(file_path, 'rb') as f:
        with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
            for offset in range(0, file_size, CHUNK_SIZE):
                chunk = mm[offset:offset + CHUNK_SIZE]
                md5_hash.update(chunk)
                sha1_hash.update(chunk)
                sha256_hash.update(chunk)

# 3. Streaming Hashing (4KB-10MB)
def _hash_file_streaming(file_path, chunk_size):
    with open(file_path, 'rb') as f:
        while chunk := f.read(chunk_size):
            md5_hash.update(chunk)
            sha1_hash.update(chunk)
            sha256_hash.update(chunk)
```

### HashCache Batch Processing

```
┌─────────────────────────────────────────────────────────┐
│                   HashCache                              │
├─────────────────────────────────────────────────────────┤
│ Purpose: Cache hashes + batch small files               │
│                                                         │
│ queue_small_file(path)                                  │
│ └─ Add to pending queue if ≤ SMALL_FILE_THRESHOLD       │
│                                                         │
│ flush_batch()                                           │
│ └─ Process all pending files with ThreadPoolExecutor    │
│ └─ Uses 8 workers for parallel hashing                  │
│                                                         │
│ get_or_compute(path)                                    │
│ └─ Check cache first                                    │
│ └─ Compute and cache if not found                       │
└─────────────────────────────────────────────────────────┘
```

---

## Analysis Modules

### Executable Analysis (`executable_analyzer.py`)

```
┌─────────────────────────────────────────────────────────┐
│              analyze_executable()                        │
├─────────────────────────────────────────────────────────┤
│ 1. Extract Strings                                      │
│    - ASCII: regex [\x20-\x7E]{4,}                       │
│    - Unicode: UTF-16LE pattern                          │
│                                                         │
│ 2. Extract Network Indicators                           │
│    - IPs: IPv4 pattern with false positive filtering    │
│    - Domains: TLD-aware pattern                         │
│    - URLs: http/https pattern                           │
│                                                         │
│ 3. PE Import Analysis (requires pefile)                 │
│    - Parse IMAGE_DIRECTORY_ENTRY_IMPORT                 │
│    - Match against SUSPICIOUS_IMPORTS dict              │
│    - ~50 suspicious functions tracked:                  │
│      • Process injection (CreateRemoteThread, etc.)     │
│      • Keylogging (GetAsyncKeyState, etc.)              │
│      • Anti-debugging (IsDebuggerPresent, etc.)         │
│      • Network (WSAStartup, InternetOpen, etc.)         │
│      • Crypto (CryptEncrypt, etc.)                      │
│                                                         │
│ 4. Signature Verification (Windows only, pywin32)       │
│    - Check Authenticode signature                       │
│    - Extract signer subject/issuer                      │
└─────────────────────────────────────────────────────────┘
```

### Document Analysis (`document_analyzer.py`)

```
┌─────────────────────────────────────────────────────────┐
│              analyze_document()                          │
├─────────────────────────────────────────────────────────┤
│ PDF Analysis:                                           │
│ ├─ Pattern matching for suspicious elements:            │
│ │   /JavaScript, /JS, /OpenAction, /AA, /Launch,        │
│ │   /EmbeddedFile, /XFA, /AcroForm, /JBIG2Decode,       │
│ │   /RichMedia, /ObjStm, /URI                           │
│ │                                                       │
│ └─ Optional: pdfid library for deeper analysis          │
│                                                         │
│ Office Analysis (requires oletools):                    │
│ ├─ VBA_Parser for macro detection                       │
│ │                                                       │
│ └─ Pattern matching for suspicious macros:              │
│     Auto_Open, Document_Open, Shell(), WScript.Shell,   │
│     PowerShell, CreateObject, URLDownloadToFile,        │
│     ADODB.Stream, CallByName, .Run                      │
└─────────────────────────────────────────────────────────┘
```

### Inline Analysis for Extracted Files

Files extracted from archives are analyzed **immediately** before the temp directory is deleted:

```python
# scanner.py - _analyze_file_inline()

def _analyze_file_inline(self, file_info):
    """Called within temp_extract_dir context"""
    
    if is_executable(file_info.path):
        result = analyze_executable(file_info.path)
        file_info.exe_domains = result['domains']
        file_info.exe_ips = result['ips']
        # ... populate all fields
    
    elif is_document(file_info.path):
        result = analyze_document(file_info.path)
        file_info.doc_has_macros = result['has_macros']
        # ... populate all fields
```

---

## Risk Scoring

### Score Calculation (`metadata.py`)

```python
def calculate_risk_score(file_info):
    score = 0
    reasons = []
    
    # VirusTotal detection: +50
    if file_info.vt_detected:
        score += 50
        reasons.append(f"VirusTotal: {file_info.vt_detection_ratio}")
    
    # Extension mismatch: +15
    if file_info.extension_mismatch:
        score += 15
        reasons.append("Extension mismatch (possible spoofing)")
    
    # Macros in documents: +20
    if file_info.doc_has_macros:
        score += 20
        reasons.append("Contains macros")
    
    # JavaScript in documents: +25
    if file_info.doc_has_javascript:
        score += 25
        reasons.append("Contains JavaScript")
    
    # Suspicious document elements: +10 each
    for elem in file_info.doc_suspicious_elements:
        score += 10
        reasons.append(f"Suspicious: {elem}")
    
    # Suspicious PE imports: +5 each
    score += 5 * len(file_info.exe_suspicious_imports)
    
    # Network indicators in PE: +5
    if file_info.exe_domains or file_info.exe_ips:
        score += 5
    
    # Executable file types: +5
    if ext in {'.exe', '.dll', '.scr', '.bat', '.ps1', '.vbs', '.js'}:
        score += 5
    
    # Android specific
    if name == 'classes.dex':
        score += 10
    
    file_info.risk_score = min(score, 100)
    file_info.risk_reasons = reasons
```

### Risk Level Classification

```
┌────────────────────────────────────────┐
│ Score 0-29:   🟢 Low Risk             │
│ Score 30-59:  🟡 Medium Risk          │
│ Score 60-100: 🔴 High Risk            │
└────────────────────────────────────────┘
```

---

## Report Generation

### HTML Report Features

- **Client-side pagination** (configurable page size)
- **Debounced search** (200ms delay)
- **Dark/Light theme** toggle
- **SHA256 copy** button
- **Sortable columns**
- **Risk badge** color coding
- **Split reports** (`--split-report N` for large datasets)

### Data Flow for Large Reports

```
┌─────────────────────────────────────────────────────────┐
│           Large Dataset Optimization                     │
├─────────────────────────────────────────────────────────┤
│ 1. Files serialized to JSON (embedded in HTML)          │
│    const filesData = {{ files_json|safe }};             │
│                                                         │
│ 2. Client-side rendering of visible page only           │
│    function renderPage(pageNum) {                       │
│        const start = pageNum * pageSize;                │
│        const pageFiles = filteredFiles.slice(           │
│            start, start + pageSize);                    │
│        // Render only this page                         │
│    }                                                    │
│                                                         │
│ 3. Split reports for 100k+ files                        │
│    --split-report 50000  # 50k files per report         │
│    └─ report_1.html, report_2.html, ...                 │
└─────────────────────────────────────────────────────────┘
```

### Split Report Implementation

```
┌─────────────────────────────────────────────────────────┐
│           --split-report N Flow                          │
├─────────────────────────────────────────────────────────┤
│ generate_report()                                       │
│    │                                                    │
│    ├─ if split_threshold > 0 AND files > threshold:    │
│    │     └─ generate_split_html_reports()              │
│    │           │                                        │
│    │           ├─ Calculate total_parts                 │
│    │           │    = ceil(file_count / N)              │
│    │           │                                        │
│    │           └─ For each part:                        │
│    │                 ├─ Slice files[start:end]          │
│    │                 ├─ Generate report_{n}.html        │
│    │                 └─ Inject part_number, total_parts │
│    │                                                    │
│    └─ else: generate single HTML report                 │
└─────────────────────────────────────────────────────────┘

Output Naming:
  --output report.html --split-report 50000
  └─ report_1.html (files 1-50,000)
  └─ report_2.html (files 50,001-100,000)
  └─ report_3.html (files 100,001+)

Each Part Contains:
  ├─ summary['is_split_report'] = True
  ├─ summary['part_number'] = N (0-indexed)
  ├─ summary['total_parts'] = total count
  ├─ Header shows "Part X of Y"
  └─ Navigation links to other parts
```

---

## Module Dependencies

```
┌─────────────────────────────────────────────────────────┐
│                 Required Dependencies                    │
├─────────────────────────────────────────────────────────┤
│ Core:                                                   │
│ ├─ tqdm (progress bars)                                 │
│ └─ jinja2 (HTML templating)                             │
│                                                         │
│ Optional (graceful degradation if missing):             │
│ ├─ python-magic → MIME type detection disabled          │
│ ├─ pefile → PE import analysis disabled                 │
│ ├─ oletools → Office macro detection disabled           │
│ ├─ py7zr → 7z extraction disabled                       │
│ ├─ rarfile → RAR extraction disabled                    │
│ └─ pywin32 → Windows metadata/signatures disabled       │
│                                                         │
│ External Tools:                                         │
│ └─ UnRAR.exe → Required for RAR extraction              │
└─────────────────────────────────────────────────────────┘
```

---

## Error Handling Patterns

### Graceful Degradation

```python
# Pattern used throughout codebase
try:
    import optional_library
    HAS_FEATURE = True
except ImportError:
    HAS_FEATURE = False

def feature_function():
    if not HAS_FEATURE:
        return default_value  # or raise descriptive error
    # ... proceed with feature
```

### Archive Error Messages

```
┌─────────────────────────────────────────────────────────┐
│              Clear Error Messages                        │
├─────────────────────────────────────────────────────────┤
│ "File does not appear to be a valid archive.            │
│  No recognized archive magic bytes found.               │
│  The file may be corrupted, empty, or not an archive."  │
│                                                         │
│ "RAR extraction requires UnRAR tool.                    │
│  Install WinRAR or download from rarlab.com"            │
│                                                         │
│ "File has TAR-like extension but is actually ZIP.       │
│  Magic bytes indicate: zip"                             │
└─────────────────────────────────────────────────────────┘
```

---

## Threading Model

```
┌─────────────────────────────────────────────────────────┐
│              Concurrency Architecture                    │
├─────────────────────────────────────────────────────────┤
│ Phase 1 (Shallow Scan):                                 │
│ └─ ThreadPoolExecutor(max_workers=8)                    │
│    └─ Directory walking + metadata extraction           │
│                                                         │
│ Phase 2 (Archive Processing):                           │
│ └─ ThreadPoolExecutor(max_workers=4)                    │
│    └─ Parallel archive extraction                       │
│    └─ Nested archives processed recursively             │
│                                                         │
│ Hashing:                                                │
│ └─ ThreadPoolExecutor(max_workers=8)                    │
│    └─ Batch processing of small files                   │
│                                                         │
│ Thread Safety:                                          │
│ └─ threading.Lock() protects:                           │
│    └─ self.files list                                   │
│    └─ self.errors list                                  │
│    └─ self.password_protected_archives list             │
└─────────────────────────────────────────────────────────┘
```
