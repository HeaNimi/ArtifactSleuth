# ArtifactSleuth ECS v9.2.0 Normalization Implementation Plan

**Document Version:** 1.0  
**ECS Version:** 9.2.0  
**Date:** 2026-01-26  
**Status:** Planning Phase

---

## Executive Summary

This document provides a comprehensive engineering plan to adopt Elastic Common Schema (ECS) v9.2.0 normalization in ArtifactSleuth. The goal is to transform the current internal artifact data model to align with ECS field semantics while maintaining backward compatibility and forensic tool-specific capabilities through a custom `artifactsleuth.*` namespace.

The plan prioritizes:
- **Interoperability** with SIEM systems (Elastic, Splunk, etc.)
- **Maintainability** through adherence to ECS field semantics
- **Forensic fidelity** by preserving tool-specific intelligence
- **Backward compatibility** for existing users

---

## 1. Current State Assessment

### 1.1 Current Internal Artifact Fields

The core data model is defined in `analyzer/metadata.py` as the `FileInfo` dataclass with 70+ fields:

**Core File Metadata (14 fields)**
```python
- path: str                      # Full filesystem path
- name: str                      # Filename
- relative_path: str             # Path relative to scan root
- size: int                      # Size in bytes
- created_time: datetime         # Creation timestamp
- modified_time: datetime        # Modification timestamp
- accessed_time: datetime        # Access timestamp
- is_directory: bool             # Directory flag
- is_archive: bool               # Archive type flag
- is_password_protected: bool    # Password-protected archive flag
- archive_path: str              # Parent archive path (if extracted)
- mime_type: str                 # MIME type (from libmagic)
- file_type: str                 # Human-readable file type
- permissions: str               # File permissions string
```

**Extended Windows Metadata (8 fields)**
```python
- friendly_type: str             # Windows friendly type description
- owner: str                     # File owner (Windows)
- attributes: str                # File attributes (R/H/S/A)
- computer: str                  # Computer hostname
- parent_folder: str             # Parent folder path
- extension_mismatch: bool       # MIME vs extension mismatch
- expected_extensions: str       # Expected extensions for MIME
```

**Document Properties (11 fields)** - From Office/PDF metadata
```python
- doc_author: str
- doc_last_modified_by: str
- doc_title: str
- doc_subject: str
- doc_keywords: str
- doc_created: str
- doc_modified: str
- doc_company: str
- doc_manager: str
- doc_category: str
- doc_comments: str
```

**Cryptographic Hashes (3 fields)**
```python
- md5: str
- sha1: str
- sha256: str
```

**Threat Intelligence - VirusTotal (4 fields)**
```python
- vt_detected: bool              # Detection flag
- vt_detection_ratio: str        # e.g., "5/70"
- vt_link: str                   # VT report URL
- vt_error: str                  # Lookup error message
```

**Document Analysis (4 fields)**
```python
- doc_has_macros: bool
- doc_has_javascript: bool
- doc_suspicious_elements: List[str]
- doc_analysis_error: str
```

**Executable Analysis (9 fields)**
```python
- exe_domains: List[str]         # Extracted domains
- exe_ips: List[str]             # Extracted IPs
- exe_urls: List[str]            # Extracted URLs
- exe_suspicious_imports: List[str]
- exe_analysis_error: str
- exe_company: str               # PE version info
- exe_product: str
- exe_description: str
- exe_version: str
```

**Digital Signature (4 fields)**
```python
- signature_info: Dict           # Full signature details
- is_signed: bool
- sig_subject: str               # Certificate subject
- sig_issuer: str                # Certificate issuer
```

**Windows Defender Integration (4 fields)**
```python
- defender_scanned: bool
- defender_detected: bool
- defender_threat_name: str
- defender_error: str
```

**Risk Assessment (2 fields)**
```python
- risk_score: int                # 0-100 heuristic score
- risk_reasons: List[str]        # Human-readable reasons
```

### 1.2 Field Definition and Population Points

**Field Definition:**
- `analyzer/metadata.py` - `FileInfo` dataclass (lines 88-172)

**Field Population:**
- `analyzer/metadata.py` - `get_file_metadata()` - Basic file metadata, owner, attributes, timestamps
- `analyzer/metadata.py` - `extract_office_properties()` - Document properties from Office files
- `analyzer/metadata.py` - `calculate_risk_score()` - Risk scoring logic
- `analyzer/hasher.py` - `HashCache.hash_file()` - MD5, SHA1, SHA256 computation
- `analyzer/document_analyzer.py` - `analyze_document()` - Document threat analysis
- `analyzer/executable_analyzer.py` - `analyze_executable()` - PE analysis and IOC extraction
- `analyzer/virustotal.py` - `lookup_files_virustotal()` - VT API enrichment
- `analyzer/defender.py` - `scan_files_with_defender()` - Windows Defender scanning

**Field Serialization:**
- `analyzer/metadata.py` - `FileInfo.to_dict()` - JSON serialization (lines 173-239)
- `analyzer/report_generator.py` - `generate_csv_report()` - CSV output (lines 17-59)
- `analyzer/report_generator.py` - `generate_html_report()` - HTML output with embedded JSON (lines 61-1893)

### 1.3 Current Output Formats

**CSV Format:**
- Flat structure with 43 predefined columns
- Lists serialized as semicolon-delimited strings
- UTF-8-BOM encoding for Excel compatibility
- No nested objects

**JSON Format:**
- Embedded in HTML reports for client-side filtering/searching
- Flat structure matching `to_dict()` output
- Lists preserved as arrays
- No formal JSON export endpoint (only embedded)

**HTML Format:**
- Interactive table with filters, sorting, pagination
- Expandable detail panels for each artifact
- Dark/light mode toggle
- Risk-based color coding
- SHA256 copy-to-clipboard
- Split-report capability for large datasets (50k+ files)

---

## 2. ECS Fieldset Selection

Based on ECS v9.2.0 documentation and ArtifactSleuth's forensic focus, the following ECS fieldsets are relevant:

### 2.1 Core Fieldsets (High Priority)

**`file.*` - File Metadata** - [ECS Reference](https://www.elastic.co/guide/en/ecs/current/ecs-file.html)
- **Justification:** Primary artifact type; maps directly to FileInfo core fields
- **Adopted Fields:**
  - `file.name` - Filename
  - `file.path` - Full file path
  - `file.size` - Size in bytes
  - `file.extension` - File extension
  - `file.created` - Creation timestamp (ISO 8601)
  - `file.mtime` - Modification time
  - `file.accessed` - Access time
  - `file.type` - File type (file/dir/symlink)
  - `file.mime_type` - MIME type
  - `file.directory` - Parent directory

**`hash.*` - Cryptographic Hashes** - [ECS Reference](https://www.elastic.co/guide/en/ecs/current/ecs-hash.html)
- **Justification:** Core to forensic artifact identification
- **Adopted Fields:**
  - `file.hash.md5`
  - `file.hash.sha1`
  - `file.hash.sha256`

**`event.*` - Event Context** - [ECS Reference](https://www.elastic.co/guide/en/ecs/current/ecs-event.html)
- **Justification:** Provides scan/analysis context metadata
- **Adopted Fields:**
  - `event.kind` = "event"
  - `event.category` = ["file"]
  - `event.type` = ["info"]
  - `event.action` = "artifact-analysis"
  - `event.created` - When analysis occurred
  - `event.dataset` = "artifactsleuth.scan"

**`host.*` - Host Information** - [ECS Reference](https://www.elastic.co/guide/en/ecs/current/ecs-host.html)
- **Justification:** Captures source system context (e.g., computer name from file metadata)
- **Adopted Fields:**
  - `host.name` - Computer name from Windows metadata

### 2.2 Threat Intelligence Fieldsets (High Priority)

**`threat.indicator.*` - Threat Indicators** - [ECS Reference](https://www.elastic.co/guide/en/ecs/current/ecs-threat.html)
- **Justification:** Maps to VirusTotal detections and suspicious artifact findings
- **Adopted Fields:**
  - `threat.indicator.type` = "file"
  - `threat.indicator.file.hash.md5`
  - `threat.indicator.file.hash.sha1`
  - `threat.indicator.file.hash.sha256`
  - `threat.indicator.description` - Human-readable threat description
  - `threat.indicator.confidence` - Confidence level (High/Medium/Low based on risk_score)
  - `threat.indicator.provider` - "virustotal" or "windows-defender"

**`threat.enrichments.*` - External Enrichment** - [ECS Reference](https://www.elastic.co/guide/en/ecs/current/ecs-threat.html)
- **Justification:** VirusTotal enrichment data
- **Adopted Fields:**
  - `threat.enrichments[].indicator.file.hash.sha256`
  - `threat.enrichments[].indicator.provider` = "virustotal"
  - `threat.enrichments[].indicator.confidence` - Based on VT detection ratio

### 2.3 Executable Analysis Fieldsets (Medium Priority)

**`pe.*` - PE (Portable Executable) Metadata** - [ECS Reference](https://www.elastic.co/guide/en/ecs/current/ecs-pe.html)
- **Justification:** Windows executable analysis is a core feature
- **Adopted Fields:**
  - `pe.company` - Company from version info
  - `pe.description` - File description
  - `pe.product` - Product name
  - `pe.original_file_name` - Original filename
  - `pe.imphash` - Import hash (if computed in future)

**`code_signature.*` - Digital Signatures** - [ECS Reference](https://www.elastic.co/guide/en/ecs/current/ecs-code_signature.html)
- **Justification:** Authenticode signature validation
- **Adopted Fields:**
  - `code_signature.exists` - Whether signature is present
  - `code_signature.valid` - Signature validation status
  - `code_signature.subject_name` - Certificate subject
  - `code_signature.issuer_name` - Certificate issuer
  - `code_signature.signing_id` - Certificate thumbprint (if available)

**`process.*` - Process Context** - [ECS Reference](https://www.elastic.co/guide/en/ecs/current/ecs-process.html)
- **Justification:** Provides executable context metadata
- **Adopted Fields:**
  - `process.executable` - Full path to executable
  - `process.name` - Executable filename
  - `process.code_signature.*` - Reuse code_signature fields

### 2.4 Network IOC Fieldsets (Medium Priority)

**`url.*` - URL Analysis** - [ECS Reference](https://www.elastic.co/guide/en/ecs/current/ecs-url.html)
- **Justification:** Extracted URLs from executables
- **Adopted Fields:**
  - `url.original` - Full URL
  - `url.domain` - Domain component
  - `url.path` - Path component

**`dns.*` - Domain Name** - [ECS Reference](https://www.elastic.co/guide/en/ecs/current/ecs-dns.html)
- **Justification:** Extracted domains from PE files
- **Adopted Fields:**
  - `dns.question.name` - Domain name

**`source.*` / `destination.*` - IP Addresses** - [ECS Reference](https://www.elastic.co/guide/en/ecs/current/ecs-source.html)
- **Justification:** Extracted IPs from PE files
- **Adopted Fields:**
  - `related.ip[]` - All extracted IPs (ECS recommends using `related.*`)

### 2.5 Document Metadata Fieldsets (Low Priority)

**`user.*` - User Identity** - [ECS Reference](https://www.elastic.co/guide/en/ecs/current/ecs-user.html)
- **Justification:** Maps to document author, file owner
- **Adopted Fields:**
  - `user.name` - File owner (Windows)
  - `user.full_name` - Document author (Office docs)

**`related.*` - Related Entities** - [ECS Reference](https://www.elastic.co/guide/en/ecs/current/ecs-related.html)
- **Justification:** Cross-reference fields for SIEM correlation
- **Adopted Fields:**
  - `related.hash[]` - All hashes
  - `related.ip[]` - All IPs
  - `related.user[]` - All user names

### 2.6 Fieldsets NOT Adopted

The following ECS fieldsets are **not relevant** to ArtifactSleuth's use case:
- `network.*` - No live network capture
- `http.*` - No HTTP transaction analysis
- `tls.*` - No TLS certificate analysis
- `dns.answers` - No DNS resolution
- `container.*` - No container analysis
- `cloud.*` - No cloud infrastructure metadata
- `geo.*` - No geolocation
- `agent.*` - ArtifactSleuth is not a beats agent
- `log.*` - Not a log aggregation tool
- `error.*` - Internal tool errors use custom namespace

---

## 3. Field Mapping Table

### 3.1 Core File Metadata Mapping

| Current Field | ECS Field | Notes |
|--------------|-----------|-------|
| `path` | `file.path` | Direct mapping |
| `name` | `file.name` | Direct mapping |
| `size` | `file.size` | Direct mapping (bytes) |
| `created_time` | `file.created` | Convert to ISO 8601 |
| `modified_time` | `file.mtime` | Convert to ISO 8601 |
| `accessed_time` | `file.accessed` | Convert to ISO 8601 |
| `mime_type` | `file.mime_type` | Direct mapping |
| `is_directory` | `file.type` | Map: `True` → "dir", `False` → "file" |
| `relative_path` | `artifactsleuth.file.relative_path` | **Custom field** (scan-relative path) |
| `parent_folder` | `file.directory` | Direct mapping |
| N/A | `file.extension` | Extract from `name` (e.g., ".exe") |

### 3.2 Hash Mapping

| Current Field | ECS Field | Notes |
|--------------|-----------|-------|
| `md5` | `file.hash.md5` | Direct mapping |
| `sha1` | `file.hash.sha1` | Direct mapping |
| `sha256` | `file.hash.sha256` | Direct mapping |
| `md5`, `sha1`, `sha256` | `related.hash[]` | Array of all hashes for correlation |

### 3.3 Windows Extended Metadata Mapping

| Current Field | ECS Field | Notes |
|--------------|-----------|-------|
| `owner` | `user.name` | File owner username |
| `computer` | `host.name` | Computer hostname from metadata |
| `attributes` | `artifactsleuth.file.attributes` | **Custom field** (R/H/S/A flags) |
| `friendly_type` | `artifactsleuth.file.friendly_type` | **Custom field** (Windows type description) |
| `file_type` | `file.type` | Map to ECS "file" or "dir" |
| `permissions` | `file.mode` | Unix permissions string (if available) |

### 3.4 PE/Executable Mapping

| Current Field | ECS Field | Notes |
|--------------|-----------|-------|
| `exe_company` | `pe.company` | Direct mapping |
| `exe_product` | `pe.product` | Direct mapping |
| `exe_description` | `pe.description` | Direct mapping |
| `exe_version` | `artifactsleuth.pe.file_version` | **Custom field** (ECS doesn't have pe.version) |
| `is_signed` | `code_signature.exists` | Direct mapping |
| `sig_subject` | `code_signature.subject_name` | Direct mapping |
| `sig_issuer` | `code_signature.issuer_name` | Direct mapping |
| `signature_info` | `artifactsleuth.code_signature.details` | **Custom field** (full signature dict) |

### 3.5 Network IOCs from PE Mapping

| Current Field | ECS Field | Notes |
|--------------|-----------|-------|
| `exe_domains[]` | `artifactsleuth.ioc.domains[]` | **Custom field** (extracted domains) |
| `exe_ips[]` | `artifactsleuth.ioc.ips[]` | **Custom field** (extracted IPs) |
| `exe_ips[]` | `related.ip[]` | Also add to `related.*` for correlation |
| `exe_urls[]` | `artifactsleuth.ioc.urls[]` | **Custom field** (extracted URLs) |
| `exe_suspicious_imports[]` | `artifactsleuth.pe.suspicious_imports[]` | **Custom field** |

### 3.6 Document Analysis Mapping

| Current Field | ECS Field | Notes |
|--------------|-----------|-------|
| `doc_author` | `user.full_name` | Document author (when available) |
| `doc_author` | `artifactsleuth.document.author` | **Custom field** (preserve original) |
| `doc_last_modified_by` | `artifactsleuth.document.last_modified_by` | **Custom field** |
| `doc_title` | `artifactsleuth.document.title` | **Custom field** |
| `doc_subject` | `artifactsleuth.document.subject` | **Custom field** |
| `doc_keywords` | `artifactsleuth.document.keywords` | **Custom field** |
| `doc_created` | `artifactsleuth.document.created` | **Custom field** |
| `doc_modified` | `artifactsleuth.document.modified` | **Custom field** |
| `doc_company` | `artifactsleuth.document.company` | **Custom field** |
| `doc_manager` | `artifactsleuth.document.manager` | **Custom field** |
| `doc_category` | `artifactsleuth.document.category` | **Custom field** |
| `doc_comments` | `artifactsleuth.document.comments` | **Custom field** |
| `doc_has_macros` | `artifactsleuth.document.has_macros` | **Custom field** |
| `doc_has_javascript` | `artifactsleuth.document.has_javascript` | **Custom field** |
| `doc_suspicious_elements[]` | `artifactsleuth.document.suspicious_elements[]` | **Custom field** |

### 3.7 Threat Intelligence Mapping

| Current Field | ECS Field | Notes |
|--------------|-----------|-------|
| `vt_detected` | `threat.indicator.file.hash.sha256` present in enrichments | Flag via enrichments array |
| `vt_detection_ratio` | `artifactsleuth.virustotal.detection_ratio` | **Custom field** |
| `vt_link` | `artifactsleuth.virustotal.permalink` | **Custom field** |
| `defender_detected` | `threat.indicator.provider` = "windows-defender" | Use threat.indicator structure |
| `defender_threat_name` | `threat.indicator.description` | Direct mapping |

### 3.8 Archive Context Mapping

| Current Field | ECS Field | Notes |
|--------------|-----------|-------|
| `is_archive` | `artifactsleuth.file.is_archive` | **Custom field** |
| `is_password_protected` | `artifactsleuth.archive.is_password_protected` | **Custom field** |
| `archive_path` | `artifactsleuth.archive.parent_path` | **Custom field** (nested archive context) |

### 3.9 Risk Scoring Mapping

| Current Field | ECS Field | Notes |
|--------------|-----------|-------|
| `risk_score` | `event.risk_score` | Direct mapping (ECS 0-100 scale) |
| `risk_score` | `threat.indicator.confidence` | Map: 0-25→"Low", 26-50→"Medium", 51+→"High" |
| `risk_reasons[]` | `artifactsleuth.risk.reasons[]` | **Custom field** |

### 3.10 Event Context Mapping (New)

| Current Field | ECS Field | Notes |
|--------------|-----------|-------|
| N/A | `event.kind` = "event" | Always "event" |
| N/A | `event.category` = ["file"] | Always ["file"] |
| N/A | `event.type` = ["info"] | Always ["info"] |
| N/A | `event.action` = "artifact-analysis" | Consistent action name |
| N/A | `event.created` | Scan timestamp (ISO 8601) |
| N/A | `event.dataset` = "artifactsleuth.scan" | Dataset identifier |
| N/A | `@timestamp` | Same as `event.created` |

### 3.11 Fields Not Mapped to ECS

These fields are **forensic-specific or tool-specific** and will remain in the `artifactsleuth.*` namespace:

- `extension_mismatch` → `artifactsleuth.file.extension_mismatch`
- `expected_extensions` → `artifactsleuth.file.expected_extensions`
- `doc_analysis_error` → `artifactsleuth.document.analysis_error`
- `exe_analysis_error` → `artifactsleuth.pe.analysis_error`
- `vt_error` → `artifactsleuth.virustotal.error`
- `defender_error` → `artifactsleuth.defender.error`
- `defender_scanned` → `artifactsleuth.defender.scanned`

---

## 4. Custom Namespace Design

### 4.1 Namespace Structure: `artifactsleuth.*`

All forensic-specific and tool-specific fields that do not have a direct ECS mapping will use the `artifactsleuth.*` namespace.

**Namespace Justification:**
- Prevents collision with future ECS additions
- Clearly identifies ArtifactSleuth-specific metadata
- Follows ECS best practices for custom fields
- Enables SIEM admins to easily filter/identify custom fields

### 4.2 Custom Field Definitions

#### `artifactsleuth.file.*` - File-Specific Forensics

```yaml
artifactsleuth.file.relative_path:
  type: keyword
  description: File path relative to scan root

artifactsleuth.file.friendly_type:
  type: keyword
  description: Windows friendly file type description

artifactsleuth.file.attributes:
  type: keyword
  description: Windows file attributes (R=Read-only, H=Hidden, S=System, A=Archive)

artifactsleuth.file.extension_mismatch:
  type: boolean
  description: True if MIME type does not match file extension

artifactsleuth.file.expected_extensions:
  type: keyword
  description: Expected file extensions for detected MIME type

artifactsleuth.file.is_archive:
  type: boolean
  description: True if file is a recognized archive format
```

#### `artifactsleuth.archive.*` - Archive Context

```yaml
artifactsleuth.archive.parent_path:
  type: keyword
  description: Path to parent archive if this file was extracted

artifactsleuth.archive.is_password_protected:
  type: boolean
  description: True if archive is password-protected

artifactsleuth.archive.depth:
  type: long
  description: Nested archive extraction depth (0 = on disk, 1+ = nested)
```

#### `artifactsleuth.document.*` - Document Analysis

```yaml
artifactsleuth.document.author:
  type: keyword
  description: Document author from metadata

artifactsleuth.document.last_modified_by:
  type: keyword
  description: Last user to modify document

artifactsleuth.document.title:
  type: text
  description: Document title

artifactsleuth.document.subject:
  type: text
  description: Document subject

artifactsleuth.document.keywords:
  type: keyword
  description: Document keywords

artifactsleuth.document.created:
  type: date
  description: Document creation date from metadata

artifactsleuth.document.modified:
  type: date
  description: Document modification date from metadata

artifactsleuth.document.company:
  type: keyword
  description: Company from document properties

artifactsleuth.document.manager:
  type: keyword
  description: Manager from document properties

artifactsleuth.document.category:
  type: keyword
  description: Document category

artifactsleuth.document.comments:
  type: text
  description: Document comments

artifactsleuth.document.has_macros:
  type: boolean
  description: True if document contains VBA macros

artifactsleuth.document.has_javascript:
  type: boolean
  description: True if document contains JavaScript

artifactsleuth.document.suspicious_elements:
  type: keyword
  description: Array of suspicious element identifiers

artifactsleuth.document.analysis_error:
  type: text
  description: Error message if document analysis failed
```

#### `artifactsleuth.pe.*` - PE-Specific Forensics

```yaml
artifactsleuth.pe.file_version:
  type: keyword
  description: PE file version string

artifactsleuth.pe.suspicious_imports:
  type: keyword
  description: Array of suspicious API imports

artifactsleuth.pe.analysis_error:
  type: text
  description: Error message if PE analysis failed
```

#### `artifactsleuth.ioc.*` - Extracted Indicators

```yaml
artifactsleuth.ioc.domains:
  type: keyword
  description: Array of domains extracted from PE file

artifactsleuth.ioc.ips:
  type: ip
  description: Array of IP addresses extracted from PE file

artifactsleuth.ioc.urls:
  type: keyword
  description: Array of URLs extracted from PE file
```

#### `artifactsleuth.code_signature.*` - Signature Details

```yaml
artifactsleuth.code_signature.details:
  type: object
  description: Full digital signature details dictionary
```

#### `artifactsleuth.virustotal.*` - VirusTotal Results

```yaml
artifactsleuth.virustotal.detection_ratio:
  type: keyword
  description: VirusTotal detection ratio (e.g., "5/70")

artifactsleuth.virustotal.permalink:
  type: keyword
  description: VirusTotal report URL

artifactsleuth.virustotal.error:
  type: text
  description: Error message if VT lookup failed
```

#### `artifactsleuth.defender.*` - Windows Defender Results

```yaml
artifactsleuth.defender.scanned:
  type: boolean
  description: True if file was scanned with Windows Defender

artifactsleuth.defender.detected:
  type: boolean
  description: True if Defender detected a threat

artifactsleuth.defender.threat_name:
  type: keyword
  description: Defender threat name (if detected)

artifactsleuth.defender.error:
  type: text
  description: Error message if Defender scan failed
```

#### `artifactsleuth.risk.*` - Risk Scoring

```yaml
artifactsleuth.risk.reasons:
  type: keyword
  description: Array of human-readable risk reasons
```

#### `artifactsleuth.scan.*` - Scan Context

```yaml
artifactsleuth.scan.root_path:
  type: keyword
  description: Root path of the scan

artifactsleuth.scan.timestamp:
  type: date
  description: When the scan was performed

artifactsleuth.scan.version:
  type: keyword
  description: ArtifactSleuth version
```

---

## 5. Data Model Changes

### 5.1 Internal Model Modifications

**Recommendation:** Keep the internal `FileInfo` dataclass **mostly unchanged** for backward compatibility and code simplicity. Add a **separate ECS transformation layer** for output.

**Changes to `analyzer/metadata.py`:**

1. **Add ECS transformation method to FileInfo:**
```python
def to_ecs_dict(self) -> Dict[str, Any]:
    """
    Transform FileInfo to ECS v9.2.0 normalized dictionary.
    
    Returns nested structure following ECS field hierarchy:
    - file.*
    - hash.*
    - event.*
    - threat.*
    - pe.*
    - code_signature.*
    - artifactsleuth.*
    """
    # Implementation in Phase 1
    pass
```

2. **Add ECS validation helper:**
```python
def validate_ecs_output(ecs_doc: Dict[str, Any]) -> List[str]:
    """
    Validate ECS document structure against v9.2.0 schema.
    Returns list of validation errors (empty if valid).
    """
    # Basic type checking for required ECS fields
    pass
```

3. **Preserve existing `to_dict()` for legacy output**

### 5.2 Nested vs Flattened Representation

**ECS Standard Representation (Nested):**
```json
{
  "file": {
    "name": "malware.exe",
    "path": "C:\\Users\\Alice\\Downloads\\malware.exe",
    "size": 524288,
    "hash": {
      "md5": "d41d8cd98f00b204e9800998ecf8427e",
      "sha1": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
      "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    },
    "created": "2026-01-15T10:30:00Z",
    "mtime": "2026-01-15T10:30:00Z"
  },
  "event": {
    "kind": "event",
    "category": ["file"],
    "type": ["info"],
    "action": "artifact-analysis",
    "created": "2026-01-26T19:00:00Z",
    "dataset": "artifactsleuth.scan"
  },
  "artifactsleuth": {
    "file": {
      "relative_path": "Downloads/malware.exe",
      "attributes": "A"
    }
  }
}
```

**Dot-Notation Flattened (for CSV/legacy compatibility):**
```json
{
  "file.name": "malware.exe",
  "file.path": "C:\\Users\\Alice\\Downloads\\malware.exe",
  "file.size": 524288,
  "file.hash.md5": "d41d8cd98f00b204e9800998ecf8427e",
  "file.hash.sha1": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
  "file.hash.sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "event.kind": "event",
  "event.category": ["file"],
  "artifactsleuth.file.relative_path": "Downloads/malware.exe"
}
```

**Decision:**
- **JSON/HTML output:** Use **nested** structure (ECS canonical format)
- **CSV output:** Use **flattened** dot-notation (required for flat tables)
- Provide utility function to flatten nested ECS docs: `flatten_ecs_dict()`

---

## 6. Serialization Strategy

### 6.1 JSON Output (ECS Nested)

**Implementation:** `analyzer/report_generator.py`

Create new function:
```python
def generate_ecs_json_report(
    files: List[FileInfo],
    summary: Dict[str, Any],
    output_path: str,
    scan_path: str
) -> None:
    """
    Generate ECS v9.2.0 normalized JSON report.
    
    Output format:
    {
      "scan_metadata": {...},
      "artifacts": [
        { ECS doc 1 },
        { ECS doc 2 },
        ...
      ]
    }
    """
    ecs_docs = [file_info.to_ecs_dict() for file_info in files]
    
    output = {
        "scan_metadata": {
            "scan_path": scan_path,
            "scan_timestamp": summary.get("scan_timestamp"),
            "artifactsleuth_version": __version__,
            "ecs_version": "9.2.0",
            "total_artifacts": len(files)
        },
        "artifacts": ecs_docs
    }
    
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(output, f, indent=2, default=str)
```

**Dot-notation fields:** Represented as nested objects
**Lists:** Preserved as JSON arrays

### 6.2 CSV Output (ECS Flattened)

**Implementation:** `analyzer/report_generator.py`

Modify `generate_csv_report()`:
```python
def generate_ecs_csv_report(
    files: List[FileInfo],
    summary: Dict[str, Any],
    output_path: str
) -> None:
    """
    Generate ECS v9.2.0 normalized CSV report with flattened fields.
    """
    # Define ECS column order
    fieldnames = [
        # Core ECS fields
        '@timestamp',
        'event.kind', 'event.category', 'event.type', 'event.action',
        'file.name', 'file.path', 'file.size', 'file.extension',
        'file.created', 'file.mtime', 'file.accessed',
        'file.mime_type', 'file.type', 'file.directory',
        'file.hash.md5', 'file.hash.sha1', 'file.hash.sha256',
        'host.name',
        'user.name', 'user.full_name',
        'event.risk_score',
        # PE fields
        'pe.company', 'pe.description', 'pe.product',
        'code_signature.exists', 'code_signature.subject_name',
        # Custom fields
        'artifactsleuth.file.relative_path',
        'artifactsleuth.file.attributes',
        'artifactsleuth.file.extension_mismatch',
        'artifactsleuth.document.has_macros',
        'artifactsleuth.document.has_javascript',
        'artifactsleuth.ioc.domains',
        'artifactsleuth.ioc.ips',
        'artifactsleuth.virustotal.detection_ratio',
        'artifactsleuth.virustotal.permalink',
        'artifactsleuth.defender.detected',
        'artifactsleuth.defender.threat_name',
        'artifactsleuth.risk.reasons',
        # ... (all relevant fields)
    ]
    
    with open(output_path, 'w', newline='', encoding='utf-8-sig') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
        writer.writeheader()
        
        for file_info in files:
            ecs_doc = file_info.to_ecs_dict()
            flattened = flatten_ecs_dict(ecs_doc)
            
            # Convert lists to semicolon-delimited strings
            for key, value in flattened.items():
                if isinstance(value, list):
                    flattened[key] = '; '.join(str(v) for v in value)
            
            writer.writerow(flattened)
```

**Handling dot-notation:** Use `flatten_ecs_dict()` to convert nested objects to flat keys
**Array fields:** Serialize as semicolon-delimited strings (e.g., `"domain1.com; domain2.com"`)

### 6.3 HTML Report Output

**Implementation:** `analyzer/report_generator.py`

Modify `generate_html_report()`:

**Option 1: Embed ECS JSON** (Recommended)
- Embed **both** legacy `to_dict()` and `to_ecs_dict()` in HTML
- Add UI toggle: "View: Legacy | ECS Normalized"
- JavaScript renders active view
- Default to Legacy for backward compatibility

**Option 2: ECS-Only HTML**
- Embed only `to_ecs_dict()`
- Update JavaScript table rendering to use ECS field paths
- More breaking change for users

**Recommendation:** Choose **Option 1** for smoother transition.

HTML changes:
```javascript
const filesDataLegacy = {{ files_json_legacy }};
const filesDataECS = {{ files_json_ecs }};
let currentView = 'legacy';  // or 'ecs'

function toggleView() {
    currentView = currentView === 'legacy' ? 'ecs' : 'legacy';
    renderTable(currentView === 'legacy' ? filesDataLegacy : filesDataECS);
}
```

**Field display mapping:**
- `file.name` → Display as "File Name"
- `file.hash.sha256` → Display as "SHA256"
- `artifactsleuth.file.relative_path` → Display as "Relative Path"
- etc.

---

## 7. Backward Compatibility

### 7.1 Impact Assessment

**Breaking Changes:**
- CSV column names change from `name` to `file.name`
- JSON structure changes from flat to nested
- HTML embedded JSON structure changes

**Users Affected:**
- **CSV users:** SIEM ingestion pipelines, spreadsheet templates
- **JSON users:** Downstream parsers expecting legacy schema
- **HTML users:** Minimal impact (UI abstracts data structure)

### 7.2 Compatibility Strategy

**Proposal: Dual-Mode Output**

Add CLI flag: `--ecs-mode` (default: off for v1.x, on for v2.0+)

**Legacy Mode (default in v1.x):**
```bash
python main.py /path/to/usb --output report.csv
# Generates legacy CSV with old field names
```

**ECS Mode:**
```bash
python main.py /path/to/usb --ecs-mode --output report.csv
# Generates ECS-normalized CSV with file.name, file.hash.md5, etc.
```

**v2.0 Migration Path:**
- v1.x: `--ecs-mode` opt-in, legacy default
- v2.0: ECS default, `--legacy-mode` for backward compat
- v3.0: Remove legacy mode entirely

### 7.3 Migration Guide

Create `docs/ECS_MIGRATION_GUIDE.md`:

**For CSV Users:**
```markdown
# Field Mapping Reference

Old Field → New ECS Field
- name → file.name
- path → file.path
- size → file.size
- md5 → file.hash.md5
- owner → user.name
- ... (full mapping table)
```

**For SIEM Users:**
```markdown
# SIEM Ingest Configuration

## Elastic Ingest Pipeline
- Use index template: `artifactsleuth-*`
- Apply ECS field mappings automatically
- No transformation needed

## Splunk Sourcetype
- sourcetype=artifactsleuth:ecs
- Use spath to extract nested fields
```

---

## 8. Validation & Testing

### 8.1 ECS Field Correctness Validation

**Automated Validation:**

Create `analyzer/ecs_validator.py`:
```python
from typing import Dict, Any, List

ECS_SCHEMA = {
    "file.name": {"type": "keyword", "required": False},
    "file.path": {"type": "keyword", "required": False},
    "file.size": {"type": "long", "required": False},
    "file.hash.md5": {"type": "keyword", "required": False},
    # ... (subset of ECS v9.2.0 fields used)
}

def validate_ecs_document(doc: Dict[str, Any]) -> List[str]:
    """
    Validate ECS document against schema.
    
    Returns:
        List of validation errors (empty if valid)
    """
    errors = []
    
    # Check required fields
    if "event.kind" not in flatten_ecs_dict(doc):
        errors.append("Missing required field: event.kind")
    
    # Type validation
    flat_doc = flatten_ecs_dict(doc)
    for field_path, value in flat_doc.items():
        if field_path in ECS_SCHEMA:
            expected_type = ECS_SCHEMA[field_path]["type"]
            if not _validate_type(value, expected_type):
                errors.append(f"Invalid type for {field_path}: expected {expected_type}")
    
    return errors
```

**Manual Validation:**
- Use Elastic's ECS validator: https://github.com/elastic/ecs
- Test ECS JSON output with `ecs-logging-validator` tool

### 8.2 Unit Tests

Create `tests/test_ecs_normalization.py`:

```python
import unittest
from analyzer.metadata import FileInfo
from datetime import datetime

class TestECSNormalization(unittest.TestCase):
    
    def setUp(self):
        self.file_info = FileInfo(
            path="/tmp/test.exe",
            name="test.exe",
            relative_path="test.exe",
            size=1024,
            created_time=datetime(2026, 1, 1),
            modified_time=datetime(2026, 1, 2),
            md5="d41d8cd98f00b204e9800998ecf8427e",
            sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        )
    
    def test_file_name_mapping(self):
        ecs_doc = self.file_info.to_ecs_dict()
        self.assertEqual(ecs_doc["file"]["name"], "test.exe")
    
    def test_hash_nesting(self):
        ecs_doc = self.file_info.to_ecs_dict()
        self.assertEqual(ecs_doc["file"]["hash"]["md5"], "d41d8cd98f00b204e9800998ecf8427e")
        self.assertEqual(ecs_doc["file"]["hash"]["sha256"], "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    
    def test_event_fields_present(self):
        ecs_doc = self.file_info.to_ecs_dict()
        self.assertEqual(ecs_doc["event"]["kind"], "event")
        self.assertEqual(ecs_doc["event"]["category"], ["file"])
        self.assertEqual(ecs_doc["event"]["action"], "artifact-analysis")
    
    def test_custom_namespace(self):
        self.file_info.attributes = "R"
        ecs_doc = self.file_info.to_ecs_dict()
        self.assertEqual(ecs_doc["artifactsleuth"]["file"]["attributes"], "R")
    
    def test_timestamp_iso8601(self):
        ecs_doc = self.file_info.to_ecs_dict()
        self.assertRegex(ecs_doc["file"]["created"], r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}")
```

### 8.3 Integration Tests

**Test Scenarios:**

1. **Full Scan Test:**
   - Scan sample directory with known files
   - Generate ECS JSON output
   - Validate all documents pass ECS validation
   - Verify critical fields present

2. **CSV Export Test:**
   - Generate ECS CSV
   - Parse with pandas
   - Verify dot-notation columns exist
   - Verify array fields are semicolon-delimited

3. **HTML Report Test:**
   - Generate HTML with ECS mode
   - Verify embedded JSON is valid ECS
   - Test UI toggle between legacy/ECS views

4. **Backward Compatibility Test:**
   - Generate legacy output
   - Verify old field names still work
   - Ensure no ECS fields leak into legacy mode

---

## 9. Documentation

### 9.1 README Updates

**Changes to `README.md`:**

Add new section:
```markdown
## ECS Normalization

ArtifactSleuth supports Elastic Common Schema (ECS) v9.2.0 normalized output for seamless integration with SIEM systems.

### Enable ECS Mode

```bash
python main.py /path/to/usb --ecs-mode --output report.json
```

### ECS Field Mapping

ArtifactSleuth maps internal fields to ECS standard fieldsets:
- `file.*` - File metadata
- `hash.*` - Cryptographic hashes
- `event.*` - Event context
- `threat.*` - Threat intelligence
- `pe.*` - PE executable metadata
- `code_signature.*` - Digital signatures
- `artifactsleuth.*` - Custom forensic fields

For full field mapping, see [docs/ECS_NORMALIZATION_PLAN.md](docs/ECS_NORMALIZATION_PLAN.md)

### SIEM Integration

**Elastic:**
```bash
# Ingest ECS JSON directly
curl -X POST "localhost:9200/artifactsleuth-scan/_doc" \
  -H "Content-Type: application/json" \
  -d @report.json
```

**Splunk:**
```bash
# Use sourcetype with ECS support
| inputlookup report.csv | spath input=file.name
```
```

### 9.2 New Documentation Files

**Create: `docs/ECS_NORMALIZATION_PLAN.md`**
- This document (reference implementation plan)

**Create: `docs/ECS_MIGRATION_GUIDE.md`**
- Step-by-step migration guide for existing users
- Field mapping reference table
- SIEM configuration examples
- Troubleshooting common issues

**Create: `docs/ECS_FIELD_REFERENCE.md`**
- Complete field mapping reference
- Custom `artifactsleuth.*` field definitions
- Data type specifications
- Example ECS documents

### 9.3 Developer Documentation

**Update: `docs/CODE_FLOW.md`**

Add section:
```markdown
## ECS Transformation Flow

1. **Artifact Collection**: FileInfo dataclass (internal model)
2. **ECS Transformation**: `FileInfo.to_ecs_dict()` → nested ECS document
3. **Serialization**:
   - JSON: Direct output of nested structure
   - CSV: Flatten with `flatten_ecs_dict()`, then write
   - HTML: Embed both legacy and ECS JSON, toggle in UI
4. **Validation**: `validate_ecs_document()` before output
```

---

## 10. Phased Rollout

### Phase 1: Core ECS Fields (Week 1-2)

**Scope:**
- Implement `file.*` and `hash.*` mapping
- Implement `event.*` context fields
- Add `to_ecs_dict()` method to FileInfo
- Create `flatten_ecs_dict()` utility
- Unit tests for core field mapping

**Deliverables:**
- Core ECS transformation working for basic file metadata
- Unit tests passing (>80% coverage)
- Basic validation logic

**Success Criteria:**
- All basic file fields map to ECS
- JSON output validates against ECS schema
- No existing functionality broken

### Phase 2: Threat Intelligence & PE Analysis (Week 3-4)

**Scope:**
- Implement `threat.*` field mapping for VT/Defender
- Implement `pe.*` and `code_signature.*` mapping
- Implement `artifactsleuth.ioc.*` for extracted indicators
- Update CSV generator for flattened ECS fields
- Integration tests for threat intel

**Deliverables:**
- Full threat intelligence in ECS format
- PE/executable analysis in ECS format
- CSV export with ECS column names

**Success Criteria:**
- VirusTotal detections map to `threat.indicator.*`
- PE metadata uses standard `pe.*` fields
- CSV export includes all critical ECS fields

### Phase 3: Document Analysis & Custom Namespace (Week 5-6)

**Scope:**
- Implement `artifactsleuth.document.*` custom fields
- Implement `artifactsleuth.archive.*` custom fields
- Implement `artifactsleuth.risk.*` custom fields
- Update HTML report for ECS embedded JSON
- Create ECS/Legacy toggle in HTML UI

**Deliverables:**
- All custom fields under `artifactsleuth.*`
- HTML report with dual-mode support
- Full ECS documentation

**Success Criteria:**
- All FileInfo fields have ECS mapping
- HTML report displays ECS and Legacy views
- Custom namespace validated

### Phase 4: Backward Compatibility & CLI (Week 7)

**Scope:**
- Add `--ecs-mode` CLI flag
- Implement legacy fallback mode
- Create migration guide documentation
- Performance optimization for ECS transformation
- User acceptance testing

**Deliverables:**
- `--ecs-mode` flag working
- Legacy mode preserved
- Migration guide published

**Success Criteria:**
- Existing users can run tool without changes
- ECS mode opt-in works correctly
- No performance degradation (< 5% overhead)

### Phase 5: Validation & Documentation (Week 8)

**Scope:**
- Comprehensive ECS validation logic
- Full integration test suite
- SIEM integration examples (Elastic, Splunk)
- Public documentation updates
- Community feedback collection

**Deliverables:**
- Automated ECS validation
- Full test coverage (>85%)
- Public docs (README, migration guide, field reference)
- Example SIEM configurations

**Success Criteria:**
- All tests passing
- ECS validator reports 0 errors
- Documentation complete and reviewed
- Ready for release

### Phase 6: Release & Monitoring (Week 9+)

**Scope:**
- v1.x release with `--ecs-mode` opt-in
- Monitor user adoption and feedback
- Bug fixes and refinements
- Plan v2.0 with ECS as default

**Deliverables:**
- Stable release with ECS support
- User feedback collected
- Roadmap for v2.0 (ECS default)

**Success Criteria:**
- No critical bugs in ECS mode
- Positive user feedback
- SIEM integration validated by users

---

## Appendix A: ECS Field Type Reference

| ECS Type | Python Type | Notes |
|----------|-------------|-------|
| `keyword` | `str` | Exact value, not analyzed |
| `text` | `str` | Full-text searchable |
| `long` | `int` | 64-bit integer |
| `boolean` | `bool` | True/False |
| `date` | `datetime` / `str` | ISO 8601 format |
| `ip` | `str` | IPv4 or IPv6 address |
| `object` | `dict` | Nested object |
| `nested` | `List[dict]` | Array of objects |

---

## Appendix B: Example ECS Document

**Full ECS-Normalized Artifact (Executable with VT Detection):**

```json
{
  "@timestamp": "2026-01-26T19:00:00.000Z",
  "event": {
    "kind": "event",
    "category": ["file"],
    "type": ["info"],
    "action": "artifact-analysis",
    "created": "2026-01-26T19:00:00.000Z",
    "dataset": "artifactsleuth.scan",
    "risk_score": 75
  },
  "file": {
    "name": "suspicious.exe",
    "path": "C:\\Users\\Alice\\Downloads\\suspicious.exe",
    "size": 524288,
    "extension": ".exe",
    "created": "2026-01-15T10:30:00.000Z",
    "mtime": "2026-01-15T10:30:00.000Z",
    "accessed": "2026-01-20T14:22:00.000Z",
    "type": "file",
    "mime_type": "application/x-dosexec",
    "directory": "C:\\Users\\Alice\\Downloads",
    "hash": {
      "md5": "5d41402abc4b2a76b9719d911017c592",
      "sha1": "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d",
      "sha256": "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae"
    }
  },
  "host": {
    "name": "ALICE-PC"
  },
  "user": {
    "name": "Alice"
  },
  "pe": {
    "company": "Malicious Corp",
    "description": "Totally Legitimate Software",
    "product": "LegitApp"
  },
  "code_signature": {
    "exists": false
  },
  "threat": {
    "indicator": {
      "type": "file",
      "description": "VirusTotal detection: Trojan.Generic",
      "confidence": "High",
      "provider": "virustotal",
      "file": {
        "hash": {
          "sha256": "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae"
        }
      }
    }
  },
  "related": {
    "hash": [
      "5d41402abc4b2a76b9719d911017c592",
      "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d",
      "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae"
    ],
    "ip": ["192.168.1.100", "10.0.0.5"],
    "user": ["Alice"]
  },
  "artifactsleuth": {
    "file": {
      "relative_path": "Downloads\\suspicious.exe",
      "attributes": "A",
      "friendly_type": "Application",
      "extension_mismatch": false,
      "is_archive": false
    },
    "pe": {
      "file_version": "1.0.0.0",
      "suspicious_imports": [
        "CreateRemoteThread",
        "WriteProcessMemory",
        "VirtualAllocEx"
      ],
      "analysis_error": null
    },
    "ioc": {
      "domains": ["malicious.example.com", "c2server.net"],
      "ips": ["192.168.1.100", "10.0.0.5"],
      "urls": ["http://malicious.example.com/payload.bin"]
    },
    "virustotal": {
      "detection_ratio": "45/70",
      "permalink": "https://www.virustotal.com/gui/file/2c26b46b...",
      "error": null
    },
    "defender": {
      "scanned": false,
      "detected": null,
      "threat_name": null,
      "error": null
    },
    "risk": {
      "reasons": [
        "VT detected (45/70 engines)",
        "Suspicious imports: CreateRemoteThread, WriteProcessMemory",
        "Extracted IOCs: 2 domains, 2 IPs",
        "Not digitally signed"
      ]
    },
    "scan": {
      "root_path": "C:\\Users\\Alice\\Downloads",
      "timestamp": "2026-01-26T19:00:00.000Z",
      "version": "1.1.0"
    }
  }
}
```

---

## Appendix C: Flattened CSV Example

**CSV Output (ECS Flattened with Dot-Notation):**

```csv
@timestamp,event.kind,event.category,event.action,file.name,file.path,file.size,file.hash.md5,file.hash.sha256,pe.company,code_signature.exists,artifactsleuth.virustotal.detection_ratio,artifactsleuth.risk.reasons
2026-01-26T19:00:00Z,event,"[""file""]",artifact-analysis,suspicious.exe,C:\Users\Alice\Downloads\suspicious.exe,524288,5d41402abc4b2a76b9719d911017c592,2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae,Malicious Corp,false,45/70,"VT detected (45/70 engines); Suspicious imports: CreateRemoteThread, WriteProcessMemory; Not digitally signed"
```

---

## Appendix D: Implementation Checklist

- [ ] **Phase 1:** Core ECS fields
  - [ ] Implement `to_ecs_dict()` method
  - [ ] Map `file.*` fields
  - [ ] Map `hash.*` fields
  - [ ] Map `event.*` fields
  - [ ] Create `flatten_ecs_dict()` utility
  - [ ] Unit tests for core fields
  
- [ ] **Phase 2:** Threat intel & PE
  - [ ] Map `threat.*` fields
  - [ ] Map `pe.*` fields
  - [ ] Map `code_signature.*` fields
  - [ ] Map `artifactsleuth.ioc.*` fields
  - [ ] Update CSV generator
  - [ ] Integration tests for threat intel
  
- [ ] **Phase 3:** Document & custom fields
  - [ ] Map `artifactsleuth.document.*` fields
  - [ ] Map `artifactsleuth.archive.*` fields
  - [ ] Map `artifactsleuth.risk.*` fields
  - [ ] Update HTML report (ECS JSON embed)
  - [ ] Add ECS/Legacy toggle in UI
  
- [ ] **Phase 4:** Backward compatibility
  - [ ] Add `--ecs-mode` CLI flag
  - [ ] Implement legacy mode fallback
  - [ ] Create migration guide
  - [ ] Performance testing
  
- [ ] **Phase 5:** Validation & docs
  - [ ] ECS validator implementation
  - [ ] Full integration tests
  - [ ] SIEM examples (Elastic, Splunk)
  - [ ] Update README.md
  - [ ] Create field reference doc
  
- [ ] **Phase 6:** Release
  - [ ] v1.x release with `--ecs-mode` opt-in
  - [ ] User feedback collection
  - [ ] Bug fixes
  - [ ] Plan v2.0 (ECS default)

---

## Appendix E: References

- **ECS v9.2.0 Documentation:** https://www.elastic.co/guide/en/ecs/current/index.html
- **ECS GitHub Repository:** https://github.com/elastic/ecs
- **ECS Field Reference:** https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html
- **ECS Best Practices:** https://www.elastic.co/guide/en/ecs/current/ecs-using-ecs.html
- **Elastic Beats ECS Integration:** https://www.elastic.co/guide/en/beats/filebeat/current/ecs-filebeat.html

---

## Sign-Off

This implementation plan provides a comprehensive blueprint for adopting ECS v9.2.0 normalization in ArtifactSleuth. The phased approach ensures:
- **Minimal disruption** to existing users
- **Gradual adoption** with opt-in ECS mode
- **Forensic fidelity** via custom namespace
- **Long-term interoperability** with SIEM systems

**Next Steps:**
1. Review this plan with stakeholders
2. Approve field mapping decisions
3. Begin Phase 1 implementation
4. Iterate based on feedback

**Estimated Timeline:** 8-9 weeks for full ECS adoption  
**Estimated Effort:** ~160-180 hours of engineering time

---

*Document prepared by: ArtifactSleuth Engineering Team*  
*Date: 2026-01-26*  
*Version: 1.0*
