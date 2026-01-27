# ArtifactSleuth ECS v9.2.0 Normalization Implementation

**ECS Version:** 9.2.0  
**Date:** 2026-01-27

---

## Overview

This document describes how to implement Elastic Common Schema (ECS) v9.2.0 normalization in ArtifactSleuth. The approach transforms the internal FileInfo data model to use ECS standard fields where applicable, and custom `artifactsleuth.*` fields for forensic-specific data.

**Implementation approach:**
- Add a new `to_ecs_dict()` method to FileInfo that transforms internal fields to ECS format
- Keep the existing internal model unchanged (add transformation layer on top)
- All output formats (JSON/CSV/HTML) will use ECS format by default
- Use nested JSON for ECS output, flattened dot-notation for CSV

---

## Current Fields (FileInfo Dataclass)

The current `FileInfo` dataclass in `analyzer/metadata.py` has 70+ fields organized as:

**Core file metadata:** path, name, relative_path, size, timestamps, mime_type, file_type, permissions  
**Hashes:** md5, sha1, sha256  
**Windows metadata:** owner, attributes, computer, friendly_type  
**Document properties:** author, title, subject, company, etc.  
**Document analysis:** has_macros, has_javascript, suspicious_elements  
**PE/executable:** company, product, version, signature info  
**PE analysis:** domains, IPs, URLs, suspicious imports  
**Threat intel:** VirusTotal results, Windows Defender results  
**Risk scoring:** risk_score, risk_reasons

---

## ECS Fieldsets to Use

### Core Fieldsets

**`file.*`** - File metadata
- `file.name` - Filename
- `file.path` - Full path
- `file.size` - Size in bytes
- `file.extension` - File extension
- `file.created` - Creation timestamp (ISO 8601)
- `file.mtime` - Modification time
- `file.accessed` - Access time
- `file.type` - "file" or "dir"
- `file.mime_type` - MIME type
- `file.directory` - Parent directory
- `file.hash.md5` - MD5 hash
- `file.hash.sha1` - SHA1 hash
- `file.hash.sha256` - SHA256 hash

**`event.*`** - Event context
- `event.kind` = "event"
- `event.category` = ["file"]
- `event.type` = ["info"]
- `event.action` = "artifact-analysis"
- `event.created` - When analysis occurred
- `event.dataset` = "artifactsleuth.scan"
- `event.risk_score` - Risk score (0-100)

**`host.*`** - Host information
- `host.name` - Computer name

**`user.*`** - User identity
- `user.name` - File owner
- `user.full_name` - Document author

**`pe.*`** - PE executable metadata
- `pe.company` - Company from version info
- `pe.description` - File description
- `pe.product` - Product name

**`code_signature.*`** - Digital signatures
- `code_signature.exists` - Whether signature is present
- `code_signature.subject_name` - Certificate subject
- `code_signature.issuer_name` - Certificate issuer

**`threat.indicator.*`** - Threat indicators
- `threat.indicator.type` = "file"
- `threat.indicator.description` - Threat description
- `threat.indicator.confidence` - "High"/"Medium"/"Low"
- `threat.indicator.provider` - "virustotal" or "windows-defender"

**`related.*`** - Cross-references
- `related.hash[]` - All hashes
- `related.ip[]` - All IPs
- `related.user[]` - All user names

---

## Custom Namespace: `artifactsleuth.*`

Forensic-specific fields that don't map cleanly to ECS:

### `artifactsleuth.file.*`
```yaml
relative_path: File path relative to scan root
friendly_type: Windows friendly file type description
attributes: Windows file attributes (R/H/S/A)
extension_mismatch: True if MIME type doesn't match extension
expected_extensions: Expected extensions for MIME type
is_archive: True if file is an archive
```

### `artifactsleuth.archive.*`
```yaml
parent_path: Path to parent archive if extracted
is_password_protected: True if archive is password-protected
depth: Nested archive extraction depth
```

### `artifactsleuth.document.*`
```yaml
author: Document author
last_modified_by: Last user to modify
title: Document title
subject: Document subject
keywords: Document keywords
created: Document creation date
modified: Document modification date
company: Company from properties
manager: Manager from properties
category: Document category
comments: Document comments
has_macros: True if contains VBA macros
has_javascript: True if contains JavaScript
suspicious_elements: Array of suspicious element identifiers
analysis_error: Error message if analysis failed
```

### `artifactsleuth.pe.*`
```yaml
file_version: PE file version string
suspicious_imports: Array of suspicious API imports
analysis_error: Error message if analysis failed
```

### `artifactsleuth.ioc.*`
```yaml
domains: Array of domains extracted from PE
ips: Array of IP addresses extracted from PE
urls: Array of URLs extracted from PE
```

### `artifactsleuth.virustotal.*`
```yaml
detection_ratio: Detection ratio (e.g., "5/70")
permalink: VirusTotal report URL
error: Error message if lookup failed
```

### `artifactsleuth.defender.*`
```yaml
scanned: True if file was scanned
detected: True if threat detected
threat_name: Defender threat name
error: Error message if scan failed
```

### `artifactsleuth.risk.*`
```yaml
reasons: Array of risk reason strings
```

### `artifactsleuth.scan.*`
```yaml
root_path: Root path of the scan
timestamp: When scan was performed
version: ArtifactSleuth version
```

---

## Field Mapping Reference

| Current Field | ECS Field | Notes |
|--------------|-----------|-------|
| `name` | `file.name` | Direct mapping |
| `path` | `file.path` | Direct mapping |
| `size` | `file.size` | Direct mapping |
| `created_time` | `file.created` | Convert to ISO 8601 |
| `modified_time` | `file.mtime` | Convert to ISO 8601 |
| `accessed_time` | `file.accessed` | Convert to ISO 8601 |
| `mime_type` | `file.mime_type` | Direct mapping |
| `is_directory` | `file.type` | Map to "dir" or "file" |
| `parent_folder` | `file.directory` | Direct mapping |
| `md5` | `file.hash.md5` | Direct mapping |
| `sha1` | `file.hash.sha1` | Direct mapping |
| `sha256` | `file.hash.sha256` | Direct mapping |
| `owner` | `user.name` | Direct mapping |
| `computer` | `host.name` | Direct mapping |
| `exe_company` | `pe.company` | Direct mapping |
| `exe_product` | `pe.product` | Direct mapping |
| `exe_description` | `pe.description` | Direct mapping |
| `is_signed` | `code_signature.exists` | Direct mapping |
| `sig_subject` | `code_signature.subject_name` | Direct mapping |
| `sig_issuer` | `code_signature.issuer_name` | Direct mapping |
| `risk_score` | `event.risk_score` | Direct mapping |
| `relative_path` | `artifactsleuth.file.relative_path` | Custom field |
| `attributes` | `artifactsleuth.file.attributes` | Custom field |
| `friendly_type` | `artifactsleuth.file.friendly_type` | Custom field |
| `doc_author` | `artifactsleuth.document.author` | Custom field |
| `doc_has_macros` | `artifactsleuth.document.has_macros` | Custom field |
| `exe_domains[]` | `artifactsleuth.ioc.domains[]` | Custom field |
| `exe_ips[]` | `artifactsleuth.ioc.ips[]` | Custom field |
| `exe_urls[]` | `artifactsleuth.ioc.urls[]` | Custom field |
| `vt_detection_ratio` | `artifactsleuth.virustotal.detection_ratio` | Custom field |
| `defender_detected` | `artifactsleuth.defender.detected` | Custom field |

---

## Implementation

### Step 1: Add ECS Transformation Method

Add the `to_ecs_dict()` method to the FileInfo class in `analyzer/metadata.py`:

```python
from datetime import datetime
from pathlib import Path
from typing import Dict, Any

def to_ecs_dict(self) -> Dict[str, Any]:
    """
    Transform FileInfo to ECS v9.2.0 normalized dictionary.
    
    Returns nested structure following ECS field hierarchy:
    - file.* - File metadata
    - event.* - Event context
    - threat.* - Threat intelligence
    - pe.* - PE metadata
    - code_signature.* - Digital signatures
    - artifactsleuth.* - Custom forensic fields
    """
    # Start with timestamp
    now = datetime.utcnow().isoformat() + "Z"
    
    # Build ECS document
    ecs_doc = {
        "@timestamp": now,
        "event": {
            "kind": "event",
            "category": ["file"],
            "type": ["info"],
            "action": "artifact-analysis",
            "created": now,
            "dataset": "artifactsleuth.scan",
            "risk_score": self.risk_score
        },
        "file": {
            "name": self.name,
            "path": self.path,
            "size": self.size,
            "extension": Path(self.name).suffix or None,
            "type": "dir" if self.is_directory else "file",
            "mime_type": self.mime_type,
            "directory": self.parent_folder
        }
    }
    
    # Add timestamps if available
    if self.created_time:
        ecs_doc["file"]["created"] = self.created_time.isoformat() + "Z"
    if self.modified_time:
        ecs_doc["file"]["mtime"] = self.modified_time.isoformat() + "Z"
    if self.accessed_time:
        ecs_doc["file"]["accessed"] = self.accessed_time.isoformat() + "Z"
    
    # Add hashes
    if self.md5 or self.sha1 or self.sha256:
        ecs_doc["file"]["hash"] = {}
        if self.md5:
            ecs_doc["file"]["hash"]["md5"] = self.md5
        if self.sha1:
            ecs_doc["file"]["hash"]["sha1"] = self.sha1
        if self.sha256:
            ecs_doc["file"]["hash"]["sha256"] = self.sha256
    
    # Add host information
    if self.computer:
        ecs_doc["host"] = {"name": self.computer}
    
    # Add user information
    if self.owner:
        ecs_doc["user"] = {"name": self.owner}
    
    # Add PE metadata if available
    if self.exe_company or self.exe_product or self.exe_description:
        ecs_doc["pe"] = {}
        if self.exe_company:
            ecs_doc["pe"]["company"] = self.exe_company
        if self.exe_product:
            ecs_doc["pe"]["product"] = self.exe_product
        if self.exe_description:
            ecs_doc["pe"]["description"] = self.exe_description
    
    # Add code signature
    if self.is_signed is not None:
        ecs_doc["code_signature"] = {"exists": self.is_signed}
        if self.sig_subject:
            ecs_doc["code_signature"]["subject_name"] = self.sig_subject
        if self.sig_issuer:
            ecs_doc["code_signature"]["issuer_name"] = self.sig_issuer
    
    # Add threat indicators if detected
    if self.vt_detected or self.defender_detected:
        ecs_doc["threat"] = {"indicator": {}}
        ecs_doc["threat"]["indicator"]["type"] = "file"
        
        # Confidence based on risk score
        if self.risk_score >= 50:
            ecs_doc["threat"]["indicator"]["confidence"] = "High"
        elif self.risk_score >= 25:
            ecs_doc["threat"]["indicator"]["confidence"] = "Medium"
        else:
            ecs_doc["threat"]["indicator"]["confidence"] = "Low"
        
        # Description from VT or Defender
        if self.vt_detected and self.vt_detection_ratio:
            ecs_doc["threat"]["indicator"]["description"] = f"VirusTotal detection: {self.vt_detection_ratio}"
            ecs_doc["threat"]["indicator"]["provider"] = "virustotal"
        elif self.defender_detected and self.defender_threat_name:
            ecs_doc["threat"]["indicator"]["description"] = f"Windows Defender: {self.defender_threat_name}"
            ecs_doc["threat"]["indicator"]["provider"] = "windows-defender"
    
    # Add related fields for correlation
    related = {}
    if self.md5 or self.sha1 or self.sha256:
        related["hash"] = [h for h in [self.md5, self.sha1, self.sha256] if h]
    if self.exe_ips:
        related["ip"] = self.exe_ips
    if self.owner:
        related["user"] = [self.owner]
        if self.doc_author and self.doc_author != self.owner:
            related["user"].append(self.doc_author)
    
    if related:
        ecs_doc["related"] = related
    
    # Add custom artifactsleuth namespace
    artifactsleuth = {}
    
    # File-specific forensics
    artifactsleuth["file"] = {
        "relative_path": self.relative_path
    }
    if self.attributes:
        artifactsleuth["file"]["attributes"] = self.attributes
    if self.friendly_type:
        artifactsleuth["file"]["friendly_type"] = self.friendly_type
    if self.extension_mismatch:
        artifactsleuth["file"]["extension_mismatch"] = self.extension_mismatch
        if self.expected_extensions:
            artifactsleuth["file"]["expected_extensions"] = self.expected_extensions
    if self.is_archive:
        artifactsleuth["file"]["is_archive"] = self.is_archive
    
    # Archive context
    if self.archive_path or self.is_password_protected:
        artifactsleuth["archive"] = {}
        if self.archive_path:
            artifactsleuth["archive"]["parent_path"] = self.archive_path
        if self.is_password_protected:
            artifactsleuth["archive"]["is_password_protected"] = self.is_password_protected
    
    # Document analysis
    if any([self.doc_author, self.doc_title, self.doc_has_macros, self.doc_has_javascript]):
        artifactsleuth["document"] = {}
        if self.doc_author:
            artifactsleuth["document"]["author"] = self.doc_author
        if self.doc_last_modified_by:
            artifactsleuth["document"]["last_modified_by"] = self.doc_last_modified_by
        if self.doc_title:
            artifactsleuth["document"]["title"] = self.doc_title
        if self.doc_subject:
            artifactsleuth["document"]["subject"] = self.doc_subject
        if self.doc_keywords:
            artifactsleuth["document"]["keywords"] = self.doc_keywords
        if self.doc_company:
            artifactsleuth["document"]["company"] = self.doc_company
        if self.doc_has_macros is not None:
            artifactsleuth["document"]["has_macros"] = self.doc_has_macros
        if self.doc_has_javascript is not None:
            artifactsleuth["document"]["has_javascript"] = self.doc_has_javascript
        if self.doc_suspicious_elements:
            artifactsleuth["document"]["suspicious_elements"] = self.doc_suspicious_elements
    
    # PE analysis
    if self.exe_version or self.exe_suspicious_imports:
        if "pe" not in artifactsleuth:
            artifactsleuth["pe"] = {}
        if self.exe_version:
            artifactsleuth["pe"]["file_version"] = self.exe_version
        if self.exe_suspicious_imports:
            artifactsleuth["pe"]["suspicious_imports"] = self.exe_suspicious_imports
    
    # IOCs extracted from PE
    if self.exe_domains or self.exe_ips or self.exe_urls:
        artifactsleuth["ioc"] = {}
        if self.exe_domains:
            artifactsleuth["ioc"]["domains"] = self.exe_domains
        if self.exe_ips:
            artifactsleuth["ioc"]["ips"] = self.exe_ips
        if self.exe_urls:
            artifactsleuth["ioc"]["urls"] = self.exe_urls
    
    # VirusTotal results
    if self.vt_detected is not None or self.vt_detection_ratio or self.vt_link:
        artifactsleuth["virustotal"] = {}
        if self.vt_detection_ratio:
            artifactsleuth["virustotal"]["detection_ratio"] = self.vt_detection_ratio
        if self.vt_link:
            artifactsleuth["virustotal"]["permalink"] = self.vt_link
        if self.vt_error:
            artifactsleuth["virustotal"]["error"] = self.vt_error
    
    # Windows Defender results
    if self.defender_scanned is not None:
        artifactsleuth["defender"] = {
            "scanned": self.defender_scanned
        }
        if self.defender_detected is not None:
            artifactsleuth["defender"]["detected"] = self.defender_detected
        if self.defender_threat_name:
            artifactsleuth["defender"]["threat_name"] = self.defender_threat_name
        if self.defender_error:
            artifactsleuth["defender"]["error"] = self.defender_error
    
    # Risk assessment
    if self.risk_reasons:
        artifactsleuth["risk"] = {
            "reasons": self.risk_reasons
        }
    
    # Add artifactsleuth namespace to document
    if artifactsleuth:
        ecs_doc["artifactsleuth"] = artifactsleuth
    
    return ecs_doc
```

**Explanation:**
- This method transforms the flat FileInfo structure into a nested ECS-compliant document
- It conditionally adds fields only if they have values (keeps output clean)
- Standard ECS fields go under their respective namespaces (file.*, event.*, etc.)
- Custom forensic fields go under artifactsleuth.*
- The method is non-destructive - original FileInfo remains unchanged

### Step 2: Add Flattening Utility

Create a utility function to flatten nested ECS dicts for CSV output in `analyzer/metadata.py`:

```python
def flatten_ecs_dict(nested: Dict[str, Any], prefix: str = "") -> Dict[str, Any]:
    """
    Flatten nested ECS dictionary to dot-notation for CSV output.
    
    Example:
        {"file": {"name": "test.exe", "hash": {"md5": "abc"}}}
        becomes
        {"file.name": "test.exe", "file.hash.md5": "abc"}
    """
    result = {}
    for key, value in nested.items():
        new_key = f"{prefix}.{key}" if prefix else key
        if isinstance(value, dict):
            # Recursively flatten nested dicts
            result.update(flatten_ecs_dict(value, new_key))
        elif isinstance(value, list):
            # Convert lists to strings for CSV
            result[new_key] = value
        else:
            result[new_key] = value
    return result
```

**Explanation:**
- Recursively walks the nested dictionary
- Joins keys with dots to create field paths (e.g., file.hash.md5)
- Preserves lists as-is (will be converted to strings later for CSV)

### Step 3: Update Report Generators

#### JSON Export

Add a new function in `analyzer/report_generator.py`:

```python
import json
from typing import List, Dict, Any
from analyzer.metadata import FileInfo

def generate_json_report(
    files: List[FileInfo],
    summary: Dict[str, Any],
    output_path: str,
    scan_path: str
) -> None:
    """
    Generate ECS v9.2.0 normalized JSON report.
    """
    ecs_docs = [file_info.to_ecs_dict() for file_info in files]
    
    output = {
        "scan_metadata": {
            "scan_path": scan_path,
            "total_artifacts": len(files),
            "ecs_version": "9.2.0"
        },
        "artifacts": ecs_docs
    }
    
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(output, f, indent=2, default=str)
```

**Explanation:**
- Transforms all FileInfo objects to ECS format
- Wraps them in a top-level document with scan metadata
- Outputs pure ECS-compliant JSON

#### CSV Export

Update `generate_csv_report()` in `analyzer/report_generator.py` to output ECS format:

```python
def generate_csv_report(
    files: List[FileInfo],
    summary: Dict[str, Any],
    output_path: str
) -> None:
    """
    Generate ECS v9.2.0 normalized CSV with flattened fields.
    """
    from analyzer.metadata import flatten_ecs_dict
    
    # Define ECS column order (most important fields first)
    fieldnames = [
        '@timestamp',
        'event.kind', 'event.category', 'event.action', 'event.risk_score',
        'file.name', 'file.path', 'file.size', 'file.extension', 'file.mime_type',
        'file.created', 'file.mtime', 'file.type',
        'file.hash.md5', 'file.hash.sha1', 'file.hash.sha256',
        'host.name', 'user.name',
        'pe.company', 'pe.product', 'pe.description',
        'code_signature.exists', 'code_signature.subject_name',
        'threat.indicator.confidence', 'threat.indicator.provider',
        'artifactsleuth.file.relative_path',
        'artifactsleuth.file.attributes',
        'artifactsleuth.file.friendly_type',
        'artifactsleuth.file.extension_mismatch',
        'artifactsleuth.document.has_macros',
        'artifactsleuth.document.has_javascript',
        'artifactsleuth.ioc.domains',
        'artifactsleuth.ioc.ips',
        'artifactsleuth.ioc.urls',
        'artifactsleuth.virustotal.detection_ratio',
        'artifactsleuth.virustotal.permalink',
        'artifactsleuth.defender.detected',
        'artifactsleuth.defender.threat_name',
        'artifactsleuth.risk.reasons',
    ]
    
    with open(output_path, 'w', newline='', encoding='utf-8-sig') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
        writer.writeheader()
        
        for file_info in files:
            ecs_doc = file_info.to_ecs_dict()
            flattened = flatten_ecs_dict(ecs_doc)
            
            # Convert lists to semicolon-delimited strings for CSV
            for key, value in flattened.items():
                if isinstance(value, list):
                    flattened[key] = '; '.join(str(v) for v in value)
            
            writer.writerow(flattened)
```

**Explanation:**
- Uses flatten_ecs_dict() to convert nested ECS to flat structure
- Orders columns with most important fields first
- Converts arrays to semicolon-delimited strings for CSV compatibility

#### HTML Report

Modify `generate_html_report()` to embed ECS JSON in `analyzer/report_generator.py`:

```python
def generate_html_report(
    files: List[FileInfo],
    summary: Dict[str, Any],
    output_path: str,
    scan_path: str
) -> None:
    """
    Generate HTML report with ECS-normalized data.
    """
    # Existing HTML generation code...
    
    # Transform to ECS format for embedding
    files_data = [f.to_ecs_dict() for f in files]
    files_json = json.dumps(files_data, separators=(',', ':'), default=str)
    
    # Embed in HTML template...
```

**Explanation:**
- Always embeds ECS-normalized JSON for client-side rendering
- JavaScript in HTML will work with ECS field structure

### Step 4: Update Report Generation in main.py

Modify `main.py` to use ECS generators:

```python
def main():
    parser = argparse.ArgumentParser(...)
    
    # ... existing arguments (no --ecs-mode flag needed) ...
    
    args = parser.parse_args()
    
    # ... existing scan logic ...
    
    # Generate report with ECS format
    if args.format == 'json':
        generate_json_report(files, summary, output_path, scan_path)
    elif args.format == 'csv':
        generate_csv_report(files, summary, output_path)
    elif args.format == 'html':
        generate_html_report(files, summary, output_path, scan_path)
```

**Explanation:**
- Always uses ECS format for all output types
- No flag needed - ECS is the only mode
- Simplified logic without conditional branching

---

## Usage Examples

### JSON Output
```bash
python main.py /path/to/usb --format json --output report.json
```

### CSV Output
```bash
python main.py /path/to/usb --format csv --output report.csv
```

### HTML Output (default)
```bash
python main.py /path/to/usb --output report.html
```

---

## Example ECS Output

**Nested JSON structure:**
```json
{
  "@timestamp": "2026-01-27T08:00:00.000Z",
  "event": {
    "kind": "event",
    "category": ["file"],
    "type": ["info"],
    "action": "artifact-analysis",
    "created": "2026-01-27T08:00:00.000Z",
    "dataset": "artifactsleuth.scan",
    "risk_score": 75
  },
  "file": {
    "name": "suspicious.exe",
    "path": "C:\\Users\\Alice\\Downloads\\suspicious.exe",
    "size": 524288,
    "extension": ".exe",
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
    "company": "Suspicious Corp",
    "product": "BadApp"
  },
  "code_signature": {
    "exists": false
  },
  "threat": {
    "indicator": {
      "type": "file",
      "confidence": "High",
      "description": "VirusTotal detection: 45/70",
      "provider": "virustotal"
    }
  },
  "related": {
    "hash": ["5d41402abc4b2a76b9719d911017c592", "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d", "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae"],
    "ip": ["192.168.1.100"],
    "user": ["Alice"]
  },
  "artifactsleuth": {
    "file": {
      "relative_path": "Downloads\\suspicious.exe",
      "attributes": "A"
    },
    "ioc": {
      "domains": ["malicious.example.com"],
      "ips": ["192.168.1.100"]
    },
    "virustotal": {
      "detection_ratio": "45/70",
      "permalink": "https://www.virustotal.com/gui/file/2c26b46b..."
    },
    "risk": {
      "reasons": [
        "VT detected (45/70 engines)",
        "Not digitally signed",
        "Suspicious imports detected"
      ]
    }
  }
}
```

**Flattened CSV structure:**
```csv
@timestamp,event.kind,event.risk_score,file.name,file.path,file.hash.md5,file.hash.sha256,pe.company,code_signature.exists,artifactsleuth.virustotal.detection_ratio,artifactsleuth.risk.reasons
2026-01-27T08:00:00Z,event,75,suspicious.exe,C:\Users\Alice\Downloads\suspicious.exe,5d41402abc4b2a76b9719d911017c592,2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae,Suspicious Corp,false,45/70,"VT detected (45/70 engines); Not digitally signed; Suspicious imports detected"
```

---

## Testing

### Unit Tests

Create `tests/test_ecs_normalization.py`:

```python
import unittest
from datetime import datetime
from analyzer.metadata import FileInfo, flatten_ecs_dict

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
        ecs = self.file_info.to_ecs_dict()
        self.assertEqual(ecs["file"]["name"], "test.exe")
    
    def test_hash_nesting(self):
        ecs = self.file_info.to_ecs_dict()
        self.assertEqual(ecs["file"]["hash"]["md5"], "d41d8cd98f00b204e9800998ecf8427e")
    
    def test_event_fields(self):
        ecs = self.file_info.to_ecs_dict()
        self.assertEqual(ecs["event"]["kind"], "event")
        self.assertEqual(ecs["event"]["category"], ["file"])
    
    def test_custom_namespace(self):
        self.file_info.attributes = "R"
        ecs = self.file_info.to_ecs_dict()
        self.assertEqual(ecs["artifactsleuth"]["file"]["attributes"], "R")
    
    def test_flattening(self):
        nested = {"file": {"name": "test", "hash": {"md5": "abc"}}}
        flat = flatten_ecs_dict(nested)
        self.assertEqual(flat["file.name"], "test")
        self.assertEqual(flat["file.hash.md5"], "abc")
```

### Integration Test

```python
def test_full_ecs_transformation(self):
    # Create a fully populated FileInfo
    file_info = FileInfo(
        name="malware.exe",
        path="/tmp/malware.exe",
        # ... all fields ...
    )
    
    # Transform to ECS
    ecs = file_info.to_ecs_dict()
    
    # Validate ECS structure
    assert "@timestamp" in ecs
    assert "event" in ecs
    assert "file" in ecs
    assert "artifactsleuth" in ecs
    
    # Validate can be flattened for CSV
    flat = flatten_ecs_dict(ecs)
    assert "file.name" in flat
    assert "file.hash.sha256" in flat
```

---

## References

- **ECS v9.2.0 Documentation**: https://www.elastic.co/guide/en/ecs/current/index.html
- **ECS Field Reference**: https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html
- **ECS GitHub**: https://github.com/elastic/ecs

---

*Implementation guide for ArtifactSleuth hobby project*
