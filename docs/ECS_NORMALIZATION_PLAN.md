# ECS Normalization Plan for ArtifactSleuth

## Overview

This document outlines the plan to normalize ArtifactSleuth's forensic scan output to conform to the **Elastic Common Schema (ECS)** standard. ECS provides a standardized way to structure event data, making it compatible with Elastic Stack (Elasticsearch, Logstash, Kibana) and other SIEM platforms.

## Goals

1. Enable seamless integration with Elastic Stack for centralized forensic analysis
2. Maintain backward compatibility with existing HTML/CSV output formats
3. Provide ECS-compliant JSON output for ingestion into security platforms
4. Standardize field naming and data types according to ECS conventions

## ECS Version

This implementation targets **ECS 8.x** specification.

## Field Mapping

### File Fields (ECS: `file.*`)

| ArtifactSleuth Field | ECS Field | ECS Type | Notes |
|---------------------|-----------|----------|-------|
| `name` | `file.name` | keyword | File name without path |
| `path` | `file.path` | keyword | Full path to the file |
| `size` | `file.size` | long | Size in bytes |
| `created_time` | `file.created` | date | ISO 8601 format |
| `modified_time` | `file.mtime` | date | Last modification time |
| `accessed_time` | `file.accessed` | date | Last access time |
| `mime_type` | `file.mime_type` | keyword | MIME type |
| `extension` (derived) | `file.extension` | keyword | File extension without dot |
| `owner` | `file.owner` | keyword | File owner |
| `permissions` | `file.attributes` | keyword | File attributes (R/H/S/A on Windows) |

### Hash Fields (ECS: `file.hash.*`)

| ArtifactSleuth Field | ECS Field | ECS Type | Notes |
|---------------------|-----------|----------|-------|
| `md5` | `file.hash.md5` | keyword | MD5 hash |
| `sha1` | `file.hash.sha1` | keyword | SHA-1 hash |
| `sha256` | `file.hash.sha256` | keyword | SHA-256 hash |

### PE/Executable Fields (ECS: `file.pe.*`)

| ArtifactSleuth Field | ECS Field | ECS Type | Notes |
|---------------------|-----------|----------|-------|
| `exe_company` | `file.pe.company` | keyword | PE company name |
| `exe_product` | `file.pe.product` | keyword | PE product name |
| `exe_description` | `file.pe.description` | keyword | PE description |
| `exe_version` | `file.pe.file_version` | keyword | PE file version |
| `exe_company` (alt) | `file.code_signature.subject_name` | keyword | When digitally signed |
| `is_signed` | `file.code_signature.exists` | boolean | Digital signature present |
| `sig_subject` | `file.code_signature.subject_name` | keyword | Certificate subject |
| `sig_issuer` | `file.code_signature.trusted` | boolean | Certificate issuer validity |

### Host/Computer Fields (ECS: `host.*`)

| ArtifactSleuth Field | ECS Field | ECS Type | Notes |
|---------------------|-----------|----------|-------|
| `computer` | `host.name` | keyword | Computer/hostname |

### Event Metadata (ECS: `event.*`)

| ArtifactSleuth Field | ECS Field | ECS Type | Notes |
|---------------------|-----------|----------|-------|
| N/A (new) | `event.kind` | keyword | Always "event" |
| N/A (new) | `event.category` | keyword | Always ["file"] |
| N/A (new) | `event.type` | keyword | Always ["info"] |
| N/A (new) | `event.dataset` | keyword | "artifactsleuth.file" |
| N/A (scan time) | `event.created` | date | When the scan occurred |
| `risk_score` | `event.risk_score` | float | Normalized 0-100 |

### Threat Intelligence (ECS: `threat.*`)

| ArtifactSleuth Field | ECS Field | ECS Type | Notes |
|---------------------|-----------|----------|-------|
| `vt_detected` | `threat.indicator.marking.tlp` | keyword | VirusTotal detection status |
| `vt_detection_ratio` | `threat.enrichments[].matched.atomic` | keyword | Detection ratio (e.g., "3/70") |
| `vt_link` | `threat.enrichments[].indicator.reference` | keyword | VirusTotal report URL |
| `defender_detected` | `threat.indicator.type` | keyword | "file" if detected |
| `defender_threat_name` | `threat.indicator.description` | keyword | Threat name from Defender |

### Document Fields (Custom namespace: `document.*`)

Since ECS doesn't have native Office document fields, we'll use a custom namespace:

| ArtifactSleuth Field | ECS Field | ECS Type | Notes |
|---------------------|-----------|----------|-------|
| `doc_author` | `artifactsleuth.document.author` | keyword | Document author |
| `doc_last_modified_by` | `artifactsleuth.document.last_modified_by` | keyword | Last modifier |
| `doc_title` | `artifactsleuth.document.title` | keyword | Document title |
| `doc_subject` | `artifactsleuth.document.subject` | keyword | Document subject |
| `doc_company` | `artifactsleuth.document.company` | keyword | Document company |
| `doc_has_macros` | `artifactsleuth.document.has_macros` | boolean | Macro presence |
| `doc_has_javascript` | `artifactsleuth.document.has_javascript` | boolean | JavaScript presence |
| `doc_suspicious_elements` | `artifactsleuth.document.suspicious_elements` | keyword[] | Suspicious elements |

### Indicators of Compromise (ECS: `related.*` + custom)

| ArtifactSleuth Field | ECS Field | ECS Type | Notes |
|---------------------|-----------|----------|-------|
| `exe_domains` | `related.domains` | keyword[] | Extracted domains |
| `exe_ips` | `related.ip` | ip[] | Extracted IP addresses |
| `exe_urls` | `artifactsleuth.ioc.urls` | keyword[] | Extracted URLs |
| `exe_suspicious_imports` | `artifactsleuth.ioc.suspicious_imports` | keyword[] | Suspicious imports |

### Archive Fields (Custom namespace)

| ArtifactSleuth Field | ECS Field | ECS Type | Notes |
|---------------------|-----------|----------|-------|
| `is_archive` | `artifactsleuth.archive.is_archive` | boolean | Is archive file |
| `is_password_protected` | `artifactsleuth.archive.is_password_protected` | boolean | Password protected |
| `archive_path` | `artifactsleuth.archive.parent_path` | keyword | Parent archive path |

### Risk Assessment (Custom namespace)

| ArtifactSleuth Field | ECS Field | ECS Type | Notes |
|---------------------|-----------|----------|-------|
| `risk_score` | `event.risk_score` | float | Also in event.risk_score |
| `risk_reasons` | `artifactsleuth.risk.reasons` | keyword[] | Risk reasons |
| `extension_mismatch` | `artifactsleuth.risk.extension_mismatch` | boolean | MIME/extension mismatch |
| `expected_extensions` | `artifactsleuth.risk.expected_extensions` | keyword | Expected extensions |

## Implementation Phases

### Phase 1: Create ECS Output Format ✓
- [x] Create this normalization plan document
- [ ] Implement `to_ecs()` method in `FileInfo` class
- [ ] Create `generate_ecs_report()` function in `report_generator.py`
- [ ] Add JSON Lines (JSONL) output for bulk ingestion

### Phase 2: Command-Line Integration
- [ ] Add `--format ecs` option to main.py
- [ ] Add `--format jsonl` for ECS JSON Lines output
- [ ] Support combined outputs (e.g., both HTML and ECS)

### Phase 3: Testing & Validation
- [ ] Test ECS output against ECS schema validator
- [ ] Verify Elasticsearch ingestion compatibility
- [ ] Create example ECS output in documentation
- [ ] Test with various file types (PE, PDF, Office, archives)

### Phase 4: Documentation
- [ ] Update README.md with ECS output examples
- [ ] Create integration guide for Elasticsearch/Logstash
- [ ] Document ECS field mappings in detail
- [ ] Add Kibana dashboard templates (optional)

## Example ECS Output

```json
{
  "@timestamp": "2026-01-31T14:00:00.000Z",
  "event": {
    "kind": "event",
    "category": ["file"],
    "type": ["info"],
    "dataset": "artifactsleuth.file",
    "created": "2026-01-31T14:00:00.000Z",
    "risk_score": 75
  },
  "file": {
    "name": "suspicious.exe",
    "path": "/mnt/usb/files/suspicious.exe",
    "extension": "exe",
    "size": 245760,
    "created": "2025-12-15T10:30:00.000Z",
    "mtime": "2025-12-20T14:45:00.000Z",
    "accessed": "2026-01-31T13:55:00.000Z",
    "mime_type": "application/x-dosexec",
    "owner": "DESKTOP-ABC\\User",
    "hash": {
      "md5": "d41d8cd98f00b204e9800998ecf8427e",
      "sha1": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
      "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    },
    "pe": {
      "company": "Evil Corp",
      "product": "Malware Toolkit",
      "description": "Suspicious Tool",
      "file_version": "1.0.0.0"
    },
    "code_signature": {
      "exists": false
    }
  },
  "host": {
    "name": "DESKTOP-ABC"
  },
  "related": {
    "domains": ["malicious.example.com", "c2server.net"],
    "ip": ["192.0.2.100", "203.0.113.50"]
  },
  "threat": {
    "enrichments": [
      {
        "indicator": {
          "reference": "https://www.virustotal.com/gui/file/e3b0c44...",
          "type": "file"
        },
        "matched": {
          "atomic": "15/70"
        }
      }
    ]
  },
  "artifactsleuth": {
    "risk": {
      "reasons": [
        "Unsigned executable",
        "Suspicious imports: VirtualAllocEx",
        "Network indicators: 2 domains, 2 IPs",
        "VirusTotal: 15/70 detections"
      ],
      "extension_mismatch": false
    },
    "ioc": {
      "suspicious_imports": ["VirtualAllocEx", "CreateRemoteThread"],
      "urls": ["http://malicious.example.com/payload"]
    }
  }
}
```

## Benefits of ECS Normalization

1. **SIEM Integration**: Direct ingestion into Elasticsearch, Splunk, and other platforms
2. **Standardization**: Consistent field naming across security tools
3. **Correlation**: Easy correlation with other ECS-compliant security events
4. **Dashboards**: Pre-built Kibana dashboards for ECS data
5. **Detection Rules**: Compatible with SIEM detection rules expecting ECS format
6. **Data Retention**: Structured data for long-term storage and analysis

## Backward Compatibility

- Existing HTML and CSV output formats remain unchanged
- ECS output is an additional format option
- All existing command-line options continue to work
- Original field names available in custom `artifactsleuth.*` namespace

## Future Enhancements

- **Logstash Pipeline**: Pre-configured pipeline for ArtifactSleuth → Elasticsearch
- **Kibana Dashboards**: Pre-built dashboards for forensic analysis
- **ECS Templates**: Elasticsearch index templates for optimal storage
- **Enrichment**: Additional threat intelligence enrichment in ECS format
- **Bulk Processing**: Optimized JSONL output for bulk ingestion

## References

- [Elastic Common Schema Documentation](https://www.elastic.co/guide/en/ecs/current/index.html)
- [ECS Field Reference](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html)
- [ECS GitHub Repository](https://github.com/elastic/ecs)
