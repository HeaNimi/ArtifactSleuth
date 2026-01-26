# ArtifactSleuth ECS Normalization Quick Reference

**Version:** 1.0  
**ECS Version:** 9.2.0  
**Related:** [Full Implementation Plan](ECS_NORMALIZATION_PLAN.md)

---

## Overview

This quick reference provides a condensed view of the ECS v9.2.0 normalization plan for ArtifactSleuth developers and contributors.

---

## Key Design Decisions

1. **Dual-Mode Output**: Support both legacy and ECS formats via `--ecs-mode` flag
2. **Custom Namespace**: Use `artifactsleuth.*` for forensic-specific fields
3. **Nested JSON, Flat CSV**: JSON uses nested ECS structure, CSV uses flattened dot-notation
4. **Backward Compatible**: Legacy format remains default in v1.x
5. **Phased Rollout**: 6 phases over 8-9 weeks

---

## Field Mapping Summary

### Core ECS Fieldsets Used

| Fieldset | Usage | Priority |
|----------|-------|----------|
| `file.*` | File metadata, hashes | High |
| `event.*` | Scan context, risk scoring | High |
| `threat.*` | VT detections, indicators | High |
| `pe.*` | PE executable metadata | Medium |
| `code_signature.*` | Digital signatures | Medium |
| `host.*` | Computer name | Low |
| `user.*` | File owner, doc author | Low |
| `related.*` | Cross-references (hashes, IPs, users) | Low |

### Top 20 Most Important Field Mappings

| Current Field | ECS Field | Type |
|--------------|-----------|------|
| `name` | `file.name` | Core |
| `path` | `file.path` | Core |
| `size` | `file.size` | Core |
| `md5` | `file.hash.md5` | Core |
| `sha1` | `file.hash.sha1` | Core |
| `sha256` | `file.hash.sha256` | Core |
| `created_time` | `file.created` | Core |
| `modified_time` | `file.mtime` | Core |
| `mime_type` | `file.mime_type` | Core |
| `risk_score` | `event.risk_score` | Core |
| `owner` | `user.name` | ECS |
| `computer` | `host.name` | ECS |
| `exe_company` | `pe.company` | ECS |
| `is_signed` | `code_signature.exists` | ECS |
| `sig_subject` | `code_signature.subject_name` | ECS |
| `relative_path` | `artifactsleuth.file.relative_path` | Custom |
| `attributes` | `artifactsleuth.file.attributes` | Custom |
| `vt_detection_ratio` | `artifactsleuth.virustotal.detection_ratio` | Custom |
| `doc_has_macros` | `artifactsleuth.document.has_macros` | Custom |
| `exe_domains[]` | `artifactsleuth.ioc.domains[]` | Custom |

---

## Custom Namespace Structure

```
artifactsleuth.*
├── file.*               # File-specific forensics
│   ├── relative_path
│   ├── friendly_type
│   ├── attributes
│   ├── extension_mismatch
│   └── is_archive
├── archive.*            # Archive context
│   ├── parent_path
│   ├── is_password_protected
│   └── depth
├── document.*           # Document analysis
│   ├── author, title, subject
│   ├── has_macros
│   ├── has_javascript
│   └── suspicious_elements[]
├── pe.*                 # PE forensics
│   ├── file_version
│   ├── suspicious_imports[]
│   └── analysis_error
├── ioc.*                # Extracted indicators
│   ├── domains[]
│   ├── ips[]
│   └── urls[]
├── virustotal.*         # VT results
│   ├── detection_ratio
│   ├── permalink
│   └── error
├── defender.*           # Windows Defender
│   ├── scanned, detected
│   ├── threat_name
│   └── error
├── risk.*               # Risk assessment
│   └── reasons[]
└── scan.*               # Scan metadata
    ├── root_path
    ├── timestamp
    └── version
```

---

## Implementation Checklist

### Phase 1: Core ECS (Weeks 1-2)
- [ ] Add `to_ecs_dict()` to `FileInfo`
- [ ] Implement `file.*` mapping
- [ ] Implement `hash.*` mapping
- [ ] Implement `event.*` context
- [ ] Create `flatten_ecs_dict()` utility
- [ ] Unit tests (>80% coverage)

### Phase 2: Threat Intel & PE (Weeks 3-4)
- [ ] Map `threat.*` fields (VT/Defender)
- [ ] Map `pe.*` fields
- [ ] Map `code_signature.*`
- [ ] Map `artifactsleuth.ioc.*`
- [ ] Update CSV generator
- [ ] Integration tests

### Phase 3: Document & Custom (Weeks 5-6)
- [ ] Map `artifactsleuth.document.*`
- [ ] Map `artifactsleuth.archive.*`
- [ ] Map `artifactsleuth.risk.*`
- [ ] Update HTML (ECS JSON embed)
- [ ] Add ECS/Legacy UI toggle

### Phase 4: CLI & Compat (Week 7)
- [ ] Add `--ecs-mode` flag
- [ ] Preserve legacy mode
- [ ] Create migration guide
- [ ] Performance testing

### Phase 5: Validation (Week 8)
- [ ] ECS validator
- [ ] Full test suite (>85% coverage)
- [ ] SIEM examples (Elastic, Splunk)
- [ ] Documentation updates

### Phase 6: Release (Week 9+)
- [ ] v1.x release with opt-in ECS
- [ ] Collect user feedback
- [ ] Bug fixes
- [ ] Plan v2.0 (ECS default)

---

## Code Examples

### Adding ECS Support to FileInfo

```python
# In analyzer/metadata.py

def to_ecs_dict(self) -> Dict[str, Any]:
    """Transform to ECS v9.2.0 format"""
    return {
        "@timestamp": datetime.utcnow().isoformat() + "Z",
        "event": {
            "kind": "event",
            "category": ["file"],
            "type": ["info"],
            "action": "artifact-analysis",
            "created": datetime.utcnow().isoformat() + "Z",
            "dataset": "artifactsleuth.scan",
            "risk_score": self.risk_score
        },
        "file": {
            "name": self.name,
            "path": self.path,
            "size": self.size,
            "extension": Path(self.name).suffix or None,
            "created": self.created_time.isoformat() + "Z" if self.created_time else None,
            "mtime": self.modified_time.isoformat() + "Z" if self.modified_time else None,
            "accessed": self.accessed_time.isoformat() + "Z" if self.accessed_time else None,
            "type": "dir" if self.is_directory else "file",
            "mime_type": self.mime_type,
            "directory": self.parent_folder,
            "hash": {
                "md5": self.md5,
                "sha1": self.sha1,
                "sha256": self.sha256
            }
        },
        "artifactsleuth": {
            "file": {
                "relative_path": self.relative_path,
                "attributes": self.attributes,
                "friendly_type": self.friendly_type
            }
        }
    }
```

### Flattening for CSV

```python
def flatten_ecs_dict(nested: Dict[str, Any], prefix: str = "") -> Dict[str, Any]:
    """Flatten nested ECS dict to dot-notation for CSV"""
    result = {}
    for key, value in nested.items():
        new_key = f"{prefix}.{key}" if prefix else key
        if isinstance(value, dict):
            result.update(flatten_ecs_dict(value, new_key))
        else:
            result[new_key] = value
    return result
```

---

## Testing Strategy

### Unit Tests
```python
# tests/test_ecs_normalization.py

def test_file_name_mapping():
    file_info = FileInfo(name="test.exe", ...)
    ecs = file_info.to_ecs_dict()
    assert ecs["file"]["name"] == "test.exe"

def test_hash_nesting():
    file_info = FileInfo(sha256="abc123", ...)
    ecs = file_info.to_ecs_dict()
    assert ecs["file"]["hash"]["sha256"] == "abc123"

def test_custom_namespace():
    file_info = FileInfo(attributes="R", ...)
    ecs = file_info.to_ecs_dict()
    assert ecs["artifactsleuth"]["file"]["attributes"] == "R"
```

### Integration Tests
- Full scan test with ECS output
- CSV export validation
- HTML report ECS mode validation
- Backward compatibility test

---

## CLI Usage

### Enable ECS Mode (v1.x)
```bash
# Generate ECS-normalized JSON
python main.py /path/to/usb --ecs-mode --output report.json

# Generate ECS-normalized CSV
python main.py /path/to/usb --ecs-mode --format csv --output report.csv

# Generate HTML with ECS embedded JSON
python main.py /path/to/usb --ecs-mode --output report.html
```

### Legacy Mode (v1.x default)
```bash
# Uses original field names
python main.py /path/to/usb --output report.csv
```

---

## SIEM Integration Examples

### Elastic (Filebeat)
```yaml
# filebeat.yml
filebeat.inputs:
- type: log
  paths:
    - /var/log/artifactsleuth/*.json
  json.keys_under_root: true
  json.add_error_key: true

output.elasticsearch:
  hosts: ["localhost:9200"]
  index: "artifactsleuth-%{+yyyy.MM.dd}"
```

### Splunk
```bash
# props.conf
[artifactsleuth:ecs]
INDEXED_EXTRACTIONS = json
KV_MODE = json
TIMESTAMP_FIELDS = @timestamp
```

---

## Validation

### ECS Validator
```python
from analyzer.ecs_validator import validate_ecs_document

ecs_doc = file_info.to_ecs_dict()
errors = validate_ecs_document(ecs_doc)

if errors:
    print("Validation errors:")
    for error in errors:
        print(f"  - {error}")
else:
    print("✓ Valid ECS v9.2.0 document")
```

---

## Migration Path

| Version | ECS Support | Default Mode | Legacy Support |
|---------|-------------|--------------|----------------|
| v1.0-1.x | Opt-in via `--ecs-mode` | Legacy | Yes (default) |
| v2.0 | Default | ECS | Yes (via `--legacy-mode`) |
| v3.0+ | Only | ECS | No |

---

## Resources

- **Full Plan:** [ECS_NORMALIZATION_PLAN.md](ECS_NORMALIZATION_PLAN.md)
- **ECS Docs:** https://www.elastic.co/guide/en/ecs/current/index.html
- **ECS GitHub:** https://github.com/elastic/ecs
- **Field Reference:** https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html

---

## Key Metrics

- **Total Fields Mapped:** 70+
- **ECS Fieldsets Used:** 8
- **Custom Fields:** 50+
- **Implementation Time:** 8-9 weeks
- **Estimated Effort:** 160-180 hours
- **Test Coverage Target:** >85%

---

*Last Updated: 2026-01-26*  
*Document Version: 1.0*
