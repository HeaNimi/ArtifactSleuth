# ArtifactSleuth

**WARNING! This whole tool is vibe coded, before use take time to read through the code because i don't give warranty if it breaks your systems.**

ArtifactSleuth is a Python forensic scanner for removable media. It crawls folders and archives, extracts file intelligence, and produces investigator-friendly HTML or CSV reports with hashes, indicators, and optional VirusTotal enrichment.

## Highlights

- Recursive analysis of folders and archives (ZIP, 7z, RAR, TAR, GZ)
- Hashing (MD5, SHA1, SHA256) with optional VirusTotal lookups
- Document triage for PDF and Office files (macros, scripts, suspicious elements)
- PE analysis for executables (domains, IPs, suspicious imports)
- Reports in HTML (light/dark toggle) or CSV

## Installation

```bash
cd c:\Code\ArtifactSleuth
pip install -r requirements.txt
```

## Quick Start

```bash
python main.py /path/to/usb --output report.html
```

## Report Preview

![ArtifactSleuth report preview](docs/web_report_example.png)

## Usage Examples

Basic scan (no VirusTotal):
```bash
python main.py /path/to/usb --output report.html
```

VirusTotal (free tier, 4 lookups/min):
```bash
python main.py /path/to/usb --vt-key YOUR_API_KEY --output report.html
```

VirusTotal (premium tier, 500 lookups/min):
```bash
python main.py /path/to/usb --vt-key YOUR_API_KEY --vt-rate 500 --output report.html
```

CSV output:
```bash
python main.py /path/to/usb --format csv --output report.csv
```

ECS (Elastic Common Schema) JSON output for SIEM integration:
```bash
python main.py /path/to/usb --format ecs --output report.json
```

ECS JSON Lines output for bulk ingestion to Elasticsearch:
```bash
python main.py /path/to/usb --format jsonl --output report.jsonl
```

Skip VirusTotal lookups:
```bash
python main.py /path/to/usb --no-vt --output report.html
```

Enable file logging:
```bash
python main.py /path/to/usb --log scan_errors.log --output report.html
```

Exclude specific archive types from extraction:
```bash
python main.py /path/to/usb --exclude-archives .apk,.jar --output report.html
```

## What Gets Reported

- Extended metadata: owner, attributes (R/H/S/A), friendly type, computer name
- Digital signatures: Authenticode verification for executables
- File hashes: MD5, SHA1, SHA256
- VirusTotal results: detection ratio and report link
- Document analysis: macros, JavaScript, suspicious elements
- Executable analysis: extracted domains, IPs, suspicious imports
- Archive contents: recursive analysis with full path tracking

## Command Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `path` | Path to scan (folder or file) | Required |
| `--output`, `-o` | Output file path | `report.html` |
| `--format`, `-f` | Output format (`html`, `csv`, `ecs`, or `jsonl`) | `html` |
| `--log` | Log file path (enables detailed logging) | None |
| `-v`, `--verbose` | Verbose mode - show detailed logging of file analysis | False |
| `--defender` | Scan files with Windows Defender for malware detection | False |
| `--vt-key` | VirusTotal API key | None |
| `--vt-rate` | VirusTotal rate limit (lookups/min) | 4 |
| `--no-vt` | Skip VirusTotal lookups | False |
| `--no-hash` | Skip file hashing (faster scan) | False |
| `--max-archive-depth` | Max nested archive extraction depth | 5 |
| `--exclude-archives` | Comma-separated archive extensions to skip (e.g., `.apk,.jar,.aar`) | None |
| `--split-report` | Split HTML report into N files each | 0 (disabled) |
| `--quiet`, `-q` | Minimal output | False |

### Windows Defender Scanning

Use `--defender` to scan files with Windows Defender (Windows only):

```bash
python main.py E:\ --defender --output report.html
```

**Features:**
- Uses built-in Windows Defender (`MpCmdRun.exe`) for malware scanning
- Detects threats without quarantining (read-only scan)
- Results appear in the HTML report detail panel
- Defender detections add +60 to risk score
- Scans files on disk (extracted archive contents not scanned after cleanup)

**Requirements:**
- Windows OS with Windows Defender enabled
- Administrator privileges not required for basic scanning

**Note:** Files inside archives are only scanned during extraction. If you need to scan all archive contents, extract them first to a folder.

### Verbose Mode

Use `-v` or `--verbose` to see detailed logging during scan:

```bash
python main.py E:\ -v --no-vt
```

This shows:
- Directory scanning progress (`[DIR]` entries)
- Each file scanned (`[SCAN]` with size and MIME type)
- Archive extraction progress (`[EXTRACT]`)
- PE/Document analysis results (`[ANALYZE]`)
- IOC findings (domains, IPs, URLs, suspicious imports)

### Split Report Option

For very large scans (100k+ files), use `--split-report` to generate multiple HTML files:

```bash
# Split into reports with 50,000 files each
python main.py E:\ --output report.html --split-report 50000
```

**Output:**
- `report_1.html` (files 1-50,000)
- `report_2.html` (files 50,001-100,000)
- etc.

Each report is self-contained with:
- Part indicator in header (e.g., "Part 1 of 3")
- Navigation links to other parts
- Full search/filter functionality within that part
- Independent pagination

**When to use:**
- Browser becomes slow/unresponsive with large reports
- Files exceed 500k+ (recommended: `--split-report 100000`)
- Need to share portions of a large scan

### ECS Integration (SIEM / Elasticsearch)

ArtifactSleuth supports **Elastic Common Schema (ECS)** output for seamless integration with Elasticsearch, Logstash, Kibana, and other SIEM platforms.

**Generate ECS JSON report:**
```bash
python main.py /path/to/usb --format ecs --output report.json
```

**Generate ECS JSON Lines for bulk ingestion:**
```bash
python main.py /path/to/usb --format jsonl --output report.jsonl
```

**Features:**
- **Standards-compliant**: Conforms to ECS 8.x specification
- **SIEM-ready**: Direct ingestion into Elasticsearch without transformation
- **Rich context**: File metadata, hashes, IOCs, threat intelligence all in ECS format
- **Custom namespace**: ArtifactSleuth-specific fields in `artifactsleuth.*` namespace

**Use cases:**
- Centralized forensic analysis across multiple scans
- Long-term storage and correlation with security events
- Building detection rules and dashboards in Kibana
- Integration with SOAR platforms

**Ingesting to Elasticsearch:**
```bash
# Using curl to bulk ingest JSONL
curl -X POST "localhost:9200/_bulk" -H 'Content-Type: application/x-ndjson' --data-binary @report.jsonl

# Using Logstash
input {
  file {
    path => "/path/to/report.jsonl"
    codec => "json_lines"
  }
}
output {
  elasticsearch {
    hosts => ["localhost:9200"]
    index => "artifactsleuth-%{+YYYY.MM.dd}"
  }
}
```

See `docs/ECS_NORMALIZATION_PLAN.md` for detailed field mappings and examples.
- Full search/filter functionality within that part
- Independent pagination

**When to use:**
- Browser becomes slow/unresponsive with large reports
- Files exceed 500k+ (recommended: `--split-report 100000`)
- Need to share portions of a large scan
