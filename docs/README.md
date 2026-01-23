# ArtifactSleuth Documentation

ArtifactSleuth is a Python forensic scanner for removable media and file collections. It crawls folders and archives, extracts file intelligence, and produces HTML or CSV reports with metadata, hashes, and optional VirusTotal enrichment.

## How It Works (High Level)

1. **Scan**: Walks the target path and inspects archives (ZIP, 7z, RAR, TAR, GZ) recursively.
2. **Analyze**: Extracts metadata, hashes, document indicators (macros/scripts), and executable indicators (imports, domains, IPs).
3. **Enrich** (optional): Looks up hashes via VirusTotal with rate limiting.
4. **Report**: Generates an HTML report with filters and expandable details or a CSV for downstream analysis.

## Requirements

- Python 3.10+ recommended
- Dependencies from `requirements.txt`
- Optional VirusTotal API key for enrichment

## Install

```bash
cd c:\Code\ArtifactSleuth
pip install -r requirements.txt
```

## Run

Basic scan (HTML report):
```bash
python main.py /path/to/usb --output report.html
```

CSV output:
```bash
python main.py /path/to/usb --format csv --output report.csv
```

Enable logging:
```bash
python main.py /path/to/usb --log scan_errors.log --output report.html
```

VirusTotal (free tier rate limit):
```bash
python main.py /path/to/usb --vt-key YOUR_API_KEY --output report.html
```

VirusTotal (custom rate limit):
```bash
python main.py /path/to/usb --vt-key YOUR_API_KEY --vt-rate 500 --output report.html
```

Skip VirusTotal lookups:
```bash
python main.py /path/to/usb --no-vt --output report.html
```

## Command Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `path` | Path to scan (folder or file) | Required |
| `--output`, `-o` | Output file path | `report.html` |
| `--format`, `-f` | Output format (`html` or `csv`) | `html` |
| `--log` | Log file path (enables detailed logging) | None |
| `--vt-key` | VirusTotal API key | None |
| `--vt-rate` | VirusTotal rate limit (lookups/min) | 4 |
| `--no-vt` | Skip VirusTotal lookups | False |

## Output Overview

- **HTML report**: Interactive view with filters, risk badges, and expandable file details.
- **CSV report**: Flat export for SIEM, spreadsheets, or custom analysis.
- **Risk scoring**: Heuristics based on file type, indicators, and extracted signals.

