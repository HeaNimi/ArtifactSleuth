# USB Forensic File Analyzer

A Python-based forensic tool for analyzing USB drive contents, generating comprehensive reports with file metadata, hashes, malware indicators, and VirusTotal integration.

## Features

- **Recursive scanning** of directories and archives (ZIP, 7z, RAR, TAR, GZ)
- **File hashing** (MD5, SHA1, SHA256) for VirusTotal lookups
- **VirusTotal integration** with configurable rate limiting (4/min free, 500/min premium)
- **Document analysis** for PDF/Office files (detect macros, scripts, suspicious elements)
- **Executable analysis** for PE files (extract domains, IPs, suspicious imports)
- **Beautiful reports** in HTML (with dark/light mode toggle) or CSV format

## Installation

```bash
cd c:\Code\DataAnalyzer
pip install -r requirements.txt
```

## Usage

### Basic Scan (No VirusTotal)
```bash
python main.py /path/to/usb --output report.html
```

### With VirusTotal (Free Tier - 4 lookups/min)
```bash
python main.py /path/to/usb --vt-key YOUR_API_KEY --output report.html
```

### With VirusTotal (Premium - 500 lookups/min)
```bash
python main.py /path/to/usb --vt-key YOUR_API_KEY --vt-rate 500 --output report.html
```

### CSV Output
```bash
python main.py /path/to/usb --format csv --output report.csv
```

### Skip VirusTotal Lookups
```bash
python main.py /path/to/usb --no-vt --output report.html
```

## Command Line Options

- **Extended File Metadata**: Owner, attributes (R/H/S/A), friendly type, computer name
- **Digital Signatures**: Verification of Authenticode signatures for executables
- **File Hashes**: MD5, SHA1, SHA256
- **VirusTotal Results**: Detection ratio, link to full report
- **Document Analysis**: Macros, JavaScript, suspicious elements
- **Executable Analysis**: Extracted domains, IPs, suspicious imports
- **Archive Contents**: Recursively analyzed with full path tracking

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

## License

MIT License
