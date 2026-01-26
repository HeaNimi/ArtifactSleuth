#!/usr/bin/env python3
"""
USB Forensic File Analyzer - Main CLI Entry Point

A forensic tool for analyzing USB drive contents, generating comprehensive 
reports with file metadata, hashes, malware indicators, and VirusTotal integration.
"""

import sys
import os
from pathlib import Path

# Add local dependencies folder to path for offline portability
# This allows the script to find libraries installed with --target ./dependencies
base_dir = os.path.dirname(os.path.abspath(__file__))
dep_dir = os.path.join(base_dir, 'dependencies')
if os.path.exists(dep_dir) and dep_dir not in sys.path:
    # Insert at index 0 so local dependencies take precedence over system ones
    sys.path.insert(0, dep_dir)

import argparse
import logging
from datetime import datetime

from tqdm import tqdm

from analyzer.scanner import FileScanner
from analyzer.metadata import calculate_risk_score
from analyzer.document_analyzer import analyze_files_documents, is_document
from analyzer.executable_analyzer import analyze_files_executables, is_executable
from analyzer.virustotal import lookup_files_virustotal
from analyzer.report_generator import generate_report


def create_progress_bar(desc: str, total: int = None):
    """Create a tqdm progress bar."""
    return tqdm(desc=desc, total=total, unit=" files", ncols=80)


def main():
    parser = argparse.ArgumentParser(
        description='USB Forensic File Analyzer - Scan and analyze files for security assessment',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  python main.py D:\\ --output report.html
  python main.py ./folder --vt-key YOUR_API_KEY --output report.html
  python main.py ./folder --format csv --output report.csv
  python main.py ./folder --no-vt --output report.html
        '''
    )
    
    parser.add_argument(
        'path',
        help='Path to scan (folder or file)'
    )
    
    parser.add_argument(
        '-o', '--output',
        default='report.html',
        help='Output file path (default: report.html)'
    )
    
    parser.add_argument(
        '-f', '--format',
        choices=['html', 'csv'],
        default='html',
        help='Output format (default: html)'
    )
    
    parser.add_argument(
        '--vt-key',
        help='VirusTotal API key for hash lookups'
    )
    
    parser.add_argument(
        '--vt-rate',
        type=int,
        default=4,
        help='VirusTotal rate limit (lookups/min, default: 4 for free tier, use 500 for premium)'
    )
    
    parser.add_argument(
        '--no-vt',
        action='store_true',
        help='Skip VirusTotal lookups entirely'
    )
    
    parser.add_argument(
        '--no-hash',
        action='store_true',
        help='Skip file hashing (faster but no VT lookups possible)'
    )
    
    parser.add_argument(
        '--max-archive-depth',
        type=int,
        default=5,
        help='Maximum depth for nested archive extraction (default: 5)'
    )
    
    parser.add_argument(
        '--split-report',
        type=int,
        default=0,
        metavar='N',
        help='Split HTML report into multiple files with N files each (e.g., --split-report 50000)'
    )
    
    parser.add_argument(
        '--log',
        help='Path to log file (e.g., scan_errors.log)'
    )
    
    parser.add_argument(
        '-q', '--quiet',
        action='store_true',
        help='Quiet mode - minimal output'
    )
    
    args = parser.parse_args()
    
    # Setup logging
    log_level = logging.INFO
    log_format = '%(asctime)s - %(levelname)s - %(message)s'
    if args.log:
        logging.basicConfig(filename=args.log, level=log_level, format=log_format)
    else:
        # If no log file, just show Errors to stderr
        logging.basicConfig(level=logging.ERROR, format=log_format)
    
    logger = logging.getLogger(__name__)
    if args.log:
        logger.info(f"Scan started at {datetime.now()}")
        logger.info(f"Scanning path: {args.path}")

    # Validate path
    scan_path = Path(args.path).resolve()
    if not scan_path.exists():
        print(f"Error: Path does not exist: {scan_path}")
        sys.exit(1)
    
    # Determine output path
    output_path = Path(args.output)
    if not output_path.suffix:
        output_path = output_path.with_suffix('.html' if args.format == 'html' else '.csv')
    
    print("=" * 60)
    print("🔍 USB Forensic File Analyzer")
    print("=" * 60)
    print(f"Scan path: {scan_path}")
    print(f"Output: {output_path} ({args.format.upper()})")
    print(f"VirusTotal: {'Disabled' if args.no_vt or not args.vt_key else f'Enabled ({args.vt_rate}/min)'}")
    print("=" * 60)
    print()
    
    # Phase 1: Scan files
    print("📁 Phase 1: Scanning files...")
    scanner = FileScanner(
        hash_files=not args.no_hash,
        max_archive_depth=args.max_archive_depth
    )
    
    if not args.quiet:
        with tqdm(desc="Scanning", unit=" files", ncols=80) as pbar:
            def progress(msg):
                pbar.set_postfix_str(msg[:30] + "..." if len(msg) > 30 else msg)
                pbar.update(1)
            scanner.progress_callback = progress
            files = scanner.scan(str(scan_path))
            # Set total and fill the bar if it's not already full
            if pbar.n < len(files):
                pbar.total = len(files)
                pbar.update(len(files) - pbar.n)
    else:
        files = scanner.scan(str(scan_path))
    
    summary = scanner.get_summary()
    print(f"   Found {len(files)} files ({summary['total_size_human']})")
    
    if summary['password_protected_archives']:
        print(f"   ⚠️  Skipped {summary['password_protected_archives']} password-protected archives")
    
    if summary['errors']:
        print(f"   ⚠️  {summary['errors']} errors during scan")
    
    print()
    
    # Phase 2: Document analysis
    doc_files = [f for f in files if is_document(f.path)]
    if doc_files:
        print(f"📄 Phase 2: Analyzing {len(doc_files)} documents...")
        if not args.quiet:
            with tqdm(total=len(doc_files), desc="Documents", unit=" files", ncols=80) as pbar:
                def doc_progress(current, total, msg):
                    pbar.update(1)
                analyze_files_documents(files, doc_progress)
        else:
            analyze_files_documents(files)
        print(f"   Analyzed {len(doc_files)} documents")
        print()
    
    # Phase 3: Executable analysis
    exe_files = [f for f in files if is_executable(f.path)]
    if exe_files:
        print(f"⚙️  Phase 3: Analyzing {len(exe_files)} executables...")
        if not args.quiet:
            with tqdm(total=len(exe_files), desc="Executables", unit=" files", ncols=80) as pbar:
                def exe_progress(current, total, msg):
                    pbar.update(1)
                analyze_files_executables(files, exe_progress)
        else:
            analyze_files_executables(files)
        
        # Count IOCs found
        total_domains = sum(len(f.exe_domains) for f in files)
        total_ips = sum(len(f.exe_ips) for f in files)
        print(f"   Found {total_domains} domains, {total_ips} IPs")
        print()
    
    # Phase 4: VirusTotal lookups
    if args.vt_key and not args.no_vt:
        hashable_files = [f for f in files if f.sha256]
        print(f"🔎 Phase 4: VirusTotal lookups for {len(hashable_files)} files...")
        print(f"   Rate limit: {args.vt_rate} lookups/minute")
        
        if len(hashable_files) > 10:
            estimated_time = (len(hashable_files) / args.vt_rate) * 60
            print(f"   Estimated time: {int(estimated_time // 60)}m {int(estimated_time % 60)}s")
        
        if not args.quiet:
            with tqdm(total=len(hashable_files), desc="VT Lookup", unit=" files", ncols=80) as pbar:
                def vt_progress(current, total, msg):
                    pbar.update(1)
                stats = lookup_files_virustotal(files, args.vt_key, args.vt_rate, vt_progress)
        else:
            stats = lookup_files_virustotal(files, args.vt_key, args.vt_rate)
        
        detected = sum(1 for f in files if f.vt_detected)
        print(f"   Completed: {stats['total_lookups']} lookups, {detected} detections")
        print()
    elif not args.no_vt and not args.vt_key:
        print("ℹ️  Phase 4: Skipping VirusTotal (no API key provided)")
        print("   Use --vt-key YOUR_KEY to enable VirusTotal lookups")
        print()
    
    # Recalculate risk scores after all analysis
    print("📊 Calculating risk scores...")
    for file_info in files:
        calculate_risk_score(file_info)
    
    # Get updated summary
    summary = scanner.get_summary()
    
    # Update risk counts after recalculation
    summary['high_risk_count'] = sum(1 for f in files if f.risk_score >= 50)
    summary['medium_risk_count'] = sum(1 for f in files if 25 <= f.risk_score < 50)
    summary['low_risk_count'] = sum(1 for f in files if 0 < f.risk_score < 25)
    
    print()
    
    # Phase 5: Generate report
    print(f"📝 Phase 5: Generating {args.format.upper()} report...")
    report_paths = generate_report(files, summary, str(output_path), str(scan_path), args.format, args.split_report)
    
    if len(report_paths) == 1:
        print(f"   Report saved to: {report_paths[0]}")
    else:
        print(f"   Generated {len(report_paths)} split reports:")
        for rp in report_paths:
            print(f"      - {rp}")
    print()
    
    # Summary
    print("=" * 60)
    print("✅ Analysis Complete!")
    print("=" * 60)
    print(f"   Total files: {summary['total_files']}")
    print(f"   Total size: {summary['total_size_human']}")
    print(f"   🔴 High risk: {summary['high_risk_count']}")
    print(f"   🟡 Medium risk: {summary['medium_risk_count']}")
    print(f"   🟢 Low risk: {summary['low_risk_count']}")
    
    if summary['password_protected_archives']:
        print(f"   ⚠️  Password protected: {summary['password_protected_archives']}")
    
    if summary['errors']:
        print(f"   ⚠️  Errors: {summary['errors']}")
    
    print("=" * 60)
    print(f"📋 Open {report_paths[0]} to view the full report")
    if len(report_paths) > 1:
        print(f"   ({len(report_paths)} parts total)")
    print()


if __name__ == '__main__':
    main()
