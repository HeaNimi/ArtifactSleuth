"""
Report generation module.
Generates CSV and HTML reports from scan results.
"""

import csv
import json
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any

from jinja2 import Template

from .metadata import FileInfo


def generate_csv_report(
    files: List[FileInfo],
    summary: Dict[str, Any],
    output_path: str
) -> None:
    """
    Generate a CSV report from scan results.
    
    Args:
        files: List of FileInfo objects
        summary: Scan summary dictionary
        output_path: Path to save the CSV file
    """
    fieldnames = [
        'relative_path', 'name', 'size', 'size_human', 
        'created_time', 'modified_time', 'mime_type',
        'extension_mismatch', 'expected_extensions',
        'friendly_type', 'attributes', 'computer', 'parent_folder',
        'owner', 'doc_author', 'doc_last_modified_by', 'doc_company',
        'exe_company', 'exe_product', 'exe_description', 'exe_version', 'is_signed',
        'md5', 'sha1', 'sha256',
        'vt_detected', 'vt_detection_ratio', 'vt_link',
        'doc_has_macros', 'doc_has_javascript', 'doc_suspicious_elements',
        'exe_domains', 'exe_ips', 'exe_urls', 'exe_suspicious_imports',
        'risk_score', 'risk_reasons',
        'is_archive', 'is_password_protected', 'archive_path'
    ]
    
    with open(output_path, 'w', newline='', encoding='utf-8-sig') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
        writer.writeheader()
        
        for file_info in files:
            row = file_info.to_dict()
            # Convert lists to strings for CSV
            row['doc_suspicious_elements'] = '; '.join(row.get('doc_suspicious_elements', []))
            row['exe_domains'] = '; '.join(row.get('exe_domains', []))
            row['exe_ips'] = '; '.join(row.get('exe_ips', []))
            row['exe_urls'] = '; '.join(row.get('exe_urls', []))
            row['exe_suspicious_imports'] = '; '.join(row.get('exe_suspicious_imports', []))
            row['risk_reasons'] = '; '.join(row.get('risk_reasons', []))
            writer.writerow(row)


# HTML Template with dark/light mode toggle and SHA256 copy button
HTML_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ArtifactSleuth Forensic Report</title>
    <style>
        :root {
            --bg-primary: #1a1a2e;
            --bg-secondary: #16213e;
            --bg-card: #1f2937;
            --text-primary: #e2e8f0;
            --text-secondary: #94a3b8;
            --accent: #3b82f6;
            --accent-hover: #2563eb;
            --success: #22c55e;
            --warning: #f59e0b;
            --danger: #ef4444;
            --border: #374151;
        }
        
        [data-theme="light"] {
            --bg-primary: #f8fafc;
            --bg-secondary: #f1f5f9;
            --bg-card: #ffffff;
            --text-primary: #1e293b;
            --text-secondary: #64748b;
            --accent: #2563eb;
            --accent-hover: #1d4ed8;
            --border: #e2e8f0;
        }
        
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.6;
            padding: 2rem;
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
        }
        
        header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 1rem;
            padding-bottom: 0.75rem;
            border-bottom: 1px solid var(--border);
        }
        
        h1 {
            font-size: 1.25rem;
            font-weight: 700;
            color: var(--text-primary);
        }
        
        .header-meta {
            color: var(--text-secondary);
            font-size: 0.75rem;
        }
        
        .theme-toggle, .copy-btn, .view-btn {
            background: var(--bg-secondary);
            border: 1px solid var(--border);
            color: var(--text-primary);
            padding: 0.5rem 1rem;
            border-radius: 0.5rem;
            cursor: pointer;
            font-size: 0.875rem;
            transition: all 0.2s;
        }
        
        .theme-toggle:hover, .copy-btn:hover, .view-btn:hover {
            background: var(--accent);
            color: white;
        }
        
        .copy-btn {
            padding: 0.25rem 0.5rem;
            font-size: 0.75rem;
            margin-left: 0.5rem;
        }
        
        .copy-btn.copied {
            background: var(--success);
            color: white;
        }
        
        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
            gap: 0.5rem;
            margin-bottom: 1rem;
        }
        
        .summary-card {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 0.5rem;
            padding: 0.6rem 0.8rem;
        }
        
        .summary-card h3 {
            font-size: 0.65rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            color: var(--text-secondary);
            margin-bottom: 0.25rem;
        }
        
        .summary-card .value {
            font-size: 1.1rem;
            font-weight: 700;
        }
        
        .summary-card.danger .value { color: var(--danger); }
        .summary-card.warning .value { color: var(--warning); }
        .summary-card.success .value { color: var(--success); }
        
        .section {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 0.75rem;
            margin-bottom: 1.5rem;
            overflow: hidden;
        }
        
        .section-header {
            background: var(--bg-secondary);
            padding: 1rem 1.25rem;
            border-bottom: 1px solid var(--border);
            display: flex;
            justify-content: space-between;
            align-items: center;
            cursor: pointer;
        }
        
        .section-header h2 {
            font-size: 1rem;
            font-weight: 600;
        }
        
        .section-header .badge {
            background: var(--accent);
            color: white;
            padding: 0.25rem 0.75rem;
            border-radius: 9999px;
            font-size: 0.75rem;
            font-weight: 600;
        }
        
        .section-content {
            padding: 1rem;
        }
        
        .section-content.collapsed {
            display: none;
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
            font-size: 0.875rem;
        }
        
        th, td {
            padding: 0.75rem 1rem;
            text-align: left;
            border-bottom: 1px solid var(--border);
        }
        
        th {
            background: var(--bg-secondary);
            font-weight: 600;
            color: var(--text-secondary);
            text-transform: uppercase;
            font-size: 0.75rem;
            letter-spacing: 0.05em;
        }
        
        tr:hover {
            background: var(--bg-secondary);
        }
        
        .risk-badge {
            display: inline-block;
            padding: 0.25rem 0.75rem;
            border-radius: 9999px;
            font-size: 0.75rem;
            font-weight: 600;
        }
        
        .risk-high { background: rgba(239, 68, 68, 0.2); color: var(--danger); }
        .risk-medium { background: rgba(245, 158, 11, 0.2); color: var(--warning); }
        .risk-low { background: rgba(34, 197, 94, 0.2); color: var(--success); }
        .risk-none { background: rgba(148, 163, 184, 0.2); color: var(--text-secondary); }
        
        .hash-cell {
            font-family: 'Consolas', 'Monaco', monospace;
            font-size: 0.75rem;
            color: var(--text-secondary);
            white-space: nowrap;
        }
        
        .mime-cell {
            max-width: 200px;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }
        
        td {
            max-width: 400px;
            overflow: hidden;
            text-overflow: ellipsis;
        }
        
        .hash-text {
            display: inline;
            text-overflow: ellipsis;
        }
        
        .vt-link {
            color: var(--accent);
            text-decoration: none;
        }
        
        .vt-link:hover {
            text-decoration: underline;
        }
        
        .tag {
            display: inline-block;
            background: var(--bg-secondary);
            border: 1px solid var(--border);
            padding: 0.125rem 0.5rem;
            border-radius: 0.25rem;
            font-size: 0.75rem;
            margin: 0.125rem;
        }
        
        .tag.suspicious {
            background: rgba(239, 68, 68, 0.1);
            border-color: var(--danger);
            color: var(--danger);
        }
        
        .tag.network {
            background: rgba(59, 130, 246, 0.1);
            border-color: var(--accent);
            color: var(--accent);
        }
        
        .tag.mismatch {
            background: rgba(245, 158, 11, 0.1);
            border-color: var(--warning);
            color: var(--warning);
        }
        
        .tag.info {
            background: rgba(34, 197, 94, 0.1);
            border-color: var(--success);
            color: var(--success);
        }
        
        /* Tooltip styles */
        .has-tooltip {
            position: relative;
            cursor: help;
            border-bottom: 1px dotted currentColor;
        }
        .has-tooltip:hover .tooltip-content {
            display: block;
        }
        .tooltip-content {
            display: none;
            position: absolute;
            bottom: 100%;
            left: 50%;
            transform: translateX(-50%);
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 6px;
            padding: 0.75rem;
            min-width: 280px;
            max-width: 400px;
            box-shadow: 0 4px 12px rgba(0,0,0,0.15);
            z-index: 1000;
            font-size: 0.85rem;
            line-height: 1.4;
            text-align: left;
            color: var(--text-primary);
            font-weight: normal;
        }
        .tooltip-content::after {
            content: '';
            position: absolute;
            top: 100%;
            left: 50%;
            transform: translateX(-50%);
            border: 6px solid transparent;
            border-top-color: var(--border);
        }
        .tooltip-title {
            font-weight: bold;
            margin-bottom: 0.5rem;
            color: var(--primary);
        }
        .tooltip-detection {
            font-size: 0.8rem;
            color: var(--text-muted);
            margin-top: 0.5rem;
            padding-top: 0.5rem;
            border-top: 1px solid var(--border);
        }
        
        .expandable {
            cursor: pointer;
        }
        
        .expandable-content {
            display: none;
            padding: 1rem;
            background: var(--bg-secondary);
            border-top: 1px solid var(--border);
        }
        
        .expandable-content.show {
            display: block;
        }
        
        .details-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 1rem;
        }
        
        .detail-item {
            margin-bottom: 0.5rem;
        }
        
        .detail-label {
            font-size: 0.75rem;
            color: var(--text-secondary);
            text-transform: uppercase;
        }
        
        .detail-value {
            font-family: 'Consolas', 'Monaco', monospace;
            font-size: 0.875rem;
            word-break: break-all;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }
        
        .detail-value-text {
            display: inline-block;
            font-family: inherit;
            font-size: inherit;
        }
        
        .ioc-section {
            margin-top: 1rem;
        }
        
        .ioc-list {
            display: flex;
            flex-wrap: wrap;
            gap: 0.5rem;
            margin-top: 0.5rem;
        }
        
        .password-protected {
            background: rgba(245, 158, 11, 0.1);
            border: 1px solid var(--warning);
            color: var(--warning);
            padding: 0.5rem 1rem;
            border-radius: 0.5rem;
            margin-bottom: 1rem;
        }
        
        .error-list {
            background: rgba(239, 68, 68, 0.1);
            border: 1px solid var(--danger);
            padding: 1rem;
            border-radius: 0.5rem;
            font-size: 0.875rem;
        }
        
        .error-list li {
            color: var(--danger);
            margin-left: 1.5rem;
        }
        
        .filter-bar {
            display: flex;
            gap: 1rem;
            margin-bottom: 1rem;
            flex-wrap: wrap;
        }
        
        .filter-bar input, .filter-bar select {
            background: var(--bg-secondary);
            border: 1px solid var(--border);
            color: var(--text-primary);
            padding: 0.5rem 1rem;
            border-radius: 0.5rem;
            font-size: 0.875rem;
        }
        
        .filter-bar input {
            flex: 1;
            min-width: 200px;
        }
        
        .metadata-section {
            background: var(--bg-secondary);
            border-radius: 0.5rem;
            padding: 1rem;
            margin-top: 1rem;
        }
        
        .metadata-section h4 {
            font-size: 0.875rem;
            margin-bottom: 0.75rem;
            color: var(--text-secondary);
        }
        
        .metadata-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 0.5rem;
        }
        
        @media (max-width: 768px) {
            body {
                padding: 1rem;
            }
            
            .summary-grid {
                grid-template-columns: 1fr 1fr;
            }
            
            table {
                display: block;
                overflow-x: auto;
            }
        }
        
        /* Loading overlay */
        .loading-overlay {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: var(--bg-primary);
            display: flex;
            flex-direction: column;
            justify-content: center;
            align-items: center;
            z-index: 9999;
            transition: opacity 0.3s;
        }
        .loading-overlay.hidden {
            opacity: 0;
            pointer-events: none;
        }
        .loading-spinner {
            width: 50px;
            height: 50px;
            border: 4px solid var(--border);
            border-top-color: var(--accent);
            border-radius: 50%;
            animation: spin 1s linear infinite;
        }
        @keyframes spin {
            to { transform: rotate(360deg); }
        }
        .loading-text {
            margin-top: 1rem;
            color: var(--text-secondary);
            font-size: 0.875rem;
        }
        .loading-progress {
            width: 300px;
            height: 6px;
            background: var(--border);
            border-radius: 3px;
            margin-top: 1rem;
            overflow: hidden;
        }
        .loading-progress-bar {
            height: 100%;
            background: var(--accent);
            border-radius: 3px;
            transition: width 0.1s;
            width: 0%;
        }
        .loading-stats {
            margin-top: 0.5rem;
            color: var(--text-muted);
            font-size: 0.75rem;
        }
        
        /* Virtual scroll container */
        .virtual-scroll-container {
            height: 600px;
            overflow-y: auto;
            position: relative;
        }
        .virtual-scroll-spacer {
            position: absolute;
            width: 1px;
            pointer-events: none;
        }
        .virtual-scroll-content {
            position: absolute;
            left: 0;
            right: 0;
        }
    </style>
</head>
<body>
    <!-- Loading Overlay -->
    <div class="loading-overlay" id="loadingOverlay">
        <div class="loading-spinner"></div>
        <div class="loading-text" id="loadingText">Initializing...</div>
        <div class="loading-progress">
            <div class="loading-progress-bar" id="loadingBar"></div>
        </div>
        <div class="loading-stats" id="loadingStats"></div>
    </div>
    <div class="container">
        <header>
            <div>
                <h1>🔍 ArtifactSleuth Forensic Report</h1>
                <div class="header-meta">
                    Generated: {{ generated_time }} | Scanned: {{ scan_path }}
                </div>
            </div>
            <div style="display: flex; align-items: center; gap: 1rem;">
                <div style="background: var(--danger); color: white; padding: 0.4rem 0.8rem; border-radius: 4px; font-size: 0.75rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.05em;">🔒 Classified - For Internal Use</div>
                <button class="theme-toggle" onclick="toggleTheme()">
                    🌓 Toggle Theme
                </button>
            </div>
        </header>
        
        <!-- Summary Cards -->
        <div class="summary-grid">
            <div class="summary-card">
                <h3>Total Files</h3>
                <div class="value">{{ summary.total_files }}</div>
            </div>
            <div class="summary-card">
                <h3>Total Size</h3>
                <div class="value">{{ summary.total_size_human }}</div>
            </div>
            <div class="summary-card danger">
                <h3>High Risk</h3>
                <div class="value">{{ summary.high_risk_count }}</div>
            </div>
            <div class="summary-card warning">
                <h3>Medium Risk</h3>
                <div class="value">{{ summary.medium_risk_count }}</div>
            </div>
            <div class="summary-card success">
                <h3>Low Risk</h3>
                <div class="value">{{ summary.low_risk_count }}</div>
            </div>
            <div class="summary-card">
                <h3>Errors</h3>
                <div class="value">{{ summary.errors }}</div>
            </div>
        </div>
        
        {% if summary.password_protected_archive_paths %}
        <div class="password-protected">
            ⚠️ <strong>Password Protected Archives (skipped):</strong>
            <ul style="margin-top: 0.5rem; margin-left: 1.5rem;">
                {% for path in summary.password_protected_archive_paths %}
                <li>{{ path }}</li>
                {% endfor %}
            </ul>
        </div>
        {% endif %}
        
        <!-- All Files (Optimized for 100k+ files) -->
        <div class="section">
            <div class="section-header" onclick="toggleSection(this)">
                <h2>📁 All Files</h2>
                <span class="badge">{{ files | length }}</span>
            </div>
            <div class="section-content">
                <div class="filter-bar" style="gap: 0.75rem; flex-wrap: wrap;">
                    <input type="text" id="searchInput" placeholder="Search path, mime, hash..." style="min-width: 250px;">
                    <select id="riskFilter">
                        <option value="">All Risk Levels</option>
                        <option value="high">High Risk (50+)</option>
                        <option value="medium">Medium Risk (25-49)</option>
                        <option value="low">Low Risk (1-24)</option>
                        <option value="none">No Risk (0)</option>
                    </select>
                    <span id="resultStats" style="color: var(--text-secondary); font-size: 0.875rem;">Loading...</span>
                </div>
                <div class="virtual-scroll-container" id="virtualContainer">
                    <div class="virtual-scroll-spacer" id="virtualSpacer"></div>
                    <div class="virtual-scroll-content" id="virtualContent">
                        <table id="filesTable" style="width:100%;">
                            <thead id="tableHead">
                                <tr>
                                    <th style="min-width: 300px;">Path</th>
                                    <th>Size</th>
                                    <th>MIME</th>
                                    <th>Risk</th>
                                    <th>SHA256</th>
                                    <th></th>
                                </tr>
                            </thead>
                            <tbody id="filesBody"></tbody>
                        </table>
                    </div>
                </div>
                <div class="filter-bar" style="margin-top: 1rem; justify-content: space-between;">
                    <span id="pageInfo" style="color: var(--text-secondary); font-size: 0.875rem;"></span>
                    <div style="display: flex; gap: 0.5rem;">
                        <button class="view-btn" onclick="prevPage()">◀ Prev</button>
                        <button class="view-btn" onclick="nextPage()">Next ▶</button>
                    </div>
                </div>
            </div>
        </div>
        
        <!-- Detail Panel (modal-style) -->
        <div id="detailPanel" style="display:none; position:fixed; top:0; right:0; width:550px; height:100vh; background:var(--bg-card); border-left:1px solid var(--border); overflow-y:auto; z-index:1000; padding:1.5rem; box-shadow: -2px 0 10px rgba(0,0,0,0.1);">
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:1rem;">
                <h3 style="margin:0;">File Details</h3>
                <button class="view-btn" onclick="closeDetails()">✕ Close</button>
            </div>
            <div id="detailBody"></div>
        </div>
        
        <!-- High Risk Files -->
        {% set high_risk_files = files | selectattr('risk_score', 'ge', 50) | list %}
        {% if high_risk_files %}
        <div class="section">
            <div class="section-header" onclick="toggleSection(this)">
                <h2>🚨 High Risk Files</h2>
                <span class="badge">{{ high_risk_files | length }}</span>
            </div>
            <div class="section-content collapsed">
                <table>
                    <thead>
                        <tr>
                            <th>File</th>
                            <th>Risk</th>
                            <th>VT Detection</th>
                            <th>Reasons</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for file in high_risk_files %}
                        <tr>
                            <td>{{ file.relative_path }}</td>
                            <td><span class="risk-badge risk-high">{{ file.risk_score }}</span></td>
                            <td>
                                {% if file.vt_link %}
                                <a href="{{ file.vt_link }}" target="_blank" class="vt-link">{{ file.vt_detection_ratio or 'Check' }}</a>
                                {% else %}
                                -
                                {% endif %}
                            </td>
                            <td>
                                {% for reason in file.risk_reasons %}
                                <span class="tag suspicious">{{ reason }}</span>
                                {% endfor %}
                            </td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
        </div>
        {% endif %}
        
        <!-- IOC Summary -->
        {% set files_with_iocs = files | selectattr('exe_domains') | list + files | selectattr('exe_ips') | list %}
        {% set all_domains = [] %}
        {% set all_ips = [] %}
        {% for file in files %}
            {% for domain in file.exe_domains %}
                {% if domain not in all_domains %}
                    {% set _ = all_domains.append(domain) %}
                {% endif %}
            {% endfor %}
            {% for ip in file.exe_ips %}
                {% if ip not in all_ips %}
                    {% set _ = all_ips.append(ip) %}
                {% endif %}
            {% endfor %}
        {% endfor %}
        
        {% if all_domains or all_ips %}
        <div class="section">
            <div class="section-header" onclick="toggleSection(this)">
                <h2>🌐 Network Indicators (IOCs)</h2>
                <span class="badge">{{ (all_domains | length) + (all_ips | length) }}</span>
            </div>
            <div class="section-content collapsed">
                <div style="display:flex;gap:1rem;margin-bottom:1rem;align-items:center;flex-wrap:wrap;">
                    <input type="text" id="iocSearch" placeholder="Filter IOCs..." style="flex:1;min-width:200px;padding:0.5rem;border:1px solid var(--border);border-radius:4px;background:var(--bg);color:var(--text);">
                    <select id="iocTypeFilter" style="padding:0.5rem;border:1px solid var(--border);border-radius:4px;background:var(--bg);color:var(--text);">
                        <option value="all">All Types</option>
                        <option value="domain">Domains</option>
                        <option value="ip">IP Addresses</option>
                    </select>
                    <span id="iocStats" style="color:var(--text-muted);font-size:0.9rem;"></span>
                </div>
                <table id="iocTable">
                    <thead>
                        <tr>
                            <th style="width:100px;">Type</th>
                            <th>Value</th>
                            <th>Source File</th>
                        </tr>
                    </thead>
                    <tbody id="iocBody"></tbody>
                </table>
                <div style="display:flex;justify-content:space-between;align-items:center;margin-top:1rem;">
                    <button class="view-btn" onclick="iocPrevPage()">← Previous</button>
                    <span id="iocPageInfo" style="color:var(--text-muted);"></span>
                    <button class="view-btn" onclick="iocNextPage()">Next →</button>
                </div>
            </div>
        </div>
        {% endif %}
        
        <!-- Errors -->
        {% if summary.error_messages %}
        <div class="section">
            <div class="section-header" onclick="toggleSection(this)">
                <h2>⚠️ Errors</h2>
                <span class="badge">{{ summary.errors }}</span>
            </div>
            <div class="section-content collapsed">
                <div class="error-list">
                    <ul>
                        {% for error in summary.error_messages %}
                        <li>{{ error }}</li>
                        {% endfor %}
                    </ul>
                </div>
            </div>
        </div>
        {% endif %}
        
        <!-- File Type Breakdown -->
        <div class="section">
            <div class="section-header" onclick="toggleSection(this)">
                <h2>📊 File Type Breakdown</h2>
            </div>
            <div class="section-content collapsed">
                <table>
                    <thead>
                        <tr>
                            <th>Extension</th>
                            <th>Count</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for ext, count in summary.extensions.items() %}
                        <tr>
                            <td>{{ ext }}</td>
                            <td>{{ count }}</td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
        </div>
    </div>
    
    <script id="file-data" type="application/json">{{ files_json }}</script>
    <script>
        // Loading state management
        const loadingOverlay = document.getElementById('loadingOverlay');
        const loadingText = document.getElementById('loadingText');
        const loadingBar = document.getElementById('loadingBar');
        const loadingStats = document.getElementById('loadingStats');
        
        function updateLoading(text, progress, stats) {
            if (loadingText) loadingText.textContent = text;
            if (loadingBar) loadingBar.style.width = progress + '%';
            if (loadingStats) loadingStats.textContent = stats || '';
        }
        
        function hideLoading() {
            if (loadingOverlay) loadingOverlay.classList.add('hidden');
        }
        
        // Theme toggle
        function toggleTheme() {
            const html = document.documentElement;
            const currentTheme = html.getAttribute('data-theme');
            html.setAttribute('data-theme', currentTheme === 'dark' ? 'light' : 'dark');
            localStorage.setItem('theme', html.getAttribute('data-theme'));
        }
        const savedTheme = localStorage.getItem('theme');
        if (savedTheme) document.documentElement.setAttribute('data-theme', savedTheme);
        
        function toggleSection(header) {
            const content = header.nextElementSibling;
            content.classList.toggle('collapsed');
        }
        
        function copyHash(hash, button) {
            navigator.clipboard.writeText(hash).then(() => {
                button.textContent = '✓';
                button.classList.add('copied');
                setTimeout(() => { button.textContent = '📋'; button.classList.remove('copied'); }, 1500);
            });
        }
        
        // Optimized data handling for 100k+ files
        updateLoading('Parsing file data...', 10, '');
        let filesData = [];
        let filtered = [];
        let debounceTimer = null;
        
        // Virtual scroll state
        const ROW_HEIGHT = 45;  // Approximate height of each row in pixels
        let visibleStart = 0;
        let visibleEnd = 0;
        let scrollTop = 0;
        
        function formatSize(bytes) {
            if (!bytes || isNaN(bytes)) return '-';
            const units = ['B', 'KB', 'MB', 'GB', 'TB'];
            let val = bytes, idx = 0;
            while (val >= 1024 && idx < units.length - 1) { val /= 1024; idx++; }
            return val.toFixed(1) + ' ' + units[idx];
        }
        
        function riskBadge(score) {
            if (score >= 50) return '<span class="risk-badge risk-high">' + score + '</span>';
            if (score >= 25) return '<span class="risk-badge risk-medium">' + score + '</span>';
            if (score > 0) return '<span class="risk-badge risk-low">' + score + '</span>';
            return '<span class="risk-badge risk-none">0</span>';
        }
        
        // Explanation database for suspicious elements
        const explanations = {
            // PDF Elements
            'Contains JavaScript': {
                desc: 'The PDF contains embedded JavaScript code that executes within the PDF reader.',
                risk: 'JavaScript in PDFs can be used for malicious purposes like exploiting vulnerabilities or phishing.',
                detection: 'Detected by finding /JavaScript or /JS keywords in PDF structure.'
            },
            'Contains JavaScript reference': {
                desc: 'The PDF references JavaScript code via the /JS keyword.',
                risk: 'Similar to embedded JavaScript, can execute malicious code when PDF is opened.',
                detection: 'Detected by finding /JS keyword in PDF raw bytes.'
            },
            'Auto-executes on open': {
                desc: 'The PDF has an OpenAction that triggers automatically when the document is opened.',
                risk: 'Often combined with JavaScript or Launch actions to run code without user interaction.',
                detection: 'Detected by finding /OpenAction keyword in PDF structure.'
            },
            'Additional actions defined': {
                desc: 'The PDF defines additional automatic actions (/AA) that trigger on various events.',
                risk: 'Can execute code on page open, close, print, or other document events.',
                detection: 'Detected by finding /AA keyword in PDF structure.'
            },
            'Can launch external applications': {
                desc: 'The PDF can launch external programs on the system.',
                risk: 'HIGH RISK - Can be used to execute malware directly from the PDF.',
                detection: 'Detected by finding /Launch keyword in PDF structure.'
            },
            'Contains embedded files': {
                desc: 'The PDF has files embedded within it.',
                risk: 'Embedded files could be executables or other malicious content.',
                detection: 'Detected by finding /EmbeddedFile keyword in PDF structure.'
            },
            'Contains XML Forms (potential XSS)': {
                desc: 'The PDF uses XFA (XML Forms Architecture) for dynamic forms.',
                risk: 'XFA can contain scripts and has been used in various exploits.',
                detection: 'Detected by finding /XFA keyword in PDF structure.'
            },
            'Contains interactive form': {
                desc: 'The PDF contains AcroForm interactive form fields.',
                risk: 'Forms can submit data to external servers or trigger scripts.',
                detection: 'Detected by finding /AcroForm keyword in PDF structure.'
            },
            'JBIG2 decoder (historical exploits)': {
                desc: 'The PDF uses JBIG2 image compression.',
                risk: 'JBIG2 has been used in several historical PDF exploits (e.g., CVE-2009-0658).',
                detection: 'Detected by finding /JBIG2Decode keyword in PDF structure.'
            },
            'Contains rich media (Flash)': {
                desc: 'The PDF contains embedded Flash or other rich media content.',
                risk: 'Flash has numerous known vulnerabilities and is deprecated.',
                detection: 'Detected by finding /RichMedia keyword in PDF structure.'
            },
            'Object streams (can hide content)': {
                desc: 'The PDF uses object streams to compress multiple objects.',
                risk: 'Object streams can be used to obfuscate malicious content from simple scanners.',
                detection: 'Detected by finding /ObjStm keyword in PDF structure.'
            },
            'Contains external URI references': {
                desc: 'The PDF contains links to external URIs/URLs.',
                risk: 'Could link to phishing sites or trigger downloads.',
                detection: 'Detected by finding /URI keyword in PDF structure.'
            },
            
            // VBA/Macro patterns
            'Auto-executes on document open': {
                desc: 'The macro runs automatically when the document is opened.',
                risk: 'HIGH RISK - Malware commonly uses auto-execute to run without user action.',
                detection: 'Detected by finding Auto_Open, AutoOpen, or Document_Open in VBA code.'
            },
            'Auto-executes on document close': {
                desc: 'The macro runs automatically when the document is closed.',
                risk: 'Can be used to execute cleanup or persistence actions.',
                detection: 'Detected by finding Auto_Close or AutoClose in VBA code.'
            },
            'Auto-executes on workbook open': {
                desc: 'The Excel macro runs automatically when the workbook opens.',
                risk: 'HIGH RISK - Same as document auto-execute.',
                detection: 'Detected by finding Workbook_Open in VBA code.'
            },
            'Can execute shell commands': {
                desc: 'The macro can run operating system shell commands.',
                risk: 'HIGH RISK - Can execute any system command, download malware, etc.',
                detection: 'Detected by finding Shell() function calls in VBA code.'
            },
            'Can execute Windows scripts': {
                desc: 'The macro uses WScript.Shell to run Windows scripts.',
                risk: 'HIGH RISK - Can execute PowerShell, batch files, or other scripts.',
                detection: 'Detected by finding WScript.Shell in VBA code.'
            },
            'References PowerShell': {
                desc: 'The macro contains references to PowerShell.',
                risk: 'HIGH RISK - PowerShell is commonly used by malware for fileless attacks.',
                detection: 'Detected by finding "PowerShell" string in VBA code.'
            },
            'Creates COM objects': {
                desc: 'The macro creates COM (Component Object Model) objects.',
                risk: 'COM objects can provide access to system functionality.',
                detection: 'Detected by finding CreateObject in VBA code.'
            },
            'Gets COM objects': {
                desc: 'The macro accesses existing COM objects.',
                risk: 'Can interact with other applications or system components.',
                detection: 'Detected by finding GetObject in VBA code.'
            },
            'Reads environment variables': {
                desc: 'The macro reads system environment variables.',
                risk: 'Can gather system information or find user folders.',
                detection: 'Detected by finding Environ() in VBA code.'
            },
            'Downloads files from URLs': {
                desc: 'The macro can download files from the internet.',
                risk: 'HIGH RISK - Classic malware dropper technique.',
                detection: 'Detected by finding URLDownloadToFile in VBA code.'
            },
            'HTTP requests capability': {
                desc: 'The macro can make HTTP requests.',
                risk: 'Can download content, exfiltrate data, or communicate with C2 servers.',
                detection: 'Detected by finding MSXML2.XMLHTTP in VBA code.'
            },
            'Binary file operations': {
                desc: 'The macro can perform binary file read/write operations.',
                risk: 'Often used to write downloaded malware to disk.',
                detection: 'Detected by finding ADODB.Stream in VBA code.'
            },
            'Sleep/delay execution': {
                desc: 'The macro can pause execution.',
                risk: 'Sometimes used to evade sandbox analysis.',
                detection: 'Detected by finding Wscript.Sleep in VBA code.'
            },
            'Character obfuscation': {
                desc: 'The macro uses Chr() to build strings from character codes.',
                risk: 'Common obfuscation technique to hide malicious strings.',
                detection: 'Detected by finding Chr() with numeric arguments in VBA code.'
            },
            'Dynamic function calls': {
                desc: 'The macro uses CallByName for dynamic function invocation.',
                risk: 'Can be used to obfuscate which functions are being called.',
                detection: 'Detected by finding CallByName in VBA code.'
            },
            'Executes commands': {
                desc: 'The macro uses .Run to execute commands.',
                risk: 'HIGH RISK - Direct command execution capability.',
                detection: 'Detected by finding .Run method calls in VBA code.'
            },
            
            // Executable imports
            'Remote thread injection': {
                desc: 'Can create threads in other processes.',
                risk: 'Common technique for injecting code into other processes.',
                detection: 'Detected by finding CreateRemoteThread import in PE file.'
            },
            'Remote memory allocation': {
                desc: 'Can allocate memory in other processes.',
                risk: 'Used for code injection - allocates space for malicious code.',
                detection: 'Detected by finding VirtualAllocEx import in PE file.'
            },
            'Process memory writing': {
                desc: 'Can write to memory of other processes.',
                risk: 'Used to write malicious code into allocated memory.',
                detection: 'Detected by finding WriteProcessMemory import in PE file.'
            },
            'Process memory reading': {
                desc: 'Can read memory from other processes.',
                risk: 'Can be used for credential theft or process inspection.',
                detection: 'Detected by finding ReadProcessMemory import in PE file.'
            },
            'Process handle access': {
                desc: 'Can open handles to other processes.',
                risk: 'Required step for most process manipulation techniques.',
                detection: 'Detected by finding OpenProcess import in PE file.'
            },
            'Process hollowing technique': {
                desc: 'Can unmap sections from process memory.',
                risk: 'HIGH RISK - Key step in process hollowing malware technique.',
                detection: 'Detected by finding NtUnmapViewOfSection import in PE file.'
            },
            'Thread context manipulation': {
                desc: 'Can modify thread execution context.',
                risk: 'Used in code injection to redirect execution.',
                detection: 'Detected by finding SetThreadContext import in PE file.'
            },
            'APC injection': {
                desc: 'Can queue code to run in another thread.',
                risk: 'Alternative code injection technique using APC queues.',
                detection: 'Detected by finding QueueUserAPC import in PE file.'
            },
            'Dynamic library loading': {
                desc: 'Can load DLL libraries at runtime.',
                risk: 'Used for dynamic code loading or DLL injection.',
                detection: 'Detected by finding LoadLibraryA/W import in PE file.'
            },
            'Dynamic function resolution': {
                desc: 'Can resolve function addresses at runtime.',
                risk: 'Used to call functions dynamically, often to evade static analysis.',
                detection: 'Detected by finding GetProcAddress import in PE file.'
            },
            'Memory protection changes': {
                desc: 'Can change memory page protections.',
                risk: 'Used to make memory executable for shellcode.',
                detection: 'Detected by finding VirtualProtect import in PE file.'
            },
            'Remote memory protection changes': {
                desc: 'Can change memory protections in other processes.',
                risk: 'Used in remote code injection.',
                detection: 'Detected by finding VirtualProtectEx import in PE file.'
            },
            'Keyboard state monitoring': {
                desc: 'Can check if keys are pressed.',
                risk: 'Potential keylogger functionality.',
                detection: 'Detected by finding GetAsyncKeyState import in PE file.'
            },
            'Key state checking': {
                desc: 'Can check keyboard key states.',
                risk: 'May indicate keylogging capability.',
                detection: 'Detected by finding GetKeyState import in PE file.'
            },
            'System-wide hooks': {
                desc: 'Can install system-wide keyboard/mouse hooks.',
                risk: 'HIGH RISK - Used for keyloggers and system monitoring.',
                detection: 'Detected by finding SetWindowsHookEx import in PE file.'
            },
            'Clipboard access': {
                desc: 'Can read clipboard contents.',
                risk: 'May steal copied passwords or sensitive data.',
                detection: 'Detected by finding GetClipboardData import in PE file.'
            },
            'Debugger detection': {
                desc: 'Checks if a debugger is attached.',
                risk: 'Anti-analysis technique - malware avoids running under debugger.',
                detection: 'Detected by finding IsDebuggerPresent import in PE file.'
            },
            'Remote debugger detection': {
                desc: 'Checks for remote debuggers.',
                risk: 'Anti-analysis technique.',
                detection: 'Detected by finding CheckRemoteDebuggerPresent import in PE file.'
            },
            'Process info query (anti-debug)': {
                desc: 'Can query detailed process information.',
                risk: 'Often used for anti-debugging checks.',
                detection: 'Detected by finding NtQueryInformationProcess import in PE file.'
            },
            'Network initialization': {
                desc: 'Initializes Windows Sockets.',
                risk: 'Indicates network communication capability.',
                detection: 'Detected by finding WSAStartup import in PE file.'
            },
            'Socket creation': {
                desc: 'Can create network sockets.',
                risk: 'Network communication capability.',
                detection: 'Detected by finding socket import in PE file.'
            },
            'Network connection': {
                desc: 'Can establish network connections.',
                risk: 'May connect to C2 servers or exfiltrate data.',
                detection: 'Detected by finding connect import in PE file.'
            },
            'Internet connection': {
                desc: 'Can open internet connections via WinINet.',
                risk: 'HTTP/HTTPS communication capability.',
                detection: 'Detected by finding InternetOpenA/W import in PE file.'
            },
            'URL connection': {
                desc: 'Can connect to URLs directly.',
                risk: 'Can download content from web servers.',
                detection: 'Detected by finding InternetOpenUrlA/W import in PE file.'
            },
            'HTTP request': {
                desc: 'Can make HTTP requests.',
                risk: 'Web communication capability.',
                detection: 'Detected by finding HttpOpenRequestA/W import in PE file.'
            },
            'File download': {
                desc: 'Can download files from URLs to disk.',
                risk: 'HIGH RISK - Classic dropper technique.',
                detection: 'Detected by finding URLDownloadToFileA/W import in PE file.'
            },
            'File access': {
                desc: 'Can create/open files.',
                risk: 'Basic file operation - context dependent.',
                detection: 'Detected by finding CreateFileA/W import in PE file.'
            },
            'File deletion': {
                desc: 'Can delete files.',
                risk: 'May be used to cover tracks or damage data.',
                detection: 'Detected by finding DeleteFileA/W import in PE file.'
            },
            'File moving': {
                desc: 'Can move/rename files.',
                risk: 'May be used for persistence or data manipulation.',
                detection: 'Detected by finding MoveFileA/W import in PE file.'
            },
            'Registry access': {
                desc: 'Can read registry keys.',
                risk: 'Registry access for configuration or reconnaissance.',
                detection: 'Detected by finding RegOpenKeyExA/W import in PE file.'
            },
            'Registry modification': {
                desc: 'Can modify registry values.',
                risk: 'Often used for persistence (Run keys) or system changes.',
                detection: 'Detected by finding RegSetValueExA/W import in PE file.'
            },
            'Registry deletion': {
                desc: 'Can delete registry keys.',
                risk: 'May disable security features or cover tracks.',
                detection: 'Detected by finding RegDeleteKeyA/W import in PE file.'
            },
            'Service manager access': {
                desc: 'Can access the Windows Service Control Manager.',
                risk: 'May install or manipulate system services.',
                detection: 'Detected by finding OpenSCManager import in PE file.'
            },
            'Service creation': {
                desc: 'Can create Windows services.',
                risk: 'HIGH RISK - Services run with SYSTEM privileges.',
                detection: 'Detected by finding CreateService import in PE file.'
            },
            'Service starting': {
                desc: 'Can start Windows services.',
                risk: 'May start malicious service.',
                detection: 'Detected by finding StartService import in PE file.'
            },
            'Privilege adjustment': {
                desc: 'Can modify process token privileges.',
                risk: 'Used for privilege escalation.',
                detection: 'Detected by finding AdjustTokenPrivileges import in PE file.'
            },
            'Process token access': {
                desc: 'Can access process security tokens.',
                risk: 'First step in token manipulation.',
                detection: 'Detected by finding OpenProcessToken import in PE file.'
            },
            'Privilege lookup': {
                desc: 'Looks up privilege values by name.',
                risk: 'Part of privilege escalation process.',
                detection: 'Detected by finding LookupPrivilegeValue import in PE file.'
            },
            'Data encryption': {
                desc: 'Can encrypt data using Windows Crypto API.',
                risk: 'May indicate ransomware or data protection.',
                detection: 'Detected by finding CryptEncrypt import in PE file.'
            },
            'Data decryption': {
                desc: 'Can decrypt data.',
                risk: 'May be decrypting malicious payloads.',
                detection: 'Detected by finding CryptDecrypt import in PE file.'
            },
            'Crypto key generation': {
                desc: 'Can generate cryptographic keys.',
                risk: 'Ransomware often generates keys for encryption.',
                detection: 'Detected by finding CryptGenKey import in PE file.'
            },
            'Crypto context': {
                desc: 'Acquires cryptographic service provider context.',
                risk: 'Required for using Windows crypto functions.',
                detection: 'Detected by finding CryptAcquireContext import in PE file.'
            },
            'Network send': {
                desc: 'Can send data over network.',
                risk: 'May exfiltrate data.',
                detection: 'Detected by finding send import in PE file.'
            },
            'Network receive': {
                desc: 'Can receive data over network.',
                risk: 'May receive commands from C2.',
                detection: 'Detected by finding recv import in PE file.'
            },
            'Debug string output': {
                desc: 'Outputs debug messages.',
                risk: 'May be used for anti-debugging tricks.',
                detection: 'Detected by finding OutputDebugString import in PE file.'
            },
            
            // Risk Reasons (from risk scoring)
            'VirusTotal detection': {
                desc: 'File was flagged by one or more antivirus engines on VirusTotal.',
                risk: 'HIGH RISK - Multiple AV vendors consider this file malicious.',
                detection: 'File hash was submitted to VirusTotal API and returned positive detections.'
            },
            'Windows Defender detection': {
                desc: 'Windows Defender identified this file as a threat.',
                risk: 'HIGH RISK - Microsoft built-in antivirus flagged this file.',
                detection: 'File was scanned locally using Windows Defender command-line scanner.'
            },
            'Contains VBA macros': {
                desc: 'Office document contains Visual Basic for Applications code.',
                risk: 'Macros can execute code when document is opened. Common malware vector.',
                detection: 'VBA project stream found in Office document structure.'
            },
            'Contains JavaScript': {
                desc: 'PDF or document contains embedded JavaScript code.',
                risk: 'JavaScript can execute when document is opened, potentially exploiting vulnerabilities.',
                detection: 'JavaScript or JS keywords found in document structure.'
            },
            'Suspicious element': {
                desc: 'Document contains elements commonly used in malicious files.',
                risk: 'These elements enable dangerous functionality like auto-execution or external access.',
                detection: 'Specific keywords found in document structure (see Document Analysis section).'
            },
            'Suspicious imports': {
                desc: 'Executable imports API functions commonly used by malware.',
                risk: 'These APIs enable process injection, keylogging, or other malicious behavior.',
                detection: 'Import table analysis found suspicious function imports (see Executable Analysis).'
            },
            'Network indicators': {
                desc: 'Executable contains embedded domains, IPs, or URLs.',
                risk: 'May indicate command-and-control communication or data exfiltration.',
                detection: 'String analysis found network-related patterns in executable.'
            },
            'Script/uncommon executable': {
                desc: 'File uses a script or uncommon executable extension (.scr, .bat, .ps1, etc.).',
                risk: 'Script files can execute malicious commands. Uncommon types may evade detection.',
                detection: 'File extension matches known high-risk script/executable types.'
            },
            'Executable file': {
                desc: 'Standard executable file format (.exe, .msi, etc.).',
                risk: 'Executables can run code directly on the system.',
                detection: 'File extension matches known executable types.'
            },
            'Library file': {
                desc: 'Dynamic library file (.dll, .sys, etc.).',
                risk: 'Libraries are loaded by other programs and can contain malicious code.',
                detection: 'File extension matches known library types.'
            },
            'Android Executable (DEX)': {
                desc: 'Dalvik Executable file used in Android applications.',
                risk: 'Contains bytecode that runs on Android devices.',
                detection: 'Filename is classes.dex (Android app executable).'
            },
            'Digitally signed': {
                desc: 'File has a valid digital signature from a known publisher.',
                risk: 'LOWER RISK - Signed files are from verified publishers (but can still be malicious).',
                detection: 'PE file authenticode signature was verified.'
            },
            'Known vendor': {
                desc: 'File is from a recognized software vendor.',
                risk: 'LOWER RISK - Files from major vendors are typically safe.',
                detection: 'Company name in PE metadata matches known vendor list.'
            }
        };
        
        // Function to get explanation for an item
        function getExplanation(item) {
            // Direct match
            if (explanations[item]) return explanations[item];
            
            // Try to find partial match
            for (const key in explanations) {
                if (item.toLowerCase().includes(key.toLowerCase()) || key.toLowerCase().includes(item.toLowerCase())) {
                    return explanations[key];
                }
            }
            return null;
        }
        
        // Create tooltip HTML for an item
        function createTooltip(item, exp) {
            if (!exp) return '<li>' + item + '</li>';
            return '<li class="has-tooltip">' + item + 
                '<div class="tooltip-content">' +
                '<div class="tooltip-title">' + item + '</div>' +
                '<div>' + exp.desc + '</div>' +
                '<div style="margin-top:0.5rem;"><strong>Risk:</strong> ' + exp.risk + '</div>' +
                '<div class="tooltip-detection"><strong>Detection:</strong> ' + exp.detection + '</div>' +
                '</div></li>';
        }
        
        function applyFilters() {
            const q = document.getElementById('searchInput').value.toLowerCase();
            const riskFilter = document.getElementById('riskFilter').value;
            filtered = filesData.filter(f => {
                const risk = f.risk_score || 0;
                if (riskFilter === 'high' && risk < 50) return false;
                if (riskFilter === 'medium' && (risk < 25 || risk >= 50)) return false;
                if (riskFilter === 'low' && (risk <= 0 || risk >= 25)) return false;
                if (riskFilter === 'none' && risk !== 0) return false;
                if (!q) return true;
                const haystack = [f.relative_path||'', f.mime_type||'', f.sha256||'', f.md5||''].join(' ').toLowerCase();
                return haystack.includes(q);
            });
            page = 1;
            updateVirtualScroll();
        }
        
        // Virtual scroll rendering - only renders visible rows
        function updateVirtualScroll() {
            const container = document.getElementById('virtualContainer');
            const spacer = document.getElementById('virtualSpacer');
            const content = document.getElementById('virtualContent');
            const tbody = document.getElementById('filesBody');
            if (!container || !tbody) return;
            
            const totalHeight = filtered.length * ROW_HEIGHT;
            spacer.style.height = totalHeight + 'px';
            
            const scrollTop = container.scrollTop;
            const viewportHeight = container.clientHeight;
            
            // Calculate visible range with buffer
            const bufferRows = 10;
            visibleStart = Math.max(0, Math.floor(scrollTop / ROW_HEIGHT) - bufferRows);
            visibleEnd = Math.min(filtered.length, Math.ceil((scrollTop + viewportHeight) / ROW_HEIGHT) + bufferRows);
            
            // Position content
            content.style.top = (visibleStart * ROW_HEIGHT) + 'px';
            
            // Build only visible rows
            let html = '';
            for (let i = visibleStart; i < visibleEnd; i++) {
                const f = filtered[i];
                const sha = f.sha256 ? (f.sha256.substring(0,16) + '...') : '-';
                const mime = f.mime_type ? (f.mime_type.length > 40 ? f.mime_type.substring(0,40)+'...' : f.mime_type) : '-';
                html += '<tr data-idx="' + i + '"><td>' + (f.relative_path||f.name||'') + '</td><td>' + formatSize(f.size) + '</td><td class="mime-cell" title="'+(f.mime_type||'')+'">' + mime + '</td><td>' + riskBadge(f.risk_score||0) + '</td><td class="hash-cell">' + sha + '</td><td><button class="view-btn" onclick="showDetails(' + i + ')">View</button></td></tr>';
            }
            tbody.innerHTML = html;
            
            // Update stats
            document.getElementById('resultStats').textContent = filtered.length.toLocaleString() + ' files • showing ' + (visibleStart+1).toLocaleString() + '-' + visibleEnd.toLocaleString();
            document.getElementById('pageInfo').textContent = 'Scroll to view more | ' + Math.round((scrollTop / Math.max(1, totalHeight - viewportHeight)) * 100) + '% scrolled';
        }
        
        // Debounced scroll handler
        let scrollTimer = null;
        function onVirtualScroll() {
            if (scrollTimer) cancelAnimationFrame(scrollTimer);
            scrollTimer = requestAnimationFrame(updateVirtualScroll);
        }
        
        // Legacy pagination (now jumps to position in virtual scroll)
        function prevPage() { 
            const container = document.getElementById('virtualContainer');
            if (container) {
                container.scrollTop = Math.max(0, container.scrollTop - (container.clientHeight - ROW_HEIGHT * 2));
            }
        }
        function nextPage() { 
            const container = document.getElementById('virtualContainer');
            if (container) {
                container.scrollTop = container.scrollTop + (container.clientHeight - ROW_HEIGHT * 2);
            }
        }
        
        function showDetails(idx) {
            const f = filtered[idx];
            if (!f) return;
            const panel = document.getElementById('detailPanel');
            const body = document.getElementById('detailBody');
            
            // Helper to create a list from array
            function arrayToList(arr, emptyText, useTooltips) {
                if (!arr || arr.length === 0) return '<span style="color:var(--text-muted);">' + (emptyText||'None') + '</span>';
                if (useTooltips) {
                    return '<ul style="margin:0;padding-left:1.2rem;">' + arr.map(function(item) {
                        var exp = getExplanation(item);
                        return createTooltip(item, exp);
                    }).join('') + '</ul>';
                }
                return '<ul style="margin:0;padding-left:1.2rem;">' + arr.map(function(item) { return '<li>' + item + '</li>'; }).join('') + '</ul>';
            }
            
            // Basic Info Section
            let html = '<h4 style="margin:0 0 1rem 0;color:var(--text-muted);border-bottom:1px solid var(--border);padding-bottom:0.5rem;">📄 File Information</h4>';
            html += '<div class="details-grid">';
            html += '<div class="detail-item"><div class="detail-label">Full Path</div><div class="detail-value" style="word-break:break-all;">' + (f.path||f.relative_path||'') + '</div></div>';
            html += '<div class="detail-item"><div class="detail-label">Size</div><div class="detail-value">' + formatSize(f.size) + ' (' + (f.size||0) + ' bytes)</div></div>';
            html += '<div class="detail-item"><div class="detail-label">MIME Type</div><div class="detail-value">' + (f.mime_type||'-') + '</div></div>';
            html += '<div class="detail-item"><div class="detail-label">File Type</div><div class="detail-value">' + (f.file_type||f.friendly_type||'-') + '</div></div>';
            html += '<div class="detail-item"><div class="detail-label">Created</div><div class="detail-value">' + (f.created_time||'-') + '</div></div>';
            html += '<div class="detail-item"><div class="detail-label">Modified</div><div class="detail-value">' + (f.modified_time||'-') + '</div></div>';
            html += '<div class="detail-item"><div class="detail-label">Accessed</div><div class="detail-value">' + (f.accessed_time||'-') + '</div></div>';
            html += '<div class="detail-item"><div class="detail-label">Owner</div><div class="detail-value">' + (f.owner||'-') + '</div></div>';
            html += '<div class="detail-item"><div class="detail-label">Computer</div><div class="detail-value">' + (f.computer||'-') + '</div></div>';
            if (f.archive_path) {
                html += '<div class="detail-item"><div class="detail-label">From Archive</div><div class="detail-value">' + f.archive_path + '</div></div>';
            }
            html += '</div>';
            
            // Risk Assessment Section
            html += '<h4 style="margin:1.5rem 0 1rem 0;color:var(--text-muted);border-bottom:1px solid var(--border);padding-bottom:0.5rem;">⚠️ Risk Assessment</h4>';
            html += '<div class="details-grid">';
            const riskColor = (f.risk_score||0) >= 70 ? '#e74c3c' : (f.risk_score||0) >= 30 ? '#f39c12' : '#27ae60';
            html += '<div class="detail-item"><div class="detail-label">Risk Score</div><div class="detail-value"><span style="font-weight:bold;font-size:1.2rem;color:' + riskColor + ';">' + (f.risk_score||0) + '</span>/100</div></div>';
            html += '</div>';
            html += '<div class="detail-item" style="margin-top:0.5rem;"><div class="detail-label">Risk Factors <span style="font-size:0.75rem;color:var(--text-muted);">(hover for info)</span></div><div class="detail-value">' + arrayToList(f.risk_reasons, 'No risk factors identified', true) + '</div></div>';
            
            // Hashes Section
            html += '<h4 style="margin:1.5rem 0 1rem 0;color:var(--text-muted);border-bottom:1px solid var(--border);padding-bottom:0.5rem;">🔐 File Hashes</h4>';
            html += '<div class="details-grid">';
            html += '<div class="detail-item"><div class="detail-label">MD5</div><div class="detail-value" style="font-family:monospace;font-size:0.85rem;">' + (f.md5||'-') + (f.md5 ? ' <button class="copy-btn" onclick="copyHash(\\x27'+f.md5+'\\x27,this)">📋</button>' : '') + '</div></div>';
            html += '<div class="detail-item"><div class="detail-label">SHA1</div><div class="detail-value" style="font-family:monospace;font-size:0.85rem;">' + (f.sha1||'-') + (f.sha1 ? ' <button class="copy-btn" onclick="copyHash(\\x27'+f.sha1+'\\x27,this)">📋</button>' : '') + '</div></div>';
            html += '<div class="detail-item"><div class="detail-label">SHA256</div><div class="detail-value" style="font-family:monospace;font-size:0.85rem;word-break:break-all;">' + (f.sha256||'-') + (f.sha256 ? ' <button class="copy-btn" onclick="copyHash(\\x27'+f.sha256+'\\x27,this)">📋</button>' : '') + '</div></div>';
            html += '</div>';
            
            // VirusTotal Section (if available)
            if (f.vt_detected !== null || f.vt_link) {
                html += '<h4 style="margin:1.5rem 0 1rem 0;color:var(--text-muted);border-bottom:1px solid var(--border);padding-bottom:0.5rem;">🛡️ VirusTotal Results</h4>';
                html += '<div class="details-grid">';
                if (f.vt_detected === true) {
                    html += '<div class="detail-item"><div class="detail-label">Detection</div><div class="detail-value" style="color:#e74c3c;font-weight:bold;">⚠️ DETECTED - ' + (f.vt_detection_ratio||'') + '</div></div>';
                } else if (f.vt_detected === false) {
                    html += '<div class="detail-item"><div class="detail-label">Detection</div><div class="detail-value" style="color:#27ae60;">✓ Clean</div></div>';
                }
                if (f.vt_link) {
                    html += '<div class="detail-item"><div class="detail-label">Report</div><div class="detail-value"><a href="' + f.vt_link + '" target="_blank" style="color:var(--primary);">View on VirusTotal →</a></div></div>';
                }
                if (f.vt_error) {
                    html += '<div class="detail-item"><div class="detail-label">Error</div><div class="detail-value" style="color:#e74c3c;">' + f.vt_error + '</div></div>';
                }
                html += '</div>';
            }
            
            // Windows Defender Section (if scanned)
            if (f.defender_scanned !== null) {
                html += '<h4 style="margin:1.5rem 0 1rem 0;color:var(--text-muted);border-bottom:1px solid var(--border);padding-bottom:0.5rem;">🛡️ Windows Defender</h4>';
                html += '<div class="details-grid">';
                if (f.defender_detected === true) {
                    html += '<div class="detail-item"><div class="detail-label">Detection</div><div class="detail-value" style="color:#e74c3c;font-weight:bold;">⚠️ THREAT DETECTED</div></div>';
                    if (f.defender_threat_name) {
                        html += '<div class="detail-item"><div class="detail-label">Threat Name</div><div class="detail-value" style="color:#e74c3c;">' + f.defender_threat_name + '</div></div>';
                    }
                } else if (f.defender_scanned === true) {
                    html += '<div class="detail-item"><div class="detail-label">Detection</div><div class="detail-value" style="color:#27ae60;">✓ Clean</div></div>';
                }
                if (f.defender_error) {
                    html += '<div class="detail-item"><div class="detail-label">Error</div><div class="detail-value" style="color:#e74c3c;">' + f.defender_error + '</div></div>';
                }
                html += '</div>';
            }
            
            // PE/Executable Analysis Section
            const hasExeAnalysis = (f.exe_domains && f.exe_domains.length) || (f.exe_ips && f.exe_ips.length) || (f.exe_urls && f.exe_urls.length) || (f.exe_suspicious_imports && f.exe_suspicious_imports.length) || f.exe_company || f.is_signed !== null;
            if (hasExeAnalysis) {
                html += '<h4 style="margin:1.5rem 0 1rem 0;color:var(--text-muted);border-bottom:1px solid var(--border);padding-bottom:0.5rem;">⚙️ Executable Analysis</h4>';
                
                // PE Metadata
                if (f.exe_company || f.exe_product || f.exe_description || f.exe_version) {
                    html += '<div class="details-grid">';
                    if (f.exe_company) html += '<div class="detail-item"><div class="detail-label">Company</div><div class="detail-value">' + f.exe_company + '</div></div>';
                    if (f.exe_product) html += '<div class="detail-item"><div class="detail-label">Product</div><div class="detail-value">' + f.exe_product + '</div></div>';
                    if (f.exe_description) html += '<div class="detail-item"><div class="detail-label">Description</div><div class="detail-value">' + f.exe_description + '</div></div>';
                    if (f.exe_version) html += '<div class="detail-item"><div class="detail-label">Version</div><div class="detail-value">' + f.exe_version + '</div></div>';
                    html += '</div>';
                }
                
                // Digital Signature
                html += '<div class="details-grid" style="margin-top:0.5rem;">';
                if (f.is_signed === true) {
                    html += '<div class="detail-item"><div class="detail-label">Digital Signature</div><div class="detail-value" style="color:#27ae60;">✓ Signed</div></div>';
                    if (f.sig_subject) html += '<div class="detail-item"><div class="detail-label">Signer</div><div class="detail-value">' + f.sig_subject + '</div></div>';
                    if (f.sig_issuer) html += '<div class="detail-item"><div class="detail-label">Issuer</div><div class="detail-value">' + f.sig_issuer + '</div></div>';
                } else if (f.is_signed === false) {
                    html += '<div class="detail-item"><div class="detail-label">Digital Signature</div><div class="detail-value" style="color:#f39c12;">✗ Not Signed</div></div>';
                }
                html += '</div>';
                
                // IOCs - Network Indicators
                html += '<div style="margin-top:1rem;"><div class="detail-label" style="margin-bottom:0.5rem;">🌐 Network IOCs (Domains)</div><div class="detail-value">' + arrayToList(f.exe_domains, 'None found') + '</div></div>';
                html += '<div style="margin-top:0.75rem;"><div class="detail-label" style="margin-bottom:0.5rem;">📍 Network IOCs (IP Addresses)</div><div class="detail-value">' + arrayToList(f.exe_ips, 'None found') + '</div></div>';
                html += '<div style="margin-top:0.75rem;"><div class="detail-label" style="margin-bottom:0.5rem;">🔗 Network IOCs (URLs)</div><div class="detail-value">' + arrayToList(f.exe_urls, 'None found') + '</div></div>';
                
                // Suspicious Imports
                html += '<div style="margin-top:0.75rem;"><div class="detail-label" style="margin-bottom:0.5rem;">🚨 Suspicious API Imports <span style="font-size:0.75rem;color:var(--text-muted);">(hover for info)</span></div><div class="detail-value">' + arrayToList(f.exe_suspicious_imports, 'None found', true) + '</div></div>';
                
                if (f.exe_analysis_error) {
                    html += '<div style="margin-top:0.75rem;"><div class="detail-label">Analysis Error</div><div class="detail-value" style="color:#e74c3c;">' + f.exe_analysis_error + '</div></div>';
                }
            }
            
            // Document Analysis Section (PDF, Office)
            const hasDocAnalysis = f.doc_has_macros !== null || f.doc_has_javascript !== null || (f.doc_suspicious_elements && f.doc_suspicious_elements.length) || f.doc_author;
            if (hasDocAnalysis) {
                html += '<h4 style="margin:1.5rem 0 1rem 0;color:var(--text-muted);border-bottom:1px solid var(--border);padding-bottom:0.5rem;">📑 Document Analysis</h4>';
                
                // Security Indicators
                html += '<div class="details-grid">';
                if (f.doc_has_macros !== null) {
                    const macroStyle = f.doc_has_macros ? 'color:#e74c3c;font-weight:bold;' : 'color:#27ae60;';
                    html += '<div class="detail-item"><div class="detail-label">VBA Macros</div><div class="detail-value" style="' + macroStyle + '">' + (f.doc_has_macros ? '⚠️ PRESENT' : '✓ None') + '</div></div>';
                }
                if (f.doc_has_javascript !== null) {
                    const jsStyle = f.doc_has_javascript ? 'color:#e74c3c;font-weight:bold;' : 'color:#27ae60;';
                    html += '<div class="detail-item"><div class="detail-label">JavaScript</div><div class="detail-value" style="' + jsStyle + '">' + (f.doc_has_javascript ? '⚠️ PRESENT' : '✓ None') + '</div></div>';
                }
                html += '</div>';
                
                // Suspicious Elements
                if (f.doc_suspicious_elements && f.doc_suspicious_elements.length) {
                    html += '<div style="margin-top:0.75rem;"><div class="detail-label" style="margin-bottom:0.5rem;color:#e74c3c;">🚨 Suspicious Elements <span style="font-size:0.75rem;color:var(--text-muted);">(hover for info)</span></div><div class="detail-value">' + arrayToList(f.doc_suspicious_elements, null, true) + '</div></div>';
                }
                
                // Document Properties
                if (f.doc_author || f.doc_company || f.doc_title || f.doc_last_modified_by) {
                    html += '<div style="margin-top:1rem;"><div class="detail-label" style="margin-bottom:0.5rem;">Document Properties</div></div>';
                    html += '<div class="details-grid">';
                    if (f.doc_author) html += '<div class="detail-item"><div class="detail-label">Author</div><div class="detail-value">' + f.doc_author + '</div></div>';
                    if (f.doc_last_modified_by) html += '<div class="detail-item"><div class="detail-label">Last Modified By</div><div class="detail-value">' + f.doc_last_modified_by + '</div></div>';
                    if (f.doc_company) html += '<div class="detail-item"><div class="detail-label">Company</div><div class="detail-value">' + f.doc_company + '</div></div>';
                    if (f.doc_title) html += '<div class="detail-item"><div class="detail-label">Title</div><div class="detail-value">' + f.doc_title + '</div></div>';
                    if (f.doc_subject) html += '<div class="detail-item"><div class="detail-label">Subject</div><div class="detail-value">' + f.doc_subject + '</div></div>';
                    if (f.doc_keywords) html += '<div class="detail-item"><div class="detail-label">Keywords</div><div class="detail-value">' + f.doc_keywords + '</div></div>';
                    if (f.doc_created) html += '<div class="detail-item"><div class="detail-label">Doc Created</div><div class="detail-value">' + f.doc_created + '</div></div>';
                    if (f.doc_modified) html += '<div class="detail-item"><div class="detail-label">Doc Modified</div><div class="detail-value">' + f.doc_modified + '</div></div>';
                    html += '</div>';
                }
                
                if (f.doc_analysis_error) {
                    html += '<div style="margin-top:0.75rem;"><div class="detail-label">Analysis Error</div><div class="detail-value" style="color:#e74c3c;">' + f.doc_analysis_error + '</div></div>';
                }
            }
            
            body.innerHTML = html;
            panel.style.display = 'block';
        }
        function closeDetails() { document.getElementById('detailPanel').style.display = 'none'; }
        
        // ==========================================
        // IOC Table with Pagination
        // ==========================================
        let iocData = [];
        let iocFiltered = [];
        
        // Build IOC data from files (called after filesData is loaded)
        function buildIOCData() {
            iocData = [];
            filesData.forEach(function(f) {
                if (f.exe_domains && f.exe_domains.length) {
                    f.exe_domains.forEach(function(d) {
                        iocData.push({type: 'domain', value: d, source: f.relative_path || f.name});
                    });
                }
                if (f.exe_ips && f.exe_ips.length) {
                    f.exe_ips.forEach(function(ip) {
                        iocData.push({type: 'ip', value: ip, source: f.relative_path || f.name});
                    });
                }
            });
            iocFiltered = iocData.slice();
        }
        let iocPage = 1;
        const iocPageSize = 50;
        
        function filterIOCs() {
            const search = (document.getElementById('iocSearch').value || '').toLowerCase();
            const typeFilter = document.getElementById('iocTypeFilter').value;
            
            iocFiltered = iocData.filter(function(ioc) {
                const matchesSearch = !search || ioc.value.toLowerCase().includes(search) || ioc.source.toLowerCase().includes(search);
                const matchesType = typeFilter === 'all' || ioc.type === typeFilter;
                return matchesSearch && matchesType;
            });
            iocPage = 1;
            renderIOCs();
        }
        
        function renderIOCs() {
            const tbody = document.getElementById('iocBody');
            if (!tbody) return;
            
            const start = (iocPage - 1) * iocPageSize;
            const end = Math.min(start + iocPageSize, iocFiltered.length);
            
            let html = '';
            for (let i = start; i < end; i++) {
                const ioc = iocFiltered[i];
                const typeLabel = ioc.type === 'domain' ? '<span class="tag network">Domain</span>' : '<span class="tag suspicious">IP</span>';
                html += '<tr><td>' + typeLabel + '</td><td style="font-family:monospace;">' + ioc.value + '</td><td>' + ioc.source + '</td></tr>';
            }
            tbody.innerHTML = html || '<tr><td colspan="3" style="text-align:center;color:var(--text-muted);">No IOCs found</td></tr>';
            
            document.getElementById('iocStats').textContent = iocFiltered.length + ' IOCs';
            document.getElementById('iocPageInfo').textContent = iocFiltered.length > 0 ? 
                'Page ' + iocPage + ' / ' + Math.max(1, Math.ceil(iocFiltered.length / iocPageSize)) : '';
        }
        
        function iocPrevPage() { if (iocPage > 1) { iocPage--; renderIOCs(); } }
        function iocNextPage() { if (iocPage < Math.ceil(iocFiltered.length / iocPageSize)) { iocPage++; renderIOCs(); } }
        
        // IOC event listeners
        if (document.getElementById('iocSearch')) {
            document.getElementById('iocSearch').addEventListener('input', function() {
                clearTimeout(debounceTimer);
                debounceTimer = setTimeout(filterIOCs, 200);
            });
            document.getElementById('iocTypeFilter').addEventListener('change', filterIOCs);
            // Initial IOC render
            renderIOCs();
        }
        
        // Event listeners with debounce
        document.getElementById('searchInput').addEventListener('input', function() {
            clearTimeout(debounceTimer);
            debounceTimer = setTimeout(applyFilters, 200);
        });
        document.getElementById('riskFilter').addEventListener('change', applyFilters);
        
        // Virtual scroll listener
        const virtualContainer = document.getElementById('virtualContainer');
        if (virtualContainer) {
            virtualContainer.addEventListener('scroll', onVirtualScroll, { passive: true });
        }
        
        // Chunked data loading for 100k+ files
        function initializeData() {
            updateLoading('Parsing JSON data...', 20, 'This may take a moment for large datasets');
            
            setTimeout(() => {
                try {
                    const rawData = document.getElementById('file-data').textContent || '[]';
                    updateLoading('Parsing ' + (rawData.length / 1024 / 1024).toFixed(1) + ' MB...', 30, '');
                    
                    setTimeout(() => {
                        filesData = JSON.parse(rawData);
                        const total = filesData.length;
                        updateLoading('Loaded ' + total.toLocaleString() + ' files', 60, 'Preparing display...');
                        
                        setTimeout(() => {
                            filtered = filesData;
                            updateLoading('Rendering...', 80, total.toLocaleString() + ' files ready');
                            
                            setTimeout(() => {
                                updateVirtualScroll();
                                buildIOCData();
                                renderIOCs();
                                updateLoading('Complete!', 100, total.toLocaleString() + ' files loaded');
                                
                                setTimeout(hideLoading, 300);
                            }, 50);
                        }, 50);
                    }, 50);
                } catch (e) {
                    updateLoading('Error loading data', 100, e.message);
                    console.error('Failed to parse file data:', e);
                    setTimeout(hideLoading, 2000);
                }
            }, 100);
        }
        
        // Start initialization
        initializeData();
    </script>
</body>
</html>
'''


def generate_html_report(
    files: List[FileInfo],
    summary: Dict[str, Any],
    output_path: str,
    scan_path: str,
    split_threshold: int = 0,
    part_number: int = 0,
    total_parts: int = 1
) -> None:
    """
    Generate an HTML report from scan results.
    
    Args:
        files: List of FileInfo objects
        summary: Scan summary dictionary
        output_path: Path to save the HTML file
        scan_path: Original path that was scanned
        split_threshold: If > 0, indicates this is a split report
        part_number: Current part number (0-indexed) for split reports
        total_parts: Total number of parts in split report
    """
    # Custom Jinja2 filter for file sizes
    def filesizeformat(value):
        if value is None:
            return '-'
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if abs(value) < 1024.0:
                return f"{value:.1f} {unit}"
            value /= 1024.0
        return f"{value:.1f} PB"
    
    template = Template(HTML_TEMPLATE)
    template.environment.filters['filesizeformat'] = filesizeformat
    
    # Convert FileInfo objects to dicts for template
    file_dicts = [f.to_dict() for f in files]
    
    # Sort by risk score (highest first)
    file_dicts.sort(key=lambda x: x.get('risk_score', 0), reverse=True)
    
    # Optimize JSON by removing null/empty values (reduces size by ~30-50%)
    def compact_dict(d):
        return {k: v for k, v in d.items() if v is not None and v != '' and v != [] and v != {}}
    
    compact_files = [compact_dict(f) for f in file_dicts]
    
    # Use separators without spaces and no indentation for smaller output
    files_json = json.dumps(compact_files, separators=(',', ':'))
    
    # Modify summary for split reports
    if split_threshold > 0:
        summary = summary.copy()
        summary['is_split_report'] = True
        summary['part_number'] = part_number + 1
        summary['total_parts'] = total_parts
        summary['files_in_part'] = len(file_dicts)
    
    html_content = template.render(
        files=file_dicts,
        files_json=files_json,
        summary=summary,
        scan_path=scan_path,
        generated_time=datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    )
    
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(html_content)


def generate_split_html_reports(
    files: List[FileInfo],
    summary: Dict[str, Any],
    output_path: str,
    scan_path: str,
    files_per_report: int = 50000
) -> List[str]:
    """
    Generate multiple HTML reports, splitting files across them.
    
    Args:
        files: List of FileInfo objects
        summary: Scan summary dictionary
        output_path: Base output path (e.g., 'report.html')
        scan_path: Original path that was scanned
        files_per_report: Maximum files per report
    
    Returns:
        List of generated report paths
    """
    if len(files) <= files_per_report:
        generate_html_report(files, summary, output_path, scan_path)
        return [output_path]
    
    # Calculate number of parts needed
    total_parts = (len(files) + files_per_report - 1) // files_per_report
    
    # Generate base path for split reports
    base_path = Path(output_path)
    stem = base_path.stem
    suffix = base_path.suffix or '.html'
    parent = base_path.parent
    
    generated_paths = []
    
    for part in range(total_parts):
        start_idx = part * files_per_report
        end_idx = min(start_idx + files_per_report, len(files))
        part_files = files[start_idx:end_idx]
        
        # Generate part filename: report_1.html, report_2.html, etc.
        part_path = parent / f"{stem}_{part + 1}{suffix}"
        
        generate_html_report(
            part_files, 
            summary, 
            str(part_path), 
            scan_path,
            split_threshold=files_per_report,
            part_number=part,
            total_parts=total_parts
        )
        generated_paths.append(str(part_path))
    
    return generated_paths


def generate_report(
    files: List[FileInfo],
    summary: Dict[str, Any],
    output_path: str,
    scan_path: str,
    format: str = 'html',
    split_threshold: int = 0
) -> List[str]:
    """
    Generate a report in the specified format.
    
    Args:
        files: List of FileInfo objects
        summary: Scan summary dictionary
        output_path: Path to save the report
        scan_path: Original path that was scanned
        format: 'html' or 'csv'
        split_threshold: If > 0, split HTML reports into parts with this many files each
    
    Returns:
        List of generated report paths
    """
    if format.lower() == 'csv':
        generate_csv_report(files, summary, output_path)
        return [output_path]
    else:
        if split_threshold > 0:
            return generate_split_html_reports(files, summary, output_path, scan_path, split_threshold)
        else:
            generate_html_report(files, summary, output_path, scan_path)
            return [output_path]
