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
    
    with open(output_path, 'w', newline='', encoding='utf-8') as f:
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
            margin-bottom: 2rem;
            padding-bottom: 1rem;
            border-bottom: 1px solid var(--border);
        }
        
        h1 {
            font-size: 1.875rem;
            font-weight: 700;
            color: var(--text-primary);
        }
        
        .header-meta {
            color: var(--text-secondary);
            font-size: 0.875rem;
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
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin-bottom: 2rem;
        }
        
        .summary-card {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 0.75rem;
            padding: 1.25rem;
        }
        
        .summary-card h3 {
            font-size: 0.75rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            color: var(--text-secondary);
            margin-bottom: 0.5rem;
        }
        
        .summary-card .value {
            font-size: 1.5rem;
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
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div>
                <h1>🔍 ArtifactSleuth Forensic Report</h1>
                <div class="header-meta">
                    Generated: {{ generated_time }} | Scanned: {{ scan_path }}
                </div>
            </div>
            <button class="theme-toggle" onclick="toggleTheme()">
                🌓 Toggle Theme
            </button>
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
                    <select id="pageSize">
                        <option value="100">100 / page</option>
                        <option value="250" selected>250 / page</option>
                        <option value="500">500 / page</option>
                        <option value="1000">1000 / page</option>
                    </select>
                    <span id="resultStats" style="color: var(--text-secondary); font-size: 0.875rem;">Loading...</span>
                </div>
                <table id="filesTable">
                    <thead>
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
        <div id="detailPanel" style="display:none; position:fixed; top:0; right:0; width:500px; height:100vh; background:var(--bg-card); border-left:1px solid var(--border); overflow-y:auto; z-index:1000; padding:1.5rem;">
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:1rem;">
                <h3 style="margin:0;">File Details</h3>
                <button class="view-btn" onclick="closeDetails()">✕ Close</button>
            </div>
            <div id="detailBody"></div>
        </div>
        
        <!-- Extension Mismatch Files -->
        {% set mismatch_files = files | selectattr('extension_mismatch') | list %}
        {% if mismatch_files %}
        <div class="section">
            <div class="section-header" onclick="toggleSection(this)">
                <h2>⚠️ Extension Mismatch (Potential File Spoofing)</h2>
                <span class="badge">{{ mismatch_files | length }}</span>
            </div>
            <div class="section-content collapsed">
                <table>
                    <thead>
                        <tr>
                            <th>File</th>
                            <th>Actual MIME Type</th>
                            <th>Expected Extensions</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for file in mismatch_files %}
                        <tr>
                            <td>{{ file.relative_path }}</td>
                            <td>{{ file.mime_type }}</td>
                            <td><span class="tag mismatch">{{ file.expected_extensions }}</span></td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
        </div>
        {% endif %}
        
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
                {% if all_domains %}
                <div class="ioc-section">
                    <strong>Domains Found:</strong>
                    <div class="ioc-list">
                        {% for domain in all_domains[:50] %}
                        <span class="tag network">{{ domain }}</span>
                        {% endfor %}
                        {% if all_domains | length > 50 %}
                        <span class="tag">... and {{ (all_domains | length) - 50 }} more</span>
                        {% endif %}
                    </div>
                </div>
                {% endif %}
                
                {% if all_ips %}
                <div class="ioc-section">
                    <strong>IP Addresses Found:</strong>
                    <div class="ioc-list">
                        {% for ip in all_ips[:50] %}
                        <span class="tag network">{{ ip }}</span>
                        {% endfor %}
                        {% if all_ips | length > 50 %}
                        <span class="tag">... and {{ (all_ips | length) - 50 }} more</span>
                        {% endif %}
                    </div>
                </div>
                {% endif %}
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
        const filesData = JSON.parse(document.getElementById('file-data').textContent || '[]');
        let filtered = filesData;
        let page = 1;
        let pageSize = 250;
        let debounceTimer = null;
        
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
            render();
        }
        
        function render() {
            const tbody = document.getElementById('filesBody');
            if (!tbody) return;
            const start = (page - 1) * pageSize;
            const end = Math.min(start + pageSize, filtered.length);
            let html = '';
            for (let i = start; i < end; i++) {
                const f = filtered[i];
                const mismatch = f.extension_mismatch ? '<span class="tag mismatch">⚠️</span>' : '';
                const sha = f.sha256 ? (f.sha256.substring(0,16) + '...') : '-';
                const mime = f.mime_type ? (f.mime_type.length > 40 ? f.mime_type.substring(0,40)+'...' : f.mime_type) : '-';
                html += '<tr><td>' + (f.relative_path||f.name||'') + mismatch + '</td><td>' + formatSize(f.size) + '</td><td class="mime-cell" title="'+(f.mime_type||'')+'">' + mime + '</td><td>' + riskBadge(f.risk_score||0) + '</td><td class="hash-cell">' + sha + '</td><td><button class="view-btn" onclick="showDetails(' + i + ')">View</button></td></tr>';
            }
            tbody.innerHTML = html;
            document.getElementById('resultStats').textContent = filtered.length + ' matching • showing ' + (start+1) + '-' + end;
            document.getElementById('pageInfo').textContent = 'Page ' + page + ' / ' + Math.max(1, Math.ceil(filtered.length / pageSize));
        }
        
        function prevPage() { if (page > 1) { page--; render(); } }
        function nextPage() { if (page < Math.ceil(filtered.length / pageSize)) { page++; render(); } }
        
        function showDetails(idx) {
            const f = filtered[idx];
            if (!f) return;
            const panel = document.getElementById('detailPanel');
            const body = document.getElementById('detailBody');
            body.innerHTML = '<div class="details-grid">' +
                '<div class="detail-item"><div class="detail-label">Full Path</div><div class="detail-value">' + (f.path||f.relative_path||'') + '</div></div>' +
                '<div class="detail-item"><div class="detail-label">Size</div><div class="detail-value">' + formatSize(f.size) + ' (' + (f.size||0) + ' bytes)</div></div>' +
                '<div class="detail-item"><div class="detail-label">MIME</div><div class="detail-value">' + (f.mime_type||'-') + '</div></div>' +
                '<div class="detail-item"><div class="detail-label">Type</div><div class="detail-value">' + (f.friendly_type||'-') + '</div></div>' +
                '<div class="detail-item"><div class="detail-label">Created</div><div class="detail-value">' + (f.created_time||'-') + '</div></div>' +
                '<div class="detail-item"><div class="detail-label">Modified</div><div class="detail-value">' + (f.modified_time||'-') + '</div></div>' +
                '<div class="detail-item"><div class="detail-label">Owner</div><div class="detail-value">' + (f.owner||'-') + '</div></div>' +
                '<div class="detail-item"><div class="detail-label">Computer</div><div class="detail-value">' + (f.computer||'-') + '</div></div>' +
                '<div class="detail-item"><div class="detail-label">MD5</div><div class="detail-value">' + (f.md5||'-') + (f.md5 ? ' <button class="copy-btn" onclick="copyHash(\\''+f.md5+'\\',this)">📋</button>' : '') + '</div></div>' +
                '<div class="detail-item"><div class="detail-label">SHA1</div><div class="detail-value">' + (f.sha1||'-') + (f.sha1 ? ' <button class="copy-btn" onclick="copyHash(\\''+f.sha1+'\\',this)">📋</button>' : '') + '</div></div>' +
                '<div class="detail-item"><div class="detail-label">SHA256</div><div class="detail-value" style="word-break:break-all;">' + (f.sha256||'-') + (f.sha256 ? ' <button class="copy-btn" onclick="copyHash(\\''+f.sha256+'\\',this)">📋</button>' : '') + '</div></div>' +
                '</div>';
            panel.style.display = 'block';
        }
        function closeDetails() { document.getElementById('detailPanel').style.display = 'none'; }
        
        // Event listeners with debounce
        document.getElementById('searchInput').addEventListener('input', function() {
            clearTimeout(debounceTimer);
            debounceTimer = setTimeout(applyFilters, 200);
        });
        document.getElementById('riskFilter').addEventListener('change', applyFilters);
        document.getElementById('pageSize').addEventListener('change', function() {
            pageSize = parseInt(this.value, 10) || 250;
            page = 1;
            render();
        });
        
        // Initial render
        applyFilters();
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
    
    # Modify summary for split reports
    if split_threshold > 0:
        summary = summary.copy()
        summary['is_split_report'] = True
        summary['part_number'] = part_number + 1
        summary['total_parts'] = total_parts
        summary['files_in_part'] = len(file_dicts)
    
    html_content = template.render(
        files=file_dicts,
        files_json=json.dumps(file_dicts),
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
