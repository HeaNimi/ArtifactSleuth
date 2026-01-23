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
        
        <!-- All Files -->
        <div class="section">
            <div class="section-header" onclick="toggleSection(this)">
                <h2>📁 All Files</h2>
                <span class="badge">{{ files | length }}</span>
            </div>
            <div class="section-content">
                <div class="filter-bar">
                    <input type="text" id="fileFilter" placeholder="Filter by filename..." onkeyup="filterFiles()">
                    <select id="riskFilter" onchange="filterFiles()">
                        <option value="">All Risk Levels</option>
                        <option value="high">High Risk (50+)</option>
                        <option value="medium">Medium Risk (25-49)</option>
                        <option value="low">Low Risk (1-24)</option>
                        <option value="none">No Risk (0)</option>
                    </select>
                </div>
                <table id="filesTable">
                    <thead>
                        <tr>
                            <th>Path</th>
                            <th>Size</th>
                            <th>MIME Type</th>
                            <th>Risk</th>
                            <th>SHA256</th>
                            <th>Details</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for file in files %}
                        <tr class="file-row" data-risk="{{ file.risk_score }}" data-name="{{ file.relative_path | lower }}">
                            <td>
                                {{ file.relative_path }}
                                {% if file.extension_mismatch %}
                                <span class="tag mismatch" title="Expected: {{ file.expected_extensions }}">⚠️ Mismatch</span>
                                {% endif %}
                            </td>
                            <td>{{ file.size | filesizeformat if file.size else '-' }}</td>
                            <td>{{ file.mime_type or '-' }}</td>
                            <td>
                                {% if file.risk_score >= 50 %}
                                <span class="risk-badge risk-high">{{ file.risk_score }}</span>
                                {% elif file.risk_score >= 25 %}
                                <span class="risk-badge risk-medium">{{ file.risk_score }}</span>
                                {% elif file.risk_score > 0 %}
                                <span class="risk-badge risk-low">{{ file.risk_score }}</span>
                                {% else %}
                                <span class="risk-badge risk-none">0</span>
                                {% endif %}
                            </td>
                            <td class="hash-cell">
                                {% if file.sha256 %}
                                <span class="hash-text" id="hash-{{ loop.index }}">{{ file.sha256[:16] }}...</span>
                                <button class="copy-btn" onclick="copyHash('{{ file.sha256 }}', this)" title="Copy full SHA256">📋</button>
                                {% else %}
                                -
                                {% endif %}
                            </td>
                            <td>
                                <button class="view-btn" onclick="toggleDetails('details-{{ loop.index }}')">View</button>
                            </td>
                        </tr>
                        <tr id="details-{{ loop.index }}" style="display: none;">
                            <td colspan="6">
                                <div class="details-grid">
                                    <div>
                                        <div class="detail-item">
                                            <div class="detail-label">Full Path</div>
                                            <div class="detail-value">{{ file.path }}</div>
                                        </div>
                                        <div class="detail-item">
                                            <div class="detail-label">MD5</div>
                                            <div class="detail-value">
                                                <span class="detail-value-text">{{ file.md5 or '-' }}</span>
                                                {% if file.md5 %}
                                                <button class="copy-btn" onclick="copyHash('{{ file.md5 }}', this)">📋</button>
                                                {% endif %}
                                            </div>
                                        </div>
                                        <div class="detail-item">
                                            <div class="detail-label">SHA1</div>
                                            <div class="detail-value">
                                                <span class="detail-value-text">{{ file.sha1 or '-' }}</span>
                                                {% if file.sha1 %}
                                                <button class="copy-btn" onclick="copyHash('{{ file.sha1 }}', this)">📋</button>
                                                {% endif %}
                                            </div>
                                        </div>
                                        <div class="detail-item">
                                            <div class="detail-label">SHA256</div>
                                            <div class="detail-value">
                                                <span class="detail-value-text">{{ file.sha256 or '-' }}</span>
                                                {% if file.sha256 %}
                                                <button class="copy-btn" onclick="copyHash('{{ file.sha256 }}', this)">📋</button>
                                                {% endif %}
                                            </div>
                                        </div>
                                    </div>
                                    <div>
                                        <div class="detail-item">
                                            <div class="detail-label">Type</div>
                                            <div class="detail-value">{{ file.friendly_type or (file.mime_type or 'File') }}</div>
                                        </div>
                                        <div class="detail-item">
                                            <div class="detail-label">File location</div>
                                            <div class="detail-value">{{ file.parent_folder or '-' }}</div>
                                        </div>
                                        <div class="detail-item">
                                            <div class="detail-label">Size</div>
                                            <div class="detail-value">{{ file.size | filesizeformat }} ({{ file.size }} bytes)</div>
                                        </div>
                                        <div class="detail-item">
                                            <div class="detail-label">Date created</div>
                                            <div class="detail-value">{{ file.created_time }}</div>
                                        </div>
                                        <div class="detail-item">
                                            <div class="detail-label">Date modified</div>
                                            <div class="detail-value">{{ file.modified_time }}</div>
                                        </div>
                                        <div class="detail-item">
                                            <div class="detail-label">Attributes</div>
                                            <div class="detail-value">{{ file.attributes or '-' }}</div>
                                        </div>
                                        <div class="detail-item">
                                            <div class="detail-label">Owner</div>
                                            <div class="detail-value">{{ file.owner or '-' }}</div>
                                        </div>
                                        <div class="detail-item">
                                            <div class="detail-label">Computer</div>
                                            <div class="detail-value">{{ file.computer or '-' }}</div>
                                        </div>
                                        {% if file.vt_link %}
                                        <div class="detail-item">
                                            <div class="detail-label">VirusTotal</div>
                                            <div class="detail-value">
                                                <a href="{{ file.vt_link }}" target="_blank" class="vt-link">
                                                    {{ file.vt_detection_ratio }} - View Report
                                                </a>
                                            </div>
                                        </div>
                                        {% endif %}
                                    </div>
                                </div>
                                
                                <!-- Document Properties -->
                                {% if file.doc_author or file.doc_last_modified_by or file.doc_company or file.doc_title %}
                                <div class="metadata-section">
                                    <h4>📄 Document Properties</h4>
                                    <div class="metadata-grid">
                                        {% if file.doc_author %}
                                        <div class="detail-item">
                                            <div class="detail-label">Author</div>
                                            <div class="detail-value">{{ file.doc_author }}</div>
                                        </div>
                                        {% endif %}
                                        {% if file.doc_last_modified_by %}
                                        <div class="detail-item">
                                            <div class="detail-label">Last Modified By</div>
                                            <div class="detail-value">{{ file.doc_last_modified_by }}</div>
                                        </div>
                                        {% endif %}
                                        {% if file.doc_company %}
                                        <div class="detail-item">
                                            <div class="detail-label">Company</div>
                                            <div class="detail-value">{{ file.doc_company }}</div>
                                        </div>
                                        {% endif %}
                                        {% if file.doc_title %}
                                        <div class="detail-item">
                                            <div class="detail-label">Title</div>
                                            <div class="detail-value">{{ file.doc_title }}</div>
                                        </div>
                                        {% endif %}
                                        {% if file.doc_subject %}
                                        <div class="detail-item">
                                            <div class="detail-label">Subject</div>
                                            <div class="detail-value">{{ file.doc_subject }}</div>
                                        </div>
                                        {% endif %}
                                        {% if file.doc_keywords %}
                                        <div class="detail-item">
                                            <div class="detail-label">Keywords</div>
                                            <div class="detail-value">{{ file.doc_keywords }}</div>
                                        </div>
                                        {% endif %}
                                        {% if file.doc_manager %}
                                        <div class="detail-item">
                                            <div class="detail-label">Manager</div>
                                            <div class="detail-value">{{ file.doc_manager }}</div>
                                        </div>
                                        {% endif %}
                                        {% if file.doc_category %}
                                        <div class="detail-item">
                                            <div class="detail-label">Category</div>
                                            <div class="detail-value">{{ file.doc_category }}</div>
                                        </div>
                                        {% endif %}
                                        {% if file.doc_created %}
                                        <div class="detail-item">
                                            <div class="detail-label">Doc Created</div>
                                            <div class="detail-value">{{ file.doc_created }}</div>
                                        </div>
                                        {% endif %}
                                        {% if file.doc_modified %}
                                        <div class="detail-item">
                                            <div class="detail-label">Doc Modified</div>
                                            <div class="detail-value">{{ file.doc_modified }}</div>
                                        </div>
                                        {% endif %}
                                    </div>
                                </div>
                                {% endif %}
                                
                                {% if file.extension_mismatch %}
                                <div class="ioc-section">
                                    <strong>⚠️ Extension Mismatch:</strong>
                                    <div class="ioc-list">
                                        <span class="tag mismatch">MIME: {{ file.mime_type }}</span>
                                        <span class="tag mismatch">Expected: {{ file.expected_extensions }}</span>
                                    </div>
                                </div>
                                {% endif %}
                                
                                <!-- Executable Information -->
                                {% if file.exe_company or file.exe_product or file.exe_version or file.exe_description or file.is_signed %}
                                <div class="metadata-section">
                                    <h4>⚙️ Executable Information</h4>
                                    <div class="metadata-grid">
                                        {% if file.exe_company %}
                                        <div class="detail-item">
                                            <div class="detail-label">Company</div>
                                            <div class="detail-value">{{ file.exe_company }}</div>
                                        </div>
                                        {% endif %}
                                        {% if file.exe_product %}
                                        <div class="detail-item">
                                            <div class="detail-label">Product</div>
                                            <div class="detail-value">{{ file.exe_product }}</div>
                                        </div>
                                        {% endif %}
                                        {% if file.exe_version %}
                                        <div class="detail-item">
                                            <div class="detail-label">Version</div>
                                            <div class="detail-value">{{ file.exe_version }}</div>
                                        </div>
                                        {% endif %}
                                        {% if file.exe_description %}
                                        <div class="detail-item">
                                            <div class="detail-label">Description</div>
                                            <div class="detail-value">{{ file.exe_description }}</div>
                                         </div>
                                        {% endif %}
                                        {% if file.is_signed %}
                                        <div class="detail-item">
                                            <div class="detail-label">Digital Signature</div>
                                            <div class="detail-value">
                                                <span class="tag info">✓ Signed</span>
                                            </div>
                                        </div>
                                        {% endif %}
                                        {% if file.sig_subject %}
                                        <div class="detail-item">
                                            <div class="detail-label">Signature Subject</div>
                                            <div class="detail-value">{{ file.sig_subject }}</div>
                                        </div>
                                        {% endif %}
                                        {% if file.sig_issuer %}
                                        <div class="detail-item">
                                            <div class="detail-label">Signature Issuer</div>
                                            <div class="detail-value">{{ file.sig_issuer }}</div>
                                        </div>
                                        {% endif %}
                                    </div>
                                </div>
                                {% endif %}
                                
                                {% if file.doc_suspicious_elements %}
                                <div class="ioc-section">
                                    <strong>Document Analysis:</strong>
                                    <div class="ioc-list">
                                        {% for elem in file.doc_suspicious_elements %}
                                        <span class="tag suspicious">{{ elem }}</span>
                                        {% endfor %}
                                    </div>
                                </div>
                                {% endif %}
                                
                                {% if file.exe_domains or file.exe_ips or file.exe_suspicious_imports %}
                                <div class="ioc-section">
                                    <strong>Executable Analysis:</strong>
                                    <div class="ioc-list">
                                        {% for domain in file.exe_domains[:10] %}
                                        <span class="tag network">{{ domain }}</span>
                                        {% endfor %}
                                        {% for ip in file.exe_ips[:10] %}
                                        <span class="tag network">{{ ip }}</span>
                                        {% endfor %}
                                        {% for imp in file.exe_suspicious_imports[:5] %}
                                        <span class="tag suspicious">{{ imp }}</span>
                                        {% endfor %}
                                    </div>
                                </div>
                                {% endif %}
                                
                                {% if file.risk_reasons %}
                                <div class="ioc-section">
                                    <strong>Risk Factors:</strong>
                                    <div class="ioc-list">
                                        {% for reason in file.risk_reasons %}
                                        <span class="tag suspicious">{{ reason }}</span>
                                        {% endfor %}
                                    </div>
                                </div>
                                {% endif %}
                            </td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
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
    
    <script>
        function toggleTheme() {
            const html = document.documentElement;
            const currentTheme = html.getAttribute('data-theme');
            html.setAttribute('data-theme', currentTheme === 'dark' ? 'light' : 'dark');
            localStorage.setItem('theme', html.getAttribute('data-theme'));
        }
        
        function toggleSection(header) {
            const content = header.nextElementSibling;
            content.classList.toggle('collapsed');
        }
        
        function toggleDetails(id) {
            const row = document.getElementById(id);
            row.style.display = row.style.display === 'none' ? 'table-row' : 'none';
        }
        
        function copyHash(hash, button) {
            navigator.clipboard.writeText(hash).then(() => {
                const originalText = button.textContent;
                button.textContent = '✓';
                button.classList.add('copied');
                setTimeout(() => {
                    button.textContent = originalText;
                    button.classList.remove('copied');
                }, 2000);
            }).catch(err => {
                console.error('Failed to copy: ', err);
            });
        }
        
        function filterFiles() {
            const nameFilter = document.getElementById('fileFilter').value.toLowerCase();
            const riskFilter = document.getElementById('riskFilter').value;
            const rows = document.querySelectorAll('.file-row');
            
            rows.forEach(row => {
                const name = row.getAttribute('data-name');
                const risk = parseInt(row.getAttribute('data-risk'));
                
                let showByName = name.includes(nameFilter);
                let showByRisk = true;
                
                if (riskFilter === 'high') showByRisk = risk >= 50;
                else if (riskFilter === 'medium') showByRisk = risk >= 25 && risk < 50;
                else if (riskFilter === 'low') showByRisk = risk > 0 && risk < 25;
                else if (riskFilter === 'none') showByRisk = risk === 0;
                
                row.style.display = (showByName && showByRisk) ? '' : 'none';
                
                // Also hide the details row
                const detailsRow = row.nextElementSibling;
                if (detailsRow && detailsRow.id && detailsRow.id.startsWith('details-')) {
                    if (!(showByName && showByRisk)) {
                        detailsRow.style.display = 'none';
                    }
                }
            });
        }
        
        // Load saved theme
        const savedTheme = localStorage.getItem('theme');
        if (savedTheme) {
            document.documentElement.setAttribute('data-theme', savedTheme);
        }
    </script>
</body>
</html>
'''


def generate_html_report(
    files: List[FileInfo],
    summary: Dict[str, Any],
    output_path: str,
    scan_path: str
) -> None:
    """
    Generate an HTML report from scan results.
    
    Args:
        files: List of FileInfo objects
        summary: Scan summary dictionary
        output_path: Path to save the HTML file
        scan_path: Original path that was scanned
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
    
    html_content = template.render(
        files=file_dicts,
        summary=summary,
        scan_path=scan_path,
        generated_time=datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    )
    
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(html_content)


def generate_report(
    files: List[FileInfo],
    summary: Dict[str, Any],
    output_path: str,
    scan_path: str,
    format: str = 'html'
) -> None:
    """
    Generate a report in the specified format.
    
    Args:
        files: List of FileInfo objects
        summary: Scan summary dictionary
        output_path: Path to save the report
        scan_path: Original path that was scanned
        format: 'html' or 'csv'
    """
    if format.lower() == 'csv':
        generate_csv_report(files, summary, output_path)
    else:
        generate_html_report(files, summary, output_path, scan_path)
