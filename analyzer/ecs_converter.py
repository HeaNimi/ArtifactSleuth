"""
ECS (Elastic Common Schema) conversion module.
Provides utilities for converting FileInfo objects to ECS format.
"""

from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List

from .metadata import FileInfo


def convert_to_ecs(file_info: FileInfo) -> Dict[str, Any]:
    """
    Convert a FileInfo object to Elastic Common Schema (ECS) format.
    
    This function implements the ECS 8.x specification mapping as defined in
    docs/ECS_NORMALIZATION_PLAN.md.
    
    Args:
        file_info: FileInfo object to convert
        
    Returns:
        Dictionary conforming to ECS format
    """
    # Extract file extension
    extension = Path(file_info.name).suffix.lstrip('.') if '.' in file_info.name else ''
    
    ecs_doc = {
        # Core ECS event metadata
        "event": {
            "kind": "event",
            "category": ["file"],
            "type": ["info"],
            "dataset": "artifactsleuth.file",
            "created": datetime.utcnow().isoformat() + "Z",
        },
        
        # File fields (ECS standard)
        "file": {
            "name": file_info.name,
            "path": file_info.path,
            "size": file_info.size,
        }
    }
    
    # Add file extension if present
    if extension:
        ecs_doc["file"]["extension"] = extension
    
    # Add timestamps
    if file_info.created_time:
        ecs_doc["file"]["created"] = _format_timestamp(file_info.created_time)
    if file_info.modified_time:
        ecs_doc["file"]["mtime"] = _format_timestamp(file_info.modified_time)
    if file_info.accessed_time:
        ecs_doc["file"]["accessed"] = _format_timestamp(file_info.accessed_time)
    
    # Add MIME type
    if file_info.mime_type:
        ecs_doc["file"]["mime_type"] = file_info.mime_type
    
    # Add file owner
    if file_info.owner:
        ecs_doc["file"]["owner"] = file_info.owner
    
    # Add file attributes (permissions)
    if file_info.attributes:
        ecs_doc["file"]["attributes"] = file_info.attributes
    
    # Add hash fields
    if file_info.md5 or file_info.sha1 or file_info.sha256:
        ecs_doc["file"]["hash"] = {}
        if file_info.md5:
            ecs_doc["file"]["hash"]["md5"] = file_info.md5
        if file_info.sha1:
            ecs_doc["file"]["hash"]["sha1"] = file_info.sha1
        if file_info.sha256:
            ecs_doc["file"]["hash"]["sha256"] = file_info.sha256
    
    # Add PE fields for executables
    if file_info.exe_company or file_info.exe_product or file_info.exe_description or file_info.exe_version:
        ecs_doc["file"]["pe"] = {}
        if file_info.exe_company:
            ecs_doc["file"]["pe"]["company"] = file_info.exe_company
        if file_info.exe_product:
            ecs_doc["file"]["pe"]["product"] = file_info.exe_product
        if file_info.exe_description:
            ecs_doc["file"]["pe"]["description"] = file_info.exe_description
        if file_info.exe_version:
            ecs_doc["file"]["pe"]["file_version"] = file_info.exe_version
    
    # Add code signature fields
    if file_info.is_signed is not None or file_info.sig_subject or file_info.sig_issuer:
        ecs_doc["file"]["code_signature"] = {}
        if file_info.is_signed is not None:
            ecs_doc["file"]["code_signature"]["exists"] = file_info.is_signed
        if file_info.sig_subject:
            ecs_doc["file"]["code_signature"]["subject_name"] = file_info.sig_subject
        if file_info.sig_issuer:
            ecs_doc["file"]["code_signature"]["issuer"] = file_info.sig_issuer
    
    # Add host information
    if file_info.computer:
        ecs_doc["host"] = {
            "name": file_info.computer
        }
    
    # Add related fields (IOCs)
    if file_info.exe_domains or file_info.exe_ips:
        ecs_doc["related"] = {}
        if file_info.exe_domains:
            ecs_doc["related"]["domains"] = file_info.exe_domains
        if file_info.exe_ips:
            ecs_doc["related"]["ip"] = file_info.exe_ips
    
    # Add threat enrichment (VirusTotal, Defender)
    enrichments = _build_threat_enrichments(file_info)
    if enrichments:
        ecs_doc["threat"] = {
            "enrichments": enrichments
        }
    
    # Add risk score to event
    if file_info.risk_score > 0:
        ecs_doc["event"]["risk_score"] = float(file_info.risk_score)
    
    # Add custom ArtifactSleuth namespace
    artifactsleuth = _build_artifactsleuth_namespace(file_info)
    if artifactsleuth:
        ecs_doc["artifactsleuth"] = artifactsleuth
    
    # Add @timestamp for Elasticsearch
    if file_info.modified_time:
        ecs_doc["@timestamp"] = _format_timestamp(file_info.modified_time)
    else:
        ecs_doc["@timestamp"] = datetime.utcnow().isoformat() + "Z"
    
    return ecs_doc


def _format_timestamp(dt: datetime) -> str:
    """Format datetime to ISO 8601 with Z suffix."""
    iso = dt.isoformat()
    return iso + "Z" if not iso.endswith('Z') else iso


def _build_threat_enrichments(file_info: FileInfo) -> List[Dict[str, Any]]:
    """Build threat enrichment array from VirusTotal and Defender results."""
    enrichments = []
    
    # VirusTotal enrichment
    if file_info.vt_detected is not None:
        vt_enrichment = {
            "indicator": {
                "type": "file"
            }
        }
        if file_info.vt_link:
            vt_enrichment["indicator"]["reference"] = file_info.vt_link
        if file_info.vt_detection_ratio:
            vt_enrichment["matched"] = {
                "atomic": file_info.vt_detection_ratio
            }
        enrichments.append(vt_enrichment)
    
    # Windows Defender enrichment
    if file_info.defender_detected:
        defender_enrichment = {
            "indicator": {
                "type": "file",
                "provider": "windows_defender"
            }
        }
        if file_info.defender_threat_name:
            defender_enrichment["indicator"]["description"] = file_info.defender_threat_name
        enrichments.append(defender_enrichment)
    
    return enrichments


def _build_artifactsleuth_namespace(file_info: FileInfo) -> Dict[str, Any]:
    """Build custom ArtifactSleuth namespace for fields not in ECS."""
    artifactsleuth = {}
    
    # Document fields
    if (file_info.doc_author or file_info.doc_last_modified_by or file_info.doc_title or 
        file_info.doc_subject or file_info.doc_company or file_info.doc_has_macros is not None or
        file_info.doc_has_javascript is not None or file_info.doc_suspicious_elements):
        artifactsleuth["document"] = {}
        if file_info.doc_author:
            artifactsleuth["document"]["author"] = file_info.doc_author
        if file_info.doc_last_modified_by:
            artifactsleuth["document"]["last_modified_by"] = file_info.doc_last_modified_by
        if file_info.doc_title:
            artifactsleuth["document"]["title"] = file_info.doc_title
        if file_info.doc_subject:
            artifactsleuth["document"]["subject"] = file_info.doc_subject
        if file_info.doc_company:
            artifactsleuth["document"]["company"] = file_info.doc_company
        if file_info.doc_has_macros is not None:
            artifactsleuth["document"]["has_macros"] = file_info.doc_has_macros
        if file_info.doc_has_javascript is not None:
            artifactsleuth["document"]["has_javascript"] = file_info.doc_has_javascript
        if file_info.doc_suspicious_elements:
            artifactsleuth["document"]["suspicious_elements"] = file_info.doc_suspicious_elements
    
    # IOC fields
    if file_info.exe_urls or file_info.exe_suspicious_imports:
        artifactsleuth["ioc"] = {}
        if file_info.exe_urls:
            artifactsleuth["ioc"]["urls"] = file_info.exe_urls
        if file_info.exe_suspicious_imports:
            artifactsleuth["ioc"]["suspicious_imports"] = file_info.exe_suspicious_imports
    
    # Archive fields
    if file_info.is_archive or file_info.is_password_protected or file_info.archive_path:
        artifactsleuth["archive"] = {}
        if file_info.is_archive:
            artifactsleuth["archive"]["is_archive"] = file_info.is_archive
        if file_info.is_password_protected:
            artifactsleuth["archive"]["is_password_protected"] = file_info.is_password_protected
        if file_info.archive_path:
            artifactsleuth["archive"]["parent_path"] = file_info.archive_path
    
    # Risk assessment fields
    if file_info.risk_reasons or file_info.extension_mismatch or file_info.expected_extensions:
        artifactsleuth["risk"] = {}
        if file_info.risk_reasons:
            artifactsleuth["risk"]["reasons"] = file_info.risk_reasons
        if file_info.extension_mismatch:
            artifactsleuth["risk"]["extension_mismatch"] = file_info.extension_mismatch
        if file_info.expected_extensions:
            artifactsleuth["risk"]["expected_extensions"] = file_info.expected_extensions
    
    return artifactsleuth
