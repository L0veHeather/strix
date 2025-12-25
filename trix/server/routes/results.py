"""Results API Routes.

REST API endpoints for querying scan results and vulnerabilities.
"""

from __future__ import annotations

import logging
from typing import Any
from pathlib import Path

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import FileResponse, StreamingResponse
from pydantic import BaseModel, Field

from trix.storage import get_database, VulnerabilitySeverity
from trix.engine import ResultCollector

logger = logging.getLogger(__name__)
router = APIRouter()


# ==================== Request/Response Models ====================

class VulnerabilityResponse(BaseModel):
    """Response model for vulnerability data."""
    
    id: str
    scan_id: str
    title: str
    severity: str
    description: str | None
    url: str | None
    plugin_name: str | None
    phase: str | None
    verification_status: int
    discovered_at: str | None


class VulnerabilityListResponse(BaseModel):
    """Response model for vulnerability list."""
    
    vulnerabilities: list[VulnerabilityResponse]
    total: int
    stats: dict[str, Any]


class VerifyRequest(BaseModel):
    """Request model for verifying a vulnerability."""
    
    status: int = Field(..., ge=-1, le=1, description="-1=dismissed, 0=unverified, 1=verified")
    notes: str | None = None


class ExportRequest(BaseModel):
    """Request model for exporting results."""
    
    format: str = Field(default="json", description="Export format: json, markdown, sarif, csv")
    include_dismissed: bool = False
    severity_filter: list[str] | None = None


# ==================== Endpoints ====================

@router.get("/scan/{scan_id}/vulnerabilities", response_model=VulnerabilityListResponse)
async def get_scan_vulnerabilities(
    scan_id: str,
    severity: str | None = None,
    plugin: str | None = None,
    verified_only: bool = False,
    include_dismissed: bool = False,
    limit: int = Query(100, le=500),
    offset: int = 0,
):
    """Get vulnerabilities for a specific scan."""
    db = get_database()
    
    # Verify scan exists
    scan = db.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    # Get vulnerabilities
    vulns = db.get_vulnerabilities(
        scan_id=scan_id,
        severity=severity,
        plugin=plugin,
        verified_only=verified_only,
        exclude_dismissed=not include_dismissed,
    )
    
    # Apply pagination
    total = len(vulns)
    vulns = vulns[offset:offset + limit]
    
    # Get stats
    stats = db.get_vulnerability_stats(scan_id)
    
    return VulnerabilityListResponse(
        vulnerabilities=[
            VulnerabilityResponse(
                id=v.id,
                scan_id=v.scan_id,
                title=v.title,
                severity=v.severity.value if v.severity else "info",
                description=v.description,
                url=v.url,
                plugin_name=v.plugin_name,
                phase=v.phase,
                verification_status=v.verification_status,
                discovered_at=v.discovered_at.isoformat() if v.discovered_at else None,
            )
            for v in vulns
        ],
        total=total,
        stats=stats,
    )


@router.get("/vulnerability/{vuln_id}")
async def get_vulnerability(vuln_id: str):
    """Get detailed information about a vulnerability."""
    db = get_database()
    
    vuln = db.get_vulnerability(vuln_id)
    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerability not found")
    
    return vuln.to_dict()


@router.post("/vulnerability/{vuln_id}/verify")
async def verify_vulnerability(vuln_id: str, request: VerifyRequest):
    """Update verification status of a vulnerability."""
    db = get_database()
    
    vuln = db.verify_vulnerability(
        vuln_id=vuln_id,
        status=request.status,
        notes=request.notes,
    )
    
    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerability not found")
    
    status_names = {-1: "dismissed", 0: "unverified", 1: "verified"}
    
    return {
        "status": "updated",
        "vulnerability_id": vuln_id,
        "verification_status": status_names.get(request.status, "unknown"),
    }


@router.post("/vulnerability/{vuln_id}/dismiss")
async def dismiss_vulnerability(vuln_id: str, notes: str | None = None):
    """Dismiss a vulnerability (mark as false positive)."""
    db = get_database()
    
    vuln = db.verify_vulnerability(
        vuln_id=vuln_id,
        status=-1,
        notes=notes or "Dismissed as false positive",
    )
    
    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerability not found")
    
    return {
        "status": "dismissed",
        "vulnerability_id": vuln_id,
    }


@router.get("/scan/{scan_id}/stats")
async def get_scan_stats(scan_id: str):
    """Get statistics for a scan."""
    db = get_database()
    
    scan = db.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    # Vulnerability stats
    vuln_stats = db.get_vulnerability_stats(scan_id)
    
    # Phase results
    phase_results = db.get_phase_results(scan_id)
    
    # Calculate total duration
    total_duration_ms = sum(pr.duration_ms or 0 for pr in phase_results)
    
    return {
        "scan_id": scan_id,
        "target": scan.target,
        "status": scan.status.value if scan.status else "unknown",
        "duration_ms": total_duration_ms,
        "vulnerabilities": vuln_stats,
        "phases": {
            pr.phase: {
                "status": pr.status,
                "duration_ms": pr.duration_ms,
                "findings_count": pr.findings_count,
                "plugins_executed": pr.plugins_executed,
            }
            for pr in phase_results
        },
    }


@router.post("/scan/{scan_id}/export")
async def export_scan_results(scan_id: str, request: ExportRequest):
    """Export scan results in various formats."""
    db = get_database()
    
    scan = db.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    # Get vulnerabilities
    vulns = db.get_vulnerabilities(
        scan_id=scan_id,
        exclude_dismissed=not request.include_dismissed,
    )
    
    # Apply severity filter
    if request.severity_filter:
        severities = {s.lower() for s in request.severity_filter}
        vulns = [v for v in vulns if v.severity and v.severity.value in severities]
    
    # Create result collector
    collector = ResultCollector(scan_id)
    
    # Add findings
    for vuln in vulns:
        collector.add_finding({
            "title": vuln.title,
            "severity": vuln.severity.value if vuln.severity else "info",
            "description": vuln.description,
            "url": vuln.url,
            "plugin_name": vuln.plugin_name,
            "phase": vuln.phase,
            "cve_id": vuln.cve_id,
            "cwe_id": vuln.cwe_id,
            "evidence": vuln.evidence,
        })
    
    # Export based on format
    format_lower = request.format.lower()
    
    if format_lower == "json":
        content = collector.export_json()
        return StreamingResponse(
            iter([content]),
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="scan_{scan_id}.json"'},
        )
    
    elif format_lower == "markdown":
        content = collector.export_markdown()
        return StreamingResponse(
            iter([content]),
            media_type="text/markdown",
            headers={"Content-Disposition": f'attachment; filename="scan_{scan_id}.md"'},
        )
    
    elif format_lower == "sarif":
        content = collector.export_sarif()
        return StreamingResponse(
            iter([content]),
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="scan_{scan_id}.sarif.json"'},
        )
    
    elif format_lower == "csv":
        content = _export_csv(vulns)
        return StreamingResponse(
            iter([content]),
            media_type="text/csv",
            headers={"Content-Disposition": f'attachment; filename="scan_{scan_id}.csv"'},
        )
    
    else:
        raise HTTPException(status_code=400, detail=f"Unsupported format: {request.format}")


@router.get("/recent")
async def get_recent_vulnerabilities(
    limit: int = Query(20, le=100),
    severity: str | None = None,
):
    """Get recently discovered vulnerabilities across all scans."""
    db = get_database()
    
    vulns = db.get_vulnerabilities(
        severity=severity,
        exclude_dismissed=True,
    )
    
    # Sort by discovery time and limit
    vulns.sort(key=lambda v: v.discovered_at or "", reverse=True)
    vulns = vulns[:limit]
    
    return {
        "vulnerabilities": [
            {
                "id": v.id,
                "scan_id": v.scan_id,
                "title": v.title,
                "severity": v.severity.value if v.severity else "info",
                "url": v.url,
                "plugin_name": v.plugin_name,
                "discovered_at": v.discovered_at.isoformat() if v.discovered_at else None,
            }
            for v in vulns
        ]
    }


@router.get("/severity-breakdown")
async def get_severity_breakdown():
    """Get vulnerability breakdown by severity across all scans."""
    db = get_database()
    
    all_vulns = db.get_vulnerabilities(exclude_dismissed=True)
    
    breakdown = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
    }
    
    for vuln in all_vulns:
        if vuln.severity:
            breakdown[vuln.severity.value] += 1
    
    return {
        "breakdown": breakdown,
        "total": sum(breakdown.values()),
    }


def _export_csv(vulns) -> str:
    """Export vulnerabilities to CSV format."""
    import csv
    import io
    
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Header
    writer.writerow([
        "ID", "Title", "Severity", "URL", "Parameter", "Plugin",
        "Phase", "CVE", "CWE", "OWASP", "Verified", "Discovered At"
    ])
    
    # Data
    for vuln in vulns:
        writer.writerow([
            vuln.id,
            vuln.title,
            vuln.severity.value if vuln.severity else "",
            vuln.url or "",
            vuln.parameter or "",
            vuln.plugin_name or "",
            vuln.phase or "",
            vuln.cve_id or "",
            vuln.cwe_id or "",
            vuln.owasp_category or "",
            "Yes" if vuln.verification_status == 1 else "No",
            vuln.discovered_at.isoformat() if vuln.discovered_at else "",
        ])
    
    return output.getvalue()
