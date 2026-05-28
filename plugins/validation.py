#!/usr/bin/env python3
"""
Validation helpers for normalized finding schema.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Optional

RISK_ORDER = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
CONFIDENCE_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CONFIRMED": 3}

def _generate_curl(request_raw: str, url: str) -> str:
    """Gera um comando cURL equivalente a partir de um request raw."""
    if not request_raw or not url:
        return ""
    
    lines = request_raw.strip().splitlines()
    if not lines:
        return ""
        
    first_line = lines[0].split()
    method = first_line[0] if len(first_line) > 0 else "GET"
    
    headers = []
    body = []
    is_body = False
    
    for line in lines[1:]:
        if is_body:
            body.append(line)
        elif not line.strip():
            is_body = True
        else:
            headers.append(line)
            
    curl = f"curl -i -s -k -X {method} '{url}'"
    
    for h in headers:
        if h.lower().startswith("host:") or h.lower().startswith("content-length:"):
            continue 
        h_escaped = h.replace("'", "'\\''")
        curl += f" \\\n    -H '{h_escaped}'"
        
    if body:
        body_str = "\\n".join(body).replace("'", "'\\''")
        curl += f" \\\n    --data-binary '{body_str}'"
        
    return curl


def has_minimum_proof(evidence: Optional[Dict[str, Any]]) -> bool:
    if not evidence:
        return False
    return bool(
        evidence.get("request_raw")
        or evidence.get("response_raw")
        or evidence.get("matched_snippet")
        or evidence.get("observable_impact")
    )


def calibrate_confidence(risk: str, requested_confidence: str, evidence: Optional[Dict[str, Any]]) -> str:
    risk_u = (risk or "LOW").upper()
    conf_u = (requested_confidence or "LOW").upper()
    if conf_u not in CONFIDENCE_ORDER:
        conf_u = "LOW"
    if risk_u in ("HIGH", "CRITICAL") and not has_minimum_proof(evidence):
        return "LOW"
    return conf_u


def finding(
    *,
    plugin: str,
    target: str,
    title: str,
    issue_type: str,
    risk: str,
    confidence: str,
    evidence: Optional[Dict[str, Any]] = None,
    description: str = "",
    url: str = "",
    detection: Optional[Dict[str, Any]] = None,
    validation: Optional[Dict[str, Any]] = None,
    metadata: Optional[Dict[str, Any]] = None,
    triage_tier: str = "",
    scope_status: str = "",
    http_status: Optional[int] = None,
) -> Dict[str, Any]:
    risk_u = (risk or "LOW").upper()
    confidence_u = calibrate_confidence(risk_u, confidence, evidence)
    
    # V11.6: Auto-generate cURL PoC if request_raw is present
    evidence_dict = evidence or {}
    if "request_raw" in evidence_dict and url and "curl_command" not in evidence_dict:
        evidence_dict["curl_command"] = _generate_curl(evidence_dict["request_raw"], url)
        
    out = {
        "schema_version": "1.0",
        "plugin": plugin,
        "target": target,
        "title": title,
        "type": issue_type,
        "risk": risk_u,
        "confidence": confidence_u,
        "description": description,
        "url": url,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "phases": {
            "detection": detection or {},
            "validation": validation or {},
        },
        "evidence": evidence_dict,
        "metadata": metadata or {},
    }
    if triage_tier:
        out["triage_tier"] = triage_tier.upper()
    if scope_status:
        out["scope_status"] = scope_status.upper()
    if http_status is not None:
        out["http_status"] = int(http_status)
    return out
