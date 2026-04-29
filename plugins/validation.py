#!/usr/bin/env python3
"""
Validation helpers for normalized finding schema.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Optional

RISK_ORDER = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
CONFIDENCE_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CONFIRMED": 3}


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
) -> Dict[str, Any]:
    risk_u = (risk or "LOW").upper()
    confidence_u = calibrate_confidence(risk_u, confidence, evidence)
    return {
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
        "evidence": evidence or {},
        "metadata": metadata or {},
    }
