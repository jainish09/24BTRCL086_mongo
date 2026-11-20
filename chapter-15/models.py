"""
Chapter 15 Standalone Schema & Seed Utilities
Multi-Tenant Threat Intelligence Case Management
"""

import json
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any

class OrganisationSchema(BaseModel):
    id: str
    name: str
    slug: str
    tier: str = "enterprise"
    max_cases: int = 1000
    features: List[str] = Field(default_factory=lambda: ["cases", "ioc_enrichment", "audit_log"])

class CaseSchema(BaseModel):
    id: str
    org_id: str
    title: str
    description: str
    severity: str = "HIGH"
    status: str = "OPEN"
    assigned_to: Optional[str] = None
    created_by: str
    threat_ids: List[str] = Field(default_factory=list)
    event_ids: List[str] = Field(default_factory=list)
    created_at: str

SAMPLE_ORGANISATIONS = [
    {"id": "org_gov_cyber", "name": "National Cyber Defense Center", "slug": "ncdc", "tier": "enterprise"},
    {"id": "org_fin_cert", "name": "Financial Services Information Sharing Center", "slug": "fs-isac", "tier": "enterprise"},
    {"id": "org_telecom_soc", "name": "Global Telecom SOC Alliance", "slug": "telecom-soc", "tier": "business"}
]

SAMPLE_CASES = [
    {
        "id": "CASE-2026-001",
        "org_id": "org_gov_cyber",
        "title": "Suspected Akira Ransomware Lateral Movement via VPN Gateway",
        "description": "Lateral movement detected originating from anomalous IP targeting critical infrastructure.",
        "severity": "CRITICAL",
        "status": "IN_PROGRESS",
        "assigned_to": "analyst_alice",
        "created_by": "sec_admin_01",
        "threat_ids": ["THR-2026-1004"],
        "event_ids": ["EVT-88219"],
        "created_at": "2026-11-15T08:30:00Z"
    },
    {
        "id": "CASE-2026-002",
        "org_id": "org_fin_cert",
        "title": "RedLine Stealer Credential Harvester Campaign",
        "description": "Credential harvesting campaign hitting customer-facing banking portals.",
        "severity": "HIGH",
        "status": "OPEN",
        "assigned_to": "analyst_bob",
        "created_by": "fin_admin",
        "threat_ids": ["THR-2026-1008"],
        "event_ids": ["EVT-90412"],
        "created_at": "2026-11-15T10:15:00Z"
    }
]

if __name__ == "__main__":
    print(f"Loaded {len(SAMPLE_ORGANISATIONS)} organisations and {len(SAMPLE_CASES)} multi-tenant cases.")

