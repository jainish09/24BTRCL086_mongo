"""
Threat Advisor Data Models and Schemas
"""

from typing import List, Optional, Dict, Any
from enum import Enum
from pydantic import BaseModel, Field


class LifecycleStatus(str, Enum):
    ACTIVE = "Active"
    EVOLVING = "Evolving"
    ANTICIPATED = "Anticipated"
    RESOLVED = "Resolved"


class Platform(str, Enum):
    WINDOWS = "windows"
    LINUX = "linux"
    MACOS = "macos"
    ANDROID = "android"
    IOS = "ios"


class Verdict(str, Enum):
    AFFECTED = "AFFECTED"
    PATCHED = "PATCHED"
    NOT_AFFECTED = "NOT AFFECTED"
    UNKNOWN = "UNKNOWN"


class CPERange(BaseModel):
    criteria: str
    versionStartIncluding: Optional[str] = None
    versionStartExcluding: Optional[str] = None
    versionEndIncluding: Optional[str] = None
    versionEndExcluding: Optional[str] = None


class KEVBlock(BaseModel):
    isKev: bool = True
    dateAdded: Optional[str] = None
    dueDate: Optional[str] = None
    knownRansomwareCampaignUse: bool = False
    notes: Optional[str] = None


class MitigationPlaybook(BaseModel):
    platform: str
    steps: List[str]
    vendorAdvisories: List[str] = []
    patchAvailable: bool = True
    workaround: Optional[str] = None


class ThreatItem(BaseModel):
    cveId: str
    title: str
    description: str
    platforms: List[str]
    product: str
    vendor: str
    cvss: float
    epss: float
    kev: KEVBlock
    mitigation: Dict[str, MitigationPlaybook] = {}
    nvdVersionRanges: List[CPERange] = []
    publishedDate: str
    lastModifiedDate: str
    status: LifecycleStatus = LifecycleStatus.ACTIVE
    status_reason: str = ""
    rank: int = 1


class KnowledgeChunk(BaseModel):
    chunkId: str
    cveId: str
    platform: str
    status: str
    kind: str  # "threat_desc" | "mitigation_playbook" | "cpe_detail"
    text: str
    textHash: str
    embedding: List[float] = []


class ChatStreamRequest(BaseModel):
    question: str
    sessionId: Optional[str] = None
    platformFilter: Optional[str] = None
    statusFilter: Optional[str] = None
    deviceId: Optional[str] = None


class CompareRequest(BaseModel):
    question: str
    platform: Optional[str] = "windows"


class AgentRegisterRequest(BaseModel):
    installToken: str
    deviceHash: str
    hostname: str
    osVersion: str
    osBuild: str
    arch: str


class AgentPollRequest(BaseModel):
    deviceHash: str
    permanentToken: str


class AgentReportRequest(BaseModel):
    deviceHash: str
    permanentToken: str
    scanTime: str
    osBuild: str
    hotfixes: List[str] = []
    installedPrograms: List[Dict[str, Any]] = []
    storeApps: List[Dict[str, Any]] = []
    steamGames: List[Dict[str, Any]] = []
    securitySettings: Dict[str, Any] = {}
    listeningPorts: List[int] = []
    runningServices: List[str] = []
