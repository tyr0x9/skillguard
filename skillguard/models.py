from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional


class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Decision(Enum):
    PASS = "PASS"
    REVIEW = "REVIEW"
    BLOCK = "BLOCK"


class ExecutionSurface(Enum):
    INSTALL = "install"
    HOOK = "hook"
    MANUAL = "manual"
    RUNTIME = "runtime"


class Capability(Enum):
    SHELL = "shell"
    NETWORK = "network"
    FILESYSTEM = "filesystem"
    PROCESS = "process"


class AssetReach(Enum):
    SECRET = "secret"
    CREDENTIAL = "credential"
    KEY = "key"
    CONFIG = "config"


@dataclass
class Finding:
    rule_id: str
    title: str
    description: str
    severity: Severity
    file_path: str
    line_number: Optional[int]
    matched_text: str
    category: str
    execution_surface: List[ExecutionSurface] = field(default_factory=list)
    capabilities: List[Capability] = field(default_factory=list)
    asset_reach: List[AssetReach] = field(default_factory=list)


@dataclass
class ScanResult:
    target: str
    score: int
    decision: Decision
    findings: List[Finding]
    execution_surfaces: List[str]
    capabilities: List[str]
    asset_exposure: List[str]
    scanned_files: List[str]
    sbom: dict
    duration_seconds: float
