"""
Analyzer for SKILL.md files.
Detects mismatches between declared capabilities and actual code behavior.
"""
import re
from pathlib import Path
from typing import List, Set

from skillguard.models import Finding, Severity, ExecutionSurface, Capability, AssetReach


# Keywords that indicate a capability is declared in SKILL.md
DECLARED_CAP_PATTERNS = {
    "network": re.compile(
        r"(?i)(network|http|internet|web\s+api|api\s+call|request|download|upload|fetch|send\s+data)",
    ),
    "filesystem": re.compile(
        r"(?i)(read\s+file|write\s+file|file\s+access|disk|storage|directory|path)",
    ),
    "shell": re.compile(
        r"(?i)(shell|exec|command|terminal|bash|run\s+script|subprocess)",
    ),
    "credentials": re.compile(
        r"(?i)(credential|auth|token|api\s+key|secret|password|ssh|aws|gcp|cloud\s+key)",
    ),
}

# Code patterns indicating actual capability use
CODE_CAP_PATTERNS = {
    "network": re.compile(
        r"(requests\.|urllib|http\.client|socket\.|fetch\(|axios\.|curl\b|wget\b|aiohttp)",
        re.IGNORECASE,
    ),
    "filesystem": re.compile(
        r"(open\s*\(|os\.path\.|pathlib\.|shutil\.|os\.remove|os\.rename|glob\.)",
        re.IGNORECASE,
    ),
    "shell": re.compile(
        r"(subprocess\.|os\.system\s*\(|os\.popen\s*\(|\beval\s*\(|\bexec\s*\()",
        re.IGNORECASE,
    ),
    "credentials": re.compile(
        r"(\.aws[/\\]|\.ssh[/\\]|id_rsa|\.env|kubeconfig|api_key|secret_key|password\s*=)",
        re.IGNORECASE,
    ),
}

CODE_EXTENSIONS = {".py", ".js", ".ts", ".sh", ".bash"}


def analyze_skill_md(skill_md_path: str, scan_dir: str) -> List[Finding]:
    """
    Analyze SKILL.md for capability declarations and compare against code.
    Returns HIGH findings for capabilities used in code but not declared in SKILL.md.
    """
    findings = []
    skill_path = Path(skill_md_path)
    if not skill_path.exists():
        return findings

    try:
        skill_content = skill_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return findings

    declared_caps: Set[str] = set()
    for cap, pattern in DECLARED_CAP_PATTERNS.items():
        if pattern.search(skill_content):
            declared_caps.add(cap)

    actual_caps: Set[str] = set()
    for code_file in Path(scan_dir).rglob("*"):
        if code_file.suffix.lower() not in CODE_EXTENSIONS:
            continue
        if code_file.name in {"SKILL.md"}:
            continue
        try:
            code_content = code_file.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for cap, pattern in CODE_CAP_PATTERNS.items():
            if pattern.search(code_content):
                actual_caps.add(cap)

    for cap in sorted(actual_caps - declared_caps):
        findings.append(Finding(
            rule_id=f"skill_undeclared_cap_{cap}",
            title=f"Undeclared capability: {cap}",
            description=(
                f"Code uses '{cap}' capability but SKILL.md does not declare it. "
                f"Skills should explicitly list all capabilities. "
                f"Undeclared capabilities may indicate hidden or unreviewed behavior."
            ),
            severity=Severity.HIGH,
            file_path="SKILL.md",
            line_number=None,
            matched_text=f"code uses '{cap}' \u2014 not declared in SKILL.md",
            category="mcp_agent",
            execution_surface=[ExecutionSurface.RUNTIME],
            capabilities=[],
            asset_reach=[],
        ))

    return findings
