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
        r"(?i)(network|http|internet|web\s+api|api\s+call|request|download|upload|fetch|send\s+data|external\s+service)",
    ),
    "filesystem": re.compile(
        r"(?i)(read\s+file|write\s+file|file\s+access|disk|storage|directory|path|file\s+system)",
    ),
    "shell": re.compile(
        r"(?i)(shell|exec|command|terminal|bash|run\s+script|subprocess|system\s+call)",
    ),
    "credentials": re.compile(
        r"(?i)(credential|auth|token|api\s+key|secret|password|ssh|aws|gcp|cloud\s+key|environment\s+variable)",
    ),
    "process": re.compile(
        r"(?i)(spawn\s+process|child\s+process|fork|dynamic\s+(import|load)|importlib|plugin)",
    ),
    "data_output": re.compile(
        r"(?i)(return\s+data|output|print|log\s+data|emit|yield\s+result)",
    ),
}

# Code patterns indicating actual capability use
CODE_CAP_PATTERNS = {
    "network": re.compile(
        r"(requests\.|urllib|http\.client|socket\.|fetch\(|axios\.|curl\b|wget\b|aiohttp|httpx\.)",
        re.IGNORECASE,
    ),
    "filesystem": re.compile(
        r"(open\s*\(|os\.path\.|pathlib\.|shutil\.|os\.remove|os\.rename|glob\.|os\.walk)",
        re.IGNORECASE,
    ),
    "shell": re.compile(
        r"(subprocess\.|os\.system\s*\(|os\.popen\s*\(|\beval\s*\(|\bexec\s*\(|os\.execv)",
        re.IGNORECASE,
    ),
    "credentials": re.compile(
        r"(\.aws[/\\]|\.ssh[/\\]|id_rsa|\.env|kubeconfig|api_key|secret_key|password\s*=|os\.environ|getenv\s*\()",
        re.IGNORECASE,
    ),
    "process": re.compile(
        r"(importlib\.import_module|__import__\s*\(|getattr\s*\([^)]+\)\s*\(|multiprocessing\.|threading\.)",
        re.IGNORECASE,
    ),
    "data_output": re.compile(
        r"(print\s*\([^)]{0,200}(environ|password|secret|token|api_key)|return\s+dict\s*\(\s*os\.environ|sys\.stdout\.write)",
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

    # Capabilities that are especially dangerous when undeclared
    CRITICAL_UNDECLARED = {"credentials", "shell"}
    HIGH_UNDECLARED = {"network", "process"}
    # data_output is lower risk on its own
    MEDIUM_UNDECLARED = {"data_output", "filesystem"}

    for cap in sorted(actual_caps - declared_caps):
        if cap in CRITICAL_UNDECLARED:
            severity = Severity.CRITICAL
        elif cap in HIGH_UNDECLARED:
            severity = Severity.HIGH
        elif cap in MEDIUM_UNDECLARED:
            severity = Severity.MEDIUM
        else:
            severity = Severity.HIGH

        findings.append(Finding(
            rule_id=f"skill_undeclared_cap_{cap}",
            title=f"Undeclared capability: {cap}",
            description=(
                f"Code uses '{cap}' capability but SKILL.md does not declare it. "
                f"Skills should explicitly list all capabilities they use. "
                f"Undeclared capabilities may indicate hidden or unreviewed behavior."
            ),
            severity=severity,
            file_path="SKILL.md",
            line_number=None,
            matched_text=f"code uses '{cap}' \u2014 not declared in SKILL.md",
            category="mcp_agent",
            execution_surface=[ExecutionSurface.RUNTIME],
            capabilities=[],
            asset_reach=[],
        ))

    return findings
