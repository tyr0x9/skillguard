import re
import fnmatch
from pathlib import Path
from typing import List, Optional

from skillguard.models import (
    Finding,
    Severity,
    ExecutionSurface,
    Capability,
    AssetReach,
)
from skillguard.rules.loader import Rule


def _severity_from_str(s: str) -> Severity:
    mapping = {
        "CRITICAL": Severity.CRITICAL,
        "HIGH": Severity.HIGH,
        "MEDIUM": Severity.MEDIUM,
        "LOW": Severity.LOW,
        "INFO": Severity.INFO,
    }
    return mapping.get(s.upper(), Severity.MEDIUM)


def _execution_surfaces(values: List[str]) -> List[ExecutionSurface]:
    mapping = {
        "install": ExecutionSurface.INSTALL,
        "hook": ExecutionSurface.HOOK,
        "manual": ExecutionSurface.MANUAL,
        "runtime": ExecutionSurface.RUNTIME,
    }
    return [mapping[v] for v in values if v in mapping]


def _capabilities(values: List[str]) -> List[Capability]:
    mapping = {
        "shell": Capability.SHELL,
        "network": Capability.NETWORK,
        "filesystem": Capability.FILESYSTEM,
        "process": Capability.PROCESS,
    }
    return [mapping[v] for v in values if v in mapping]


def _asset_reach(values: List[str]) -> List[AssetReach]:
    mapping = {
        "secret": AssetReach.SECRET,
        "credential": AssetReach.CREDENTIAL,
        "key": AssetReach.KEY,
        "config": AssetReach.CONFIG,
    }
    return [mapping[v] for v in values if v in mapping]


def file_matches_patterns(file_path: str, file_patterns: List[str]) -> bool:
    """Check if a file path matches any of the given glob patterns."""
    filename = Path(file_path).name
    rel_path = file_path

    for pattern in file_patterns:
        if fnmatch.fnmatch(filename, pattern):
            return True
        if fnmatch.fnmatch(rel_path, pattern):
            return True
        # Also check against path parts
        if fnmatch.fnmatch(file_path, f"*/{pattern}"):
            return True

    return False


def parse_inline_ignores(line: str) -> List[str]:
    """Extract rule IDs from inline skillguard:ignore comments."""
    ignored = []
    pattern = r"#\s*skillguard:ignore\s+([\w,\s]+)"
    match = re.search(pattern, line)
    if match:
        ids = match.group(1).split(",")
        ignored = [rid.strip() for rid in ids if rid.strip()]
    return ignored


def match_rules(
    file_path: str,
    content: str,
    rules: List[Rule],
    ignored_rules: Optional[List[str]] = None,
) -> List[Finding]:
    """Match rules against file content and return findings."""
    if ignored_rules is None:
        ignored_rules = []

    findings = []
    lines = content.splitlines()

    # Build per-line ignore sets
    line_ignores: dict = {}
    for i, line in enumerate(lines, 1):
        inline = parse_inline_ignores(line)
        if inline:
            line_ignores[i] = set(inline)

    for rule in rules:
        if rule.id in ignored_rules:
            continue

        # Check if the file matches this rule's file_patterns
        if rule.file_patterns and not file_matches_patterns(file_path, rule.file_patterns):
            continue

        for pattern_str in rule.patterns:
            try:
                regex = re.compile(pattern_str, re.IGNORECASE | re.MULTILINE)
            except re.error:
                continue

            for i, line in enumerate(lines, 1):
                # Check inline ignore for this line
                if i in line_ignores and rule.id in line_ignores[i]:
                    continue

                match = regex.search(line)
                if match:
                    matched_text = line.strip()
                    finding = Finding(
                        rule_id=rule.id,
                        title=rule.title,
                        description=rule.description,
                        severity=_severity_from_str(rule.severity),
                        file_path=file_path,
                        line_number=i,
                        matched_text=matched_text[:200],
                        category=rule.category,
                        execution_surface=_execution_surfaces(rule.execution_surface),
                        capabilities=_capabilities(rule.capabilities),
                        asset_reach=_asset_reach(rule.asset_reach),
                    )
                    findings.append(finding)
                    break  # Only report first match per rule per file

    return findings
