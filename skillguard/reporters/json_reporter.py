"""JSON reporter for SkillGuard scan results."""

import json
import sys
from typing import Optional, TextIO, Any, Dict

from skillguard.models import ScanResult, Finding


def _finding_to_dict(finding: Finding) -> Dict[str, Any]:
    """Convert a Finding to a JSON-serializable dict."""
    return {
        "rule_id": finding.rule_id,
        "title": finding.title,
        "description": finding.description,
        "severity": finding.severity.value,
        "file_path": finding.file_path,
        "line_number": finding.line_number,
        "matched_text": finding.matched_text,
        "category": finding.category,
        "execution_surface": [s.value for s in finding.execution_surface],
        "capabilities": [c.value for c in finding.capabilities],
        "asset_reach": [a.value for a in finding.asset_reach],
    }


def _result_to_dict(result: ScanResult) -> Dict[str, Any]:
    """Convert a ScanResult to a JSON-serializable dict."""
    return {
        "target": result.target,
        "score": result.score,
        "decision": result.decision.value,
        "findings": [_finding_to_dict(f) for f in result.findings],
        "findings_count": len(result.findings),
        "execution_surfaces": result.execution_surfaces,
        "capabilities": result.capabilities,
        "asset_exposure": result.asset_exposure,
        "scanned_files": result.scanned_files,
        "scanned_files_count": len(result.scanned_files),
        "sbom": result.sbom,
        "duration_seconds": result.duration_seconds,
        "summary": {
            "critical": sum(1 for f in result.findings if f.severity.value == "CRITICAL"),
            "high": sum(1 for f in result.findings if f.severity.value == "HIGH"),
            "medium": sum(1 for f in result.findings if f.severity.value == "MEDIUM"),
            "low": sum(1 for f in result.findings if f.severity.value == "LOW"),
            "info": sum(1 for f in result.findings if f.severity.value == "INFO"),
        },
    }


class JsonReporter:
    """Formats scan results as JSON output."""

    def __init__(self, indent: int = 2, file: Optional[TextIO] = None):
        self.indent = indent
        self.file = file or sys.stdout

    def report(self, result: ScanResult) -> None:
        """Output scan results as JSON."""
        data = _result_to_dict(result)
        json.dump(data, self.file, indent=self.indent, ensure_ascii=False)
        print(file=self.file)  # Trailing newline

    def to_dict(self, result: ScanResult) -> Dict[str, Any]:
        """Convert result to dictionary."""
        return _result_to_dict(result)

    def to_json(self, result: ScanResult) -> str:
        """Convert result to JSON string."""
        return json.dumps(_result_to_dict(result), indent=self.indent, ensure_ascii=False)
