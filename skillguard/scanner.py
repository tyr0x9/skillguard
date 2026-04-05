"""Main scanner orchestrator for SkillGuard."""

import os
import time
import tempfile
import subprocess
from pathlib import Path
from typing import List, Optional, Set, Dict, Any

from skillguard.models import (
    Finding,
    ScanResult,
    Decision,
    Severity,
    ExecutionSurface,
    Capability,
    AssetReach,
)
from skillguard.rules.loader import load_rules, get_default_rules_dir
from skillguard.analyzers.file_analyzer import analyze_file, collect_files
from skillguard.analyzers.dependency_analyzer import (
    analyze_requirements_txt,
    analyze_package_json,
    analyze_pyproject_toml,
    check_missing_lockfiles,
    extract_sbom_from_requirements,
    extract_sbom_from_package_json,
)
from skillguard.analyzers.mcp_analyzer import analyze_mcp_config, is_mcp_config_file
from skillguard.allowlist import load_allowlist, Allowlist


# Score deductions per severity
SEVERITY_DEDUCTIONS = {
    Severity.CRITICAL: 40,
    Severity.HIGH: 20,
    Severity.MEDIUM: 10,
    Severity.LOW: 5,
    Severity.INFO: 0,
}

# Default thresholds
DEFAULT_PASS_THRESHOLD = 80
DEFAULT_REVIEW_THRESHOLD = 50


def _is_github_target(target: str) -> bool:
    """Check if target is a GitHub repo reference."""
    return target.startswith("github:") or (
        target.startswith("https://github.com/") or
        (not target.startswith("/") and not target.startswith(".") and "/" in target and not Path(target).exists())
    )


def _clone_github_repo(target: str) -> str:
    """Clone a GitHub repository to a temp directory and return the path."""
    # Normalize target: github:owner/repo or https://github.com/owner/repo or owner/repo
    if target.startswith("github:"):
        repo_ref = target[len("github:"):]
        url = f"https://github.com/{repo_ref}.git"
    elif target.startswith("https://github.com/"):
        url = target if target.endswith(".git") else target + ".git"
    else:
        url = f"https://github.com/{target}.git"

    tmp_dir = tempfile.mkdtemp(prefix="skillguard_")
    result = subprocess.run(
        ["git", "clone", "--depth=1", url, tmp_dir],
        capture_output=True,
        text=True,
        timeout=120,
    )
    if result.returncode != 0:
        raise RuntimeError(f"Failed to clone {url}: {result.stderr.strip()}")

    return tmp_dir


def _calculate_score(findings: List[Finding]) -> int:
    """Calculate risk score starting from 100, deducting for each finding."""
    score = 100
    for finding in findings:
        deduction = SEVERITY_DEDUCTIONS.get(finding.severity, 0)
        score -= deduction
    return max(0, score)


def _determine_decision(
    score: int,
    findings: List[Finding],
    pass_threshold: int = DEFAULT_PASS_THRESHOLD,
    review_threshold: int = DEFAULT_REVIEW_THRESHOLD,
) -> Decision:
    """Determine the scan decision based on score and dangerous combinations."""
    # Check for dangerous combinations that always result in BLOCK
    all_surfaces: Set[ExecutionSurface] = set()
    all_caps: Set[Capability] = set()
    all_assets: Set[AssetReach] = set()

    for f in findings:
        all_surfaces.update(f.execution_surface)
        all_caps.update(f.capabilities)
        all_assets.update(f.asset_reach)

    # BLOCK override: Install + Shell + Credential
    if (
        ExecutionSurface.INSTALL in all_surfaces and
        Capability.SHELL in all_caps and
        AssetReach.CREDENTIAL in all_assets
    ):
        return Decision.BLOCK

    # BLOCK override: Hook + Network + Secret
    if (
        ExecutionSurface.HOOK in all_surfaces and
        Capability.NETWORK in all_caps and
        AssetReach.SECRET in all_assets
    ):
        return Decision.BLOCK

    # Score-based decision
    if score >= pass_threshold:
        return Decision.PASS
    elif score >= review_threshold:
        return Decision.REVIEW
    else:
        return Decision.BLOCK


def _collect_execution_surfaces(findings: List[Finding]) -> List[str]:
    """Collect unique execution surfaces from findings."""
    surfaces: Set[str] = set()
    for f in findings:
        for s in f.execution_surface:
            surfaces.add(s.value)
    return sorted(surfaces)


def _collect_capabilities(findings: List[Finding]) -> List[str]:
    """Collect unique capabilities from findings."""
    caps: Set[str] = set()
    for f in findings:
        for c in f.capabilities:
            caps.add(c.value)
    return sorted(caps)


def _collect_asset_exposure(findings: List[Finding]) -> List[str]:
    """Collect unique asset exposure from findings."""
    assets: Set[str] = set()
    for f in findings:
        for a in f.asset_reach:
            assets.add(a.value)
    return sorted(assets)


def _build_sbom(target_dir: str) -> Dict[str, Any]:
    """Build a simple SBOM from detected dependency files."""
    packages = []
    target_path = Path(target_dir)

    req_file = target_path / "requirements.txt"
    if req_file.exists():
        packages.extend(extract_sbom_from_requirements(str(req_file)))

    pkg_json = target_path / "package.json"
    if pkg_json.exists():
        packages.extend(extract_sbom_from_package_json(str(pkg_json)))

    return {"packages": packages}


def scan(
    target: str,
    rules_dir: Optional[str] = None,
    pass_threshold: int = DEFAULT_PASS_THRESHOLD,
    review_threshold: int = DEFAULT_REVIEW_THRESHOLD,
) -> ScanResult:
    """
    Main scan function.

    Args:
        target: Local path, local file, or github:owner/repo
        rules_dir: Path to rules directory (uses default if None)
        pass_threshold: Score threshold for PASS decision
        review_threshold: Score threshold for REVIEW (below this = BLOCK)

    Returns:
        ScanResult with all findings and metadata
    """
    start_time = time.monotonic()
    tmp_dir: Optional[str] = None

    # Resolve target
    if _is_github_target(target):
        tmp_dir = _clone_github_repo(target)
        scan_path = tmp_dir
        display_target = target
    else:
        scan_path = os.path.abspath(target)
        display_target = target

    try:
        # Load rules
        if rules_dir is None:
            rules_dir = get_default_rules_dir()
        rules = load_rules(rules_dir)

        # Load allowlist
        if Path(scan_path).is_dir():
            allowlist = load_allowlist(scan_path)
        else:
            allowlist = load_allowlist(str(Path(scan_path).parent))

        all_findings: List[Finding] = []
        scanned_files: List[str] = []

        if Path(scan_path).is_file():
            # Single file scan
            file_path = scan_path
            base_dir = str(Path(scan_path).parent)

            if not allowlist.is_file_ignored(file_path):
                ignored_rules = allowlist.ignored_rules[:]

                # Specialized analysis for certain file types
                fname = Path(file_path).name
                if fname == "requirements.txt":
                    all_findings.extend(analyze_requirements_txt(file_path))
                elif fname == "package.json":
                    all_findings.extend(analyze_package_json(file_path))
                elif fname == "pyproject.toml":
                    all_findings.extend(analyze_pyproject_toml(file_path))
                elif is_mcp_config_file(file_path):
                    all_findings.extend(analyze_mcp_config(file_path))
                else:
                    all_findings.extend(
                        analyze_file(file_path, rules, ignored_rules, base_dir)
                    )

                scanned_files.append(file_path)

            sbom = {}
        else:
            # Directory scan
            files = collect_files(scan_path)
            base_dir = scan_path

            for file_path in files:
                # Check allowlist
                try:
                    rel_path = str(Path(file_path).relative_to(base_dir))
                except ValueError:
                    rel_path = file_path

                if allowlist.is_file_ignored(rel_path) or allowlist.is_file_ignored(file_path):
                    continue

                ignored_rules = allowlist.ignored_rules[:]
                fname = Path(file_path).name

                # Use specialized analyzers for certain files
                if fname == "requirements.txt":
                    findings = analyze_requirements_txt(file_path)
                    # Make paths relative
                    for f in findings:
                        try:
                            f.file_path = str(Path(f.file_path).relative_to(base_dir))
                        except ValueError:
                            pass
                    all_findings.extend(findings)
                elif fname == "package.json":
                    findings = analyze_package_json(file_path)
                    for f in findings:
                        try:
                            f.file_path = str(Path(f.file_path).relative_to(base_dir))
                        except ValueError:
                            pass
                    all_findings.extend(findings)
                elif fname == "pyproject.toml":
                    findings = analyze_pyproject_toml(file_path)
                    for f in findings:
                        try:
                            f.file_path = str(Path(f.file_path).relative_to(base_dir))
                        except ValueError:
                            pass
                    all_findings.extend(findings)
                elif is_mcp_config_file(file_path):
                    findings = analyze_mcp_config(file_path)
                    for f in findings:
                        try:
                            f.file_path = str(Path(f.file_path).relative_to(base_dir))
                        except ValueError:
                            pass
                    all_findings.extend(findings)
                else:
                    findings = analyze_file(file_path, rules, ignored_rules, base_dir)
                    all_findings.extend(findings)

                scanned_files.append(rel_path)

            # Check for missing lockfiles
            lockfile_findings = check_missing_lockfiles(scan_path)
            for f in lockfile_findings:
                try:
                    f.file_path = str(Path(f.file_path).relative_to(base_dir))
                except ValueError:
                    pass
            all_findings.extend(lockfile_findings)

            sbom = _build_sbom(scan_path)

        # Filter out globally ignored rules
        all_findings = [
            f for f in all_findings
            if not allowlist.is_rule_ignored(f.rule_id)
        ]

        # Deduplicate: same rule_id + file_path + line_number
        seen: Set[tuple] = set()
        deduped: List[Finding] = []
        for f in all_findings:
            key = (f.rule_id, f.file_path, f.line_number)
            if key not in seen:
                seen.add(key)
                deduped.append(f)
        all_findings = deduped

        # Sort findings by severity
        severity_order = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFO: 4,
        }
        all_findings.sort(key=lambda f: severity_order.get(f.severity, 99))

        # Calculate score and decision
        score = _calculate_score(all_findings)
        decision = _determine_decision(score, all_findings, pass_threshold, review_threshold)

        duration = time.monotonic() - start_time

        return ScanResult(
            target=display_target,
            score=score,
            decision=decision,
            findings=all_findings,
            execution_surfaces=_collect_execution_surfaces(all_findings),
            capabilities=_collect_capabilities(all_findings),
            asset_exposure=_collect_asset_exposure(all_findings),
            scanned_files=scanned_files,
            sbom=sbom,
            duration_seconds=round(duration, 3),
        )

    finally:
        # Cleanup temp dir if we cloned a repo
        if tmp_dir:
            import shutil
            shutil.rmtree(tmp_dir, ignore_errors=True)
