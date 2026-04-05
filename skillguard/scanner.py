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
from skillguard.analyzers.skill_analyzer import analyze_skill_md
from skillguard.allowlist import load_allowlist, Allowlist


SEVERITY_DEDUCTIONS = {
    Severity.CRITICAL: 40,
    Severity.HIGH: 20,
    Severity.MEDIUM: 10,
    Severity.LOW: 5,
    Severity.INFO: 0,
}

DEFAULT_PASS_THRESHOLD = 80
DEFAULT_REVIEW_THRESHOLD = 50


def _is_github_target(target: str) -> bool:
    return target.startswith("github:") or (
        target.startswith("https://github.com/") or
        (not target.startswith("/") and not target.startswith(".") and "/" in target and not Path(target).exists())
    )


def _clone_github_repo(target: str) -> str:
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
        capture_output=True, text=True, timeout=120,
    )
    if result.returncode != 0:
        raise RuntimeError(f"Failed to clone {url}: {result.stderr.strip()}")
    return tmp_dir


def _calculate_score(findings: List[Finding]) -> int:
    score = 100
    for finding in findings:
        score -= SEVERITY_DEDUCTIONS.get(finding.severity, 0)
    return max(0, score)


def _determine_decision(
    score: int,
    findings: List[Finding],
    pass_threshold: int = DEFAULT_PASS_THRESHOLD,
    review_threshold: int = DEFAULT_REVIEW_THRESHOLD,
) -> Decision:
    all_surfaces: Set[ExecutionSurface] = set()
    all_caps: Set[Capability] = set()
    all_assets: Set[AssetReach] = set()
    for f in findings:
        all_surfaces.update(f.execution_surface)
        all_caps.update(f.capabilities)
        all_assets.update(f.asset_reach)

    if (ExecutionSurface.INSTALL in all_surfaces and
            Capability.SHELL in all_caps and
            AssetReach.CREDENTIAL in all_assets):
        return Decision.BLOCK

    if (ExecutionSurface.HOOK in all_surfaces and
            Capability.NETWORK in all_caps and
            AssetReach.SECRET in all_assets):
        return Decision.BLOCK

    if score >= pass_threshold:
        return Decision.PASS
    elif score >= review_threshold:
        return Decision.REVIEW
    else:
        return Decision.BLOCK


def _collect_execution_surfaces(findings: List[Finding]) -> List[str]:
    surfaces: Set[str] = set()
    for f in findings:
        for s in f.execution_surface:
            surfaces.add(s.value)
    return sorted(surfaces)


def _collect_capabilities(findings: List[Finding]) -> List[str]:
    caps: Set[str] = set()
    for f in findings:
        for c in f.capabilities:
            caps.add(c.value)
    return sorted(caps)


def _collect_asset_exposure(findings: List[Finding]) -> List[str]:
    assets: Set[str] = set()
    for f in findings:
        for a in f.asset_reach:
            assets.add(a.value)
    return sorted(assets)


def _build_sbom(target_dir: str) -> Dict[str, Any]:
    packages = []
    target_path = Path(target_dir)
    req_file = target_path / "requirements.txt"
    if req_file.exists():
        packages.extend(extract_sbom_from_requirements(str(req_file)))
    pkg_json = target_path / "package.json"
    if pkg_json.exists():
        packages.extend(extract_sbom_from_package_json(str(pkg_json)))
    return {"packages": packages}


def _apply_correlations(findings: List[Finding]) -> List[Finding]:
    """
    Detect dangerous combinations of findings and generate correlation findings.
    These represent multi-signal risks more severe than individual findings.
    """
    correlation_findings = []

    has_file_read = any(
        f.rule_id in {
            "cred_ssh_key_read", "cred_aws_credentials", "cred_env_file",
            "cred_kubeconfig", "cred_gcloud_creds", "cred_git_credentials",
            "cred_docker_config", "cred_gcp_service_account",
        } or ("open" in f.matched_text.lower() and any(
            p in f.matched_text for p in ["/.ssh", "/.aws", ".env", "kubeconfig", "credential"]
        ))
        for f in findings
    )
    has_network_send = any(
        f.category == "network" and Capability.NETWORK in f.capabilities
        for f in findings
    )
    has_env_read = any(
        "environ" in f.matched_text.lower() or "os.environ" in f.matched_text.lower()
        for f in findings
    )
    has_eval_exec = any(
        f.rule_id in {
            "exec_eval_shell", "exec_python_exec", "exec_os_system",
            "exec_subprocess_shell", "exec_dynamic_import",
            "exec_importlib_dynamic", "exec_getattr_dynamic",
        }
        for f in findings
    )
    has_obfuscation = any(f.category == "obfuscation" for f in findings)
    has_persistence = any(f.category == "persistence" for f in findings)

    if has_file_read and has_network_send:
        correlation_findings.append(Finding(
            rule_id="corr_read_then_send",
            title="Credential read + network send (exfiltration risk)",
            description="Sensitive file read AND external network communication detected. This combination is the hallmark of credential exfiltration malware.",
            severity=Severity.CRITICAL,
            file_path="[correlation]",
            line_number=None,
            matched_text="credential_read + network_post",
            category="correlation",
            execution_surface=[ExecutionSurface.RUNTIME],
            capabilities=[Capability.NETWORK, Capability.FILESYSTEM],
            asset_reach=[AssetReach.CREDENTIAL, AssetReach.SECRET],
        ))

    if has_env_read and has_network_send:
        correlation_findings.append(Finding(
            rule_id="corr_env_exfil",
            title="Environment variables + network send (env exfiltration)",
            description="os.environ access AND external network communication detected. Environment variables often contain API keys and secrets.",
            severity=Severity.CRITICAL,
            file_path="[correlation]",
            line_number=None,
            matched_text="os.environ + network_send",
            category="correlation",
            execution_surface=[ExecutionSurface.RUNTIME],
            capabilities=[Capability.NETWORK],
            asset_reach=[AssetReach.SECRET, AssetReach.CREDENTIAL],
        ))

    if has_eval_exec and has_network_send:
        correlation_findings.append(Finding(
            rule_id="corr_eval_network",
            title="Dynamic code execution + network (RCE chain risk)",
            description="eval/exec/dynamic-import AND network access detected together. This pattern is used to fetch and execute remote payloads.",
            severity=Severity.CRITICAL,
            file_path="[correlation]",
            line_number=None,
            matched_text="eval/exec + network",
            category="correlation",
            execution_surface=[ExecutionSurface.RUNTIME, ExecutionSurface.INSTALL],
            capabilities=[Capability.SHELL, Capability.NETWORK, Capability.PROCESS],
            asset_reach=[],
        ))

    if has_obfuscation and has_network_send:
        correlation_findings.append(Finding(
            rule_id="corr_obfuscation_network",
            title="Obfuscation + network (hidden exfiltration)",
            description="Code obfuscation AND network communication detected. Strongly suggests data hiding and exfiltration.",
            severity=Severity.CRITICAL,
            file_path="[correlation]",
            line_number=None,
            matched_text="obfuscation + network_send",
            category="correlation",
            execution_surface=[ExecutionSurface.RUNTIME],
            capabilities=[Capability.NETWORK],
            asset_reach=[AssetReach.SECRET],
        ))

    if has_persistence and has_network_send:
        correlation_findings.append(Finding(
            rule_id="corr_persistence_network",
            title="Persistence + network (C2 beacon risk)",
            description="Persistence mechanism AND network communication detected. Typical of backdoors that call home after installation.",
            severity=Severity.CRITICAL,
            file_path="[correlation]",
            line_number=None,
            matched_text="persistence + network",
            category="correlation",
            execution_surface=[ExecutionSurface.INSTALL, ExecutionSurface.RUNTIME],
            capabilities=[Capability.NETWORK, Capability.PROCESS],
            asset_reach=[],
        ))

    return correlation_findings


def scan(
    target: str,
    rules_dir: Optional[str] = None,
    pass_threshold: int = DEFAULT_PASS_THRESHOLD,
    review_threshold: int = DEFAULT_REVIEW_THRESHOLD,
) -> ScanResult:
    start_time = time.monotonic()
    tmp_dir: Optional[str] = None

    if _is_github_target(target):
        tmp_dir = _clone_github_repo(target)
        scan_path = tmp_dir
        display_target = target
    else:
        scan_path = os.path.abspath(target)
        display_target = target

    try:
        if rules_dir is None:
            rules_dir = get_default_rules_dir()
        rules = load_rules(rules_dir)

        if Path(scan_path).is_dir():
            allowlist = load_allowlist(scan_path)
        else:
            allowlist = load_allowlist(str(Path(scan_path).parent))

        all_findings: List[Finding] = []
        scanned_files: List[str] = []

        if Path(scan_path).is_file():
            file_path = scan_path
            base_dir = str(Path(scan_path).parent)
            if not allowlist.is_file_ignored(file_path):
                ignored_rules = allowlist.ignored_rules[:]
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
                    all_findings.extend(analyze_file(file_path, rules, ignored_rules, base_dir))
                scanned_files.append(file_path)
            sbom = {}
        else:
            files = collect_files(scan_path)
            base_dir = scan_path

            for file_path in files:
                try:
                    rel_path = str(Path(file_path).relative_to(base_dir))
                except ValueError:
                    rel_path = file_path

                if allowlist.is_file_ignored(rel_path) or allowlist.is_file_ignored(file_path):
                    continue

                ignored_rules = allowlist.ignored_rules[:]
                fname = Path(file_path).name

                if fname == "requirements.txt":
                    findings = analyze_requirements_txt(file_path)
                elif fname == "package.json":
                    findings = analyze_package_json(file_path)
                elif fname == "pyproject.toml":
                    findings = analyze_pyproject_toml(file_path)
                elif is_mcp_config_file(file_path):
                    findings = analyze_mcp_config(file_path)
                else:
                    findings = analyze_file(file_path, rules, ignored_rules, base_dir)

                for f in findings:
                    try:
                        f.file_path = str(Path(f.file_path).relative_to(base_dir))
                    except ValueError:
                        pass
                all_findings.extend(findings)
                scanned_files.append(rel_path)

            skill_md_path = Path(scan_path) / "SKILL.md"
            if skill_md_path.exists():
                skill_findings = analyze_skill_md(str(skill_md_path), scan_path)
                all_findings.extend(skill_findings)

            lockfile_findings = check_missing_lockfiles(scan_path)
            for f in lockfile_findings:
                try:
                    f.file_path = str(Path(f.file_path).relative_to(base_dir))
                except ValueError:
                    pass
            all_findings.extend(lockfile_findings)
            sbom = _build_sbom(scan_path)

        all_findings = [f for f in all_findings if not allowlist.is_rule_ignored(f.rule_id)]

        seen: Set[tuple] = set()
        deduped: List[Finding] = []
        for f in all_findings:
            key = (f.rule_id, f.file_path, f.line_number)
            if key not in seen:
                seen.add(key)
                deduped.append(f)
        all_findings = deduped

        correlation_findings = _apply_correlations(all_findings)
        all_findings.extend(correlation_findings)

        severity_order = {
            Severity.CRITICAL: 0, Severity.HIGH: 1,
            Severity.MEDIUM: 2, Severity.LOW: 3, Severity.INFO: 4,
        }
        all_findings.sort(key=lambda f: severity_order.get(f.severity, 99))

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
        if tmp_dir:
            import shutil
            shutil.rmtree(tmp_dir, ignore_errors=True)
