import json
import re
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple

from skillguard.models import Finding, Severity, Capability, AssetReach


def _make_finding(
    rule_id: str,
    title: str,
    description: str,
    severity: Severity,
    file_path: str,
    line_number: Optional[int],
    matched_text: str,
    category: str = "supply_chain",
) -> Finding:
    return Finding(
        rule_id=rule_id,
        title=title,
        description=description,
        severity=severity,
        file_path=file_path,
        line_number=line_number,
        matched_text=matched_text,
        category=category,
        execution_surface=[],
        capabilities=[],
        asset_reach=[],
    )


KNOWN_TYPOSQUATS = {
    "reqeusts", "requets", "reqests", "numpy1", "numpys", "panddas",
    "pandes", "djnago", "flaskr", "bottlee", "torchh", "tensorfow",
    "scikit-learn1", "matplotlip", "beutifulsoup4", "beautifulsoup",
    "colorma", "pilows", "pilow", "cryptografhy", "pycrypto2",
    "urllib4", "urlib3", "setuptool", "setuptools2", "pipenv2",
}


def analyze_requirements_txt(file_path: str) -> List[Finding]:
    """Analyze requirements.txt for security issues."""
    findings = []
    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
    except OSError:
        return findings

    lines = content.splitlines()
    has_hashes = any("--hash=" in line for line in lines)

    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith("-"):
            continue

        # Check for git+ dependencies
        if stripped.startswith("git+"):
            findings.append(_make_finding(
                "sc_git_dependency",
                "Git dependency (unversioned)",
                "Git dependencies without a tag are mutable and can introduce supply chain risks",
                Severity.HIGH,
                file_path,
                i,
                stripped,
            ))
            # Check if it's pinned to a branch not a tag
            if "@" in stripped and not re.search(r"@[vV]?\d+\.\d+", stripped):
                findings.append(_make_finding(
                    "sc_vcs_dependency",
                    "VCS dependency pinned to branch not tag",
                    "Pinning to a branch instead of a specific tag can lead to unexpected code execution",
                    Severity.HIGH,
                    file_path,
                    i,
                    stripped,
                ))
            continue

        # Parse package name
        pkg_match = re.match(r"^([A-Za-z0-9_\-\.]+)", stripped)
        if not pkg_match:
            continue
        pkg_name = pkg_match.group(1).lower()

        # Check for typosquatting
        if pkg_name in KNOWN_TYPOSQUATS:
            findings.append(_make_finding(
                "sc_typosquatting_common",
                f"Potential typosquatting: {pkg_name}",
                "This package name resembles a known typosquatting attempt",
                Severity.CRITICAL,
                file_path,
                i,
                stripped,
            ))

        # Check for unpinned dependencies
        if "==" not in stripped and ">=" not in stripped and "~=" not in stripped and "<=" not in stripped:
            if "!=" not in stripped and not stripped.startswith("-"):
                findings.append(_make_finding(
                    "sc_pip_unpinned",
                    f"Unpinned dependency: {pkg_name}",
                    "Unpinned dependencies can introduce supply chain risks through automatic updates",
                    Severity.MEDIUM,
                    file_path,
                    i,
                    stripped,
                ))
        elif "*" in stripped:
            findings.append(_make_finding(
                "sc_wildcard_version",
                f"Wildcard version: {pkg_name}",
                "Wildcard versions allow any version to be installed, introducing supply chain risk",
                Severity.MEDIUM,
                file_path,
                i,
                stripped,
            ))

        # Check for recently-published / 0.0.x versions
        ver_match = re.search(r"==\s*(0\.[01]\.\d+)", stripped)
        if ver_match:
            findings.append(_make_finding(
                "sc_recently_published",
                f"Very low version package: {pkg_name}",
                "Packages at version 0.0.x or 0.1.x may be new or test packages with higher supply chain risk",
                Severity.LOW,
                file_path,
                i,
                stripped,
            ))

    # Check for missing hash verification
    if lines and not has_hashes:
        findings.append(_make_finding(
            "sc_requirements_no_hash",
            "requirements.txt without hash verification",
            "Using --hash= in requirements.txt ensures integrity of downloaded packages",
            Severity.LOW,
            file_path,
            None,
            "No --hash= directives found",
        ))

    return findings


def analyze_package_json(file_path: str) -> List[Finding]:
    """Analyze package.json for security issues."""
    findings = []
    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        return findings

    # Check for custom npm registry
    if "publishConfig" in data:
        registry = data["publishConfig"].get("registry", "")
        if registry and "npmjs.com" not in registry and "registry.npmjs.org" not in registry:
            findings.append(_make_finding(
                "sc_npm_registry_custom",
                "Custom npm registry",
                f"Package uses custom registry: {registry}. This could be a dependency confusion vector.",
                Severity.HIGH,
                file_path,
                None,
                f"registry: {registry}",
            ))

    # Check scripts for suspicious patterns
    scripts = data.get("scripts", {})
    suspicious_patterns = [
        (r"curl\s+\S+\s*\|\s*(sh|bash)", "curl piped to shell in npm script"),
        (r"wget\s+\S+\s*\|\s*(sh|bash)", "wget piped to shell in npm script"),
        (r"(bash|sh)\s+-c\s+['\"]", "shell execution in npm script"),
    ]

    for script_name, script_content in scripts.items():
        for pattern, desc in suspicious_patterns:
            if re.search(pattern, script_content, re.IGNORECASE):
                if script_name == "postinstall":
                    findings.append(_make_finding(
                        "sc_postinstall_script",
                        f"Suspicious postinstall script: {desc}",
                        "The postinstall script runs automatically on npm install and can execute arbitrary code",
                        Severity.CRITICAL,
                        file_path,
                        None,
                        f"{script_name}: {script_content}",
                    ))
                else:
                    findings.append(_make_finding(
                        "sc_install_script",
                        f"Suspicious npm script ({script_name}): {desc}",
                        "npm scripts can execute arbitrary code during package lifecycle events",
                        Severity.HIGH,
                        file_path,
                        None,
                        f"{script_name}: {script_content}",
                    ))

    # Check for unpinned/wildcard dependencies
    all_deps = {}
    all_deps.update(data.get("dependencies", {}))
    all_deps.update(data.get("devDependencies", {}))

    for pkg_name, version in all_deps.items():
        if version == "*":
            findings.append(_make_finding(
                "sc_wildcard_version",
                f"Wildcard version: {pkg_name}",
                "Wildcard versions allow any version, introducing supply chain risk",
                Severity.MEDIUM,
                file_path,
                None,
                f"{pkg_name}: {version}",
            ))
        elif version.startswith("git+") or version.startswith("github:"):
            findings.append(_make_finding(
                "sc_git_dependency",
                f"Git dependency: {pkg_name}",
                "Git dependencies are mutable and can introduce supply chain risks",
                Severity.HIGH,
                file_path,
                None,
                f"{pkg_name}: {version}",
            ))
        elif not version.startswith(("^", "~", ">", "<", "=")) and not re.match(r"^\d", version):
            pass  # skip non-semver
        elif version.startswith("^") or version.startswith("~"):
            findings.append(_make_finding(
                "sc_npm_unpinned",
                f"Non-exact version: {pkg_name}",
                "Using ^ or ~ allows automatic minor/patch updates which may introduce supply chain risks",
                Severity.LOW,
                file_path,
                None,
                f"{pkg_name}: {version}",
            ))

        # Check for recently published (0.0.x or 0.1.x)
        ver_match = re.search(r"[=^~]?(0\.[01]\.\d+)", version)
        if ver_match:
            findings.append(_make_finding(
                "sc_recently_published",
                f"Very low version package: {pkg_name}",
                "Packages at version 0.0.x or 0.1.x may be new or test packages",
                Severity.LOW,
                file_path,
                None,
                f"{pkg_name}: {version}",
            ))

    # Check for missing lockfile (we check in the scanner for this)

    return findings


def analyze_pyproject_toml(file_path: str) -> List[Finding]:
    """Analyze pyproject.toml for security issues."""
    findings = []
    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
    except OSError:
        return findings

    # Simple text-based analysis for pyproject.toml
    lines = content.splitlines()

    for i, line in enumerate(lines, 1):
        stripped = line.strip()

        # Check for custom index
        if "index-url" in stripped.lower() or "extra-index-url" in stripped.lower():
            if "pypi.org" not in stripped:
                findings.append(_make_finding(
                    "sc_pip_index_url_custom",
                    "Custom PyPI index URL",
                    "Custom package indexes can be used for dependency confusion attacks",
                    Severity.HIGH,
                    file_path,
                    i,
                    stripped,
                ))

        # Check for git+ dependencies
        if "git+" in stripped:
            findings.append(_make_finding(
                "sc_git_dependency",
                "Git dependency in pyproject.toml",
                "Git dependencies without a specific tag are mutable",
                Severity.HIGH,
                file_path,
                i,
                stripped,
            ))

        # Check for wildcard versions
        if re.search(r'["\'][\*]\s*["\']', stripped) or re.search(r'==\s*\*', stripped):
            findings.append(_make_finding(
                "sc_wildcard_version",
                "Wildcard version in pyproject.toml",
                "Wildcard versions allow any version to be installed",
                Severity.MEDIUM,
                file_path,
                i,
                stripped,
            ))

    return findings


def check_missing_lockfiles(target_dir: str) -> List[Finding]:
    """Check for missing lockfiles in a project directory."""
    findings = []
    target_path = Path(target_dir)

    has_requirements = (target_path / "requirements.txt").exists()
    has_pip_lock = (
        (target_path / "requirements.lock").exists() or
        (target_path / "Pipfile.lock").exists() or
        (target_path / "poetry.lock").exists() or
        (target_path / "uv.lock").exists()
    )

    has_package_json = (target_path / "package.json").exists()
    has_npm_lock = (
        (target_path / "package-lock.json").exists() or
        (target_path / "yarn.lock").exists() or
        (target_path / "pnpm-lock.yaml").exists()
    )

    if has_requirements and not has_pip_lock:
        findings.append(_make_finding(
            "sc_no_lockfile",
            "Missing Python lockfile",
            "requirements.txt without a lockfile (Pipfile.lock, poetry.lock, uv.lock) can lead to supply chain risks",
            Severity.LOW,
            str(target_path / "requirements.txt"),
            None,
            "No lockfile found",
        ))

    if has_package_json and not has_npm_lock:
        findings.append(_make_finding(
            "sc_no_package_lock",
            "Missing npm/yarn lockfile",
            "package.json without package-lock.json or yarn.lock can lead to supply chain risks",
            Severity.MEDIUM,
            str(target_path / "package.json"),
            None,
            "No package-lock.json or yarn.lock found",
        ))

    return findings


def extract_sbom_from_requirements(file_path: str) -> List[Dict[str, str]]:
    """Extract SBOM entries from requirements.txt."""
    packages = []
    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
    except OSError:
        return packages

    for line in content.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith("-"):
            continue
        match = re.match(r"^([A-Za-z0-9_\-\.]+)\s*(?:==\s*([^\s;]+))?", stripped)
        if match:
            name = match.group(1)
            version = match.group(2) or "unknown"
            packages.append({"name": name, "version": version, "ecosystem": "pypi"})

    return packages


def extract_sbom_from_package_json(file_path: str) -> List[Dict[str, str]]:
    """Extract SBOM entries from package.json."""
    packages = []
    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        return packages

    for dep_type in ["dependencies", "devDependencies"]:
        for name, version in data.get(dep_type, {}).items():
            packages.append({"name": name, "version": version, "ecosystem": "npm"})

    return packages
