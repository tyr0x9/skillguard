import os
from pathlib import Path
from typing import List, Optional

from skillguard.models import Finding
from skillguard.rules.engine import match_rules
from skillguard.rules.loader import Rule

# File extensions and names to analyze
SCAN_EXTENSIONS = {
    ".sh", ".bash", ".py", ".js", ".ts", ".yaml", ".yml", ".json",
    ".md", ".pth", ".rb", ".pl", ".ps1", ".bat", ".cmd",
}

SCAN_FILENAMES = {
    "SKILL.md", "README.md", "requirements.txt", "package.json",
    "pyproject.toml", "setup.py", "setup.cfg", "Makefile",
    "Dockerfile", "docker-compose.yml", "docker-compose.yaml",
    ".npmrc", ".pypirc", "sitecustomize.py",
}

SCAN_DIRECTORIES = {
    "scripts", "hooks", ".git/hooks", "bin",
}


def should_scan_file(file_path: str) -> bool:
    """Determine if a file should be scanned."""
    path = Path(file_path)
    name = path.name
    suffix = path.suffix.lower()

    if name in SCAN_FILENAMES:
        return True
    if suffix in SCAN_EXTENSIONS:
        return True

    # Check if in a scripts/hooks directory
    parts = path.parts
    for part in parts:
        if part in SCAN_DIRECTORIES:
            return True

    return False


def analyze_file(
    file_path: str,
    rules: List[Rule],
    ignored_rules: Optional[List[str]] = None,
    base_dir: Optional[str] = None,
) -> List[Finding]:
    """Analyze a single file against the provided rules."""
    if ignored_rules is None:
        ignored_rules = []

    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
    except (OSError, PermissionError):
        return []

    # Use relative path for display if base_dir provided
    if base_dir:
        try:
            display_path = str(Path(file_path).relative_to(base_dir))
        except ValueError:
            display_path = file_path
    else:
        display_path = file_path

    findings = match_rules(display_path, content, rules, ignored_rules)
    return findings


def collect_files(target_dir: str) -> List[str]:
    """Collect all files that should be scanned from a directory."""
    files = []
    target_path = Path(target_dir)

    if not target_path.exists():
        return files

    if target_path.is_file():
        return [str(target_path)]

    for root, dirs, filenames in os.walk(target_path):
        # Skip hidden dirs except .git/hooks
        dirs[:] = [
            d for d in dirs
            if not (d.startswith(".") and d not in {".git"})
            or d == ".git"
        ]

        # For .git directory, only look at hooks
        rel_root = Path(root).relative_to(target_path)
        parts = rel_root.parts
        if parts and parts[0] == ".git":
            if len(parts) == 1:
                dirs[:] = ["hooks"] if "hooks" in dirs else []
            elif parts[1] != "hooks":
                dirs[:] = []

        for filename in filenames:
            full_path = os.path.join(root, filename)
            if should_scan_file(full_path):
                files.append(full_path)

    return sorted(files)
