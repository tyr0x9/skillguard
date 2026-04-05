"""Allowlist management for SkillGuard.

Supports:
- .skillguard.yaml file in the target directory
- Inline `# skillguard:ignore rule_id` comments (handled by rules engine)
"""

import re
from pathlib import Path
from typing import List, Optional, Dict, Any

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False


DEFAULT_ALLOWLIST_FILENAME = ".skillguard.yaml"


class Allowlist:
    """Manages ignored rules and exceptions."""

    def __init__(
        self,
        ignored_rules: Optional[List[str]] = None,
        ignored_files: Optional[List[str]] = None,
        ignored_paths: Optional[List[str]] = None,
    ):
        self.ignored_rules: List[str] = ignored_rules or []
        self.ignored_files: List[str] = ignored_files or []
        self.ignored_paths: List[str] = ignored_paths or []

    def is_rule_ignored(self, rule_id: str) -> bool:
        """Check if a rule is globally ignored."""
        return rule_id in self.ignored_rules

    def is_file_ignored(self, file_path: str) -> bool:
        """Check if a file should be skipped."""
        path = Path(file_path)
        name = path.name

        if name in self.ignored_files:
            return True

        for ignored_path in self.ignored_paths:
            try:
                # Check if file_path starts with ignored_path
                if file_path.startswith(ignored_path):
                    return True
                # Check path component match
                if Path(ignored_path) in path.parents:
                    return True
            except (ValueError, TypeError):
                pass

        return False

    def __repr__(self) -> str:
        return (
            f"Allowlist(ignored_rules={self.ignored_rules}, "
            f"ignored_files={self.ignored_files})"
        )


def load_allowlist(target_dir: str) -> Allowlist:
    """Load .skillguard.yaml from the target directory."""
    allowlist_path = Path(target_dir) / DEFAULT_ALLOWLIST_FILENAME

    if not allowlist_path.exists():
        # Also try parent directories (up to 3 levels)
        parent = Path(target_dir).parent
        for _ in range(3):
            candidate = parent / DEFAULT_ALLOWLIST_FILENAME
            if candidate.exists():
                allowlist_path = candidate
                break
            parent = parent.parent

    if not allowlist_path.exists():
        return Allowlist()

    if not HAS_YAML:
        return Allowlist()

    try:
        with open(allowlist_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
    except (OSError, yaml.YAMLError):
        return Allowlist()

    if not isinstance(data, dict):
        return Allowlist()

    # Parse allowlist configuration
    ignored_rules: List[str] = []
    ignored_files: List[str] = []
    ignored_paths: List[str] = []

    # Support multiple key names for flexibility
    for key in ("ignore_rules", "ignoreRules", "ignored_rules", "ignore"):
        val = data.get(key)
        if isinstance(val, list):
            ignored_rules.extend(str(r) for r in val)

    for key in ("ignore_files", "ignoreFiles", "ignored_files"):
        val = data.get(key)
        if isinstance(val, list):
            ignored_files.extend(str(f) for f in val)

    for key in ("ignore_paths", "ignorePaths", "ignored_paths"):
        val = data.get(key)
        if isinstance(val, list):
            ignored_paths.extend(str(p) for p in val)

    return Allowlist(
        ignored_rules=list(set(ignored_rules)),
        ignored_files=list(set(ignored_files)),
        ignored_paths=list(set(ignored_paths)),
    )


def parse_inline_ignore(line: str) -> List[str]:
    """
    Extract rule IDs from an inline skillguard:ignore comment.

    Example: `curl ... | bash  # skillguard:ignore exec_curl_pipe_sh`
    Returns: ['exec_curl_pipe_sh']
    """
    pattern = r"#\s*skillguard:ignore\s+([\w,\s]+)"
    match = re.search(pattern, line, re.IGNORECASE)
    if not match:
        return []
    ids_str = match.group(1)
    return [rid.strip() for rid in ids_str.split(",") if rid.strip()]
