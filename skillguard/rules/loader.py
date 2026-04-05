import os
import glob
from pathlib import Path
from typing import List, Dict, Any
import yaml


class Rule:
    def __init__(self, data: Dict[str, Any]):
        self.id: str = data["id"]
        self.title: str = data["title"]
        self.description: str = data.get("description", "")
        self.category: str = data.get("category", "general")
        self.severity: str = data.get("severity", "MEDIUM")
        self.file_patterns: List[str] = data.get("file_patterns", ["*"])
        raw_patterns = data.get("patterns", [])
        if isinstance(raw_patterns, str):
            raw_patterns = [raw_patterns]
        self.patterns: List[str] = raw_patterns
        self.execution_surface: List[str] = data.get("execution_surface", [])
        self.capabilities: List[str] = data.get("capabilities", [])
        self.asset_reach: List[str] = data.get("asset_reach", [])

    def __repr__(self) -> str:
        return f"Rule(id={self.id}, severity={self.severity})"


def load_rules(rules_dir: str) -> List[Rule]:
    """Load all rules from YAML files in the given directory."""
    rules = []
    rules_path = Path(rules_dir)

    if not rules_path.exists():
        return rules

    yaml_files = sorted(rules_path.glob("*.yaml")) + sorted(rules_path.glob("*.yml"))

    for yaml_file in yaml_files:
        try:
            with open(yaml_file, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
            if data and "rules" in data:
                for rule_data in data["rules"]:
                    try:
                        rule = Rule(rule_data)
                        rules.append(rule)
                    except (KeyError, TypeError) as e:
                        pass
        except (yaml.YAMLError, OSError):
            pass

    return rules


def get_default_rules_dir() -> str:
    """Get the default rules directory (relative to package or project root)."""
    # Try package-relative path first
    pkg_dir = Path(__file__).parent.parent.parent
    candidate = pkg_dir / "rules"
    if candidate.exists():
        return str(candidate)

    # Try current working directory
    cwd_candidate = Path.cwd() / "rules"
    if cwd_candidate.exists():
        return str(cwd_candidate)

    return str(candidate)
