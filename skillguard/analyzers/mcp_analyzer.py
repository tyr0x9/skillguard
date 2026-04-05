"""MCP (Model Context Protocol) configuration analyzer."""

import json
import re
from pathlib import Path
from typing import List, Optional, Any, Dict

from skillguard.models import Finding, Severity, ExecutionSurface, Capability, AssetReach


def _make_finding(
    rule_id: str,
    title: str,
    description: str,
    severity: Severity,
    file_path: str,
    line_number: Optional[int],
    matched_text: str,
    category: str = "mcp_agent",
    execution_surface: Optional[List[ExecutionSurface]] = None,
    capabilities: Optional[List[Capability]] = None,
    asset_reach: Optional[List[AssetReach]] = None,
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
        execution_surface=execution_surface or [],
        capabilities=capabilities or [],
        asset_reach=asset_reach or [],
    )


def _is_external_url(value: str) -> bool:
    """Check if a string looks like an external URL."""
    if isinstance(value, str):
        return value.startswith(("http://", "https://", "ws://", "wss://"))
    return False


def _check_auto_approve(data: Dict[str, Any], file_path: str) -> List[Finding]:
    """Check for auto-approve configurations."""
    findings = []

    # Check for autoApprove: ["*"] or autoApprove: "all"
    auto_approve = data.get("autoApprove") or data.get("auto_approve")
    if auto_approve is not None:
        if auto_approve == "*" or auto_approve == "all" or auto_approve == ["*"]:
            findings.append(_make_finding(
                "mcp_auto_approve_all",
                "Auto-approve all tools",
                "autoApprove: '*' or 'all' grants all MCP tools automatic execution without user confirmation",
                Severity.CRITICAL,
                file_path,
                None,
                f"autoApprove: {auto_approve}",
                capabilities=[Capability.SHELL, Capability.PROCESS],
            ))
        elif isinstance(auto_approve, list) and len(auto_approve) > 5:
            findings.append(_make_finding(
                "mcp_auto_approve_all",
                "Auto-approve many tools",
                f"autoApprove grants {len(auto_approve)} tools automatic execution",
                Severity.HIGH,
                file_path,
                None,
                f"autoApprove: {auto_approve}",
                capabilities=[Capability.PROCESS],
            ))

    return findings


def _check_mcp_servers(data: Dict[str, Any], file_path: str) -> List[Finding]:
    """Check MCP server configurations."""
    findings = []

    # Handle various MCP config formats
    servers = {}
    if "mcpServers" in data:
        servers = data["mcpServers"]
    elif "mcp" in data and "servers" in data["mcp"]:
        servers = data["mcp"]["servers"]
    elif "servers" in data:
        servers = data["servers"]

    if not isinstance(servers, dict):
        return findings

    for server_name, server_config in servers.items():
        if not isinstance(server_config, dict):
            continue

        # Check for external MCP server URLs
        url = server_config.get("url") or server_config.get("baseUrl")
        if url and _is_external_url(url):
            # Check if it's clearly untrusted
            trusted_domains = ["localhost", "127.0.0.1", "0.0.0.0", "::1"]
            is_local = any(d in url for d in trusted_domains)
            if not is_local:
                findings.append(_make_finding(
                    "mcp_external_mcp_server",
                    f"External MCP server: {server_name}",
                    f"MCP server '{server_name}' points to an external URL. Verify this server is trusted.",
                    Severity.HIGH,
                    file_path,
                    None,
                    f"{server_name}: {url}",
                    capabilities=[Capability.NETWORK],
                ))

        # Check for auto-approve on specific server
        server_auto_approve = server_config.get("autoApprove")
        if server_auto_approve == "*" or server_auto_approve == ["*"]:
            findings.append(_make_finding(
                "mcp_auto_approve_all",
                f"Auto-approve all tools for server: {server_name}",
                "autoApprove: '*' grants all tools automatic execution without user confirmation",
                Severity.CRITICAL,
                file_path,
                None,
                f"{server_name}.autoApprove: {server_auto_approve}",
                capabilities=[Capability.SHELL, Capability.PROCESS],
            ))

        # Check for allowed tools / tool filtering
        allowed_tools = server_config.get("allowedTools") or server_config.get("tools")
        if allowed_tools is None:
            findings.append(_make_finding(
                "mcp_no_tool_filtering",
                f"No tool filtering for MCP server: {server_name}",
                "No allowedTools list means all tools from this server are accessible",
                Severity.MEDIUM,
                file_path,
                None,
                f"{server_name}: no allowedTools defined",
            ))

        # Check trust level
        trust = server_config.get("trust") or server_config.get("trustLevel")
        if trust in ("all", "unsafe", "full"):
            findings.append(_make_finding(
                "mcp_agent_trust_all",
                f"Trust level set to '{trust}' for server: {server_name}",
                "Setting trust level to 'all' or 'unsafe' bypasses security checks",
                Severity.CRITICAL,
                file_path,
                None,
                f"{server_name}.trust: {trust}",
            ))

        # Check for filesystem server with broad access
        env = server_config.get("env", {})
        args = server_config.get("args", [])
        command = server_config.get("command", "")

        # Check if it's a filesystem MCP
        is_filesystem = (
            "filesystem" in server_name.lower() or
            "filesystem" in command.lower() or
            any("filesystem" in str(a).lower() for a in args)
        )
        if is_filesystem:
            # Check if root is in the args
            if "/" in args or any(a in ("/", "/*", "/home", "/etc") for a in args):
                findings.append(_make_finding(
                    "mcp_broad_filesystem",
                    f"Filesystem MCP with root access: {server_name}",
                    "Filesystem MCP configured with root or home directory access",
                    Severity.HIGH,
                    file_path,
                    None,
                    f"{server_name}: args={args}",
                    capabilities=[Capability.FILESYSTEM],
                    asset_reach=[AssetReach.CONFIG, AssetReach.CREDENTIAL],
                ))

        # Check for shell/exec MCP
        is_shell = (
            "shell" in server_name.lower() or
            "exec" in server_name.lower() or
            "terminal" in server_name.lower() or
            "bash" in command.lower() or
            "sh" in command.lower()
        )
        if is_shell:
            restrictions = server_config.get("restrictions") or server_config.get("allowedCommands")
            if restrictions is None:
                findings.append(_make_finding(
                    "mcp_unrestricted_shell",
                    f"Shell/exec MCP with no restrictions: {server_name}",
                    "Shell MCP server without command restrictions can execute arbitrary code",
                    Severity.CRITICAL,
                    file_path,
                    None,
                    f"{server_name}: command={command}",
                    capabilities=[Capability.SHELL, Capability.PROCESS],
                    execution_surface=[ExecutionSurface.RUNTIME],
                ))

        # Check for auto-execute skills
        auto_execute = server_config.get("autoExecute") or server_config.get("auto_execute")
        if auto_execute:
            findings.append(_make_finding(
                "mcp_skill_auto_execute",
                f"Skill auto-execution enabled: {server_name}",
                "autoExecute allows skills to run without user confirmation",
                Severity.HIGH,
                file_path,
                None,
                f"{server_name}.autoExecute: {auto_execute}",
                execution_surface=[ExecutionSurface.RUNTIME],
            ))

        # Check permissions
        permissions = server_config.get("permissions", {})
        if isinstance(permissions, dict):
            read_perms = permissions.get("read", [])
            write_perms = permissions.get("write", [])

            sensitive_dirs = ["/etc", "/root", "/home", "~/.ssh", "~/.aws", "~/.kube"]
            for perm_path in read_perms:
                if any(s in str(perm_path) for s in sensitive_dirs):
                    findings.append(_make_finding(
                        "mcp_broad_read_permissions",
                        f"Read permissions on sensitive directory: {perm_path}",
                        "MCP server has read access to potentially sensitive directories",
                        Severity.HIGH,
                        file_path,
                        None,
                        f"{server_name}.permissions.read: {perm_path}",
                        capabilities=[Capability.FILESYSTEM],
                        asset_reach=[AssetReach.CREDENTIAL, AssetReach.SECRET],
                    ))

            system_dirs = ["/etc", "/bin", "/usr", "/sbin", "/lib", "/boot"]
            for perm_path in write_perms:
                if any(str(perm_path).startswith(s) for s in system_dirs):
                    findings.append(_make_finding(
                        "mcp_write_system_dirs",
                        f"Write permissions on system directory: {perm_path}",
                        "MCP server has write access to system directories",
                        Severity.CRITICAL,
                        file_path,
                        None,
                        f"{server_name}.permissions.write: {perm_path}",
                        capabilities=[Capability.FILESYSTEM],
                    ))

        # Check for hooks with shell execution
        hooks = server_config.get("hooks", {})
        if isinstance(hooks, dict):
            for hook_name, hook_cmd in hooks.items():
                if isinstance(hook_cmd, str) and re.search(r"(sh|bash|exec|eval|python|node)", hook_cmd):
                    findings.append(_make_finding(
                        "mcp_hook_pre_post",
                        f"Hook with shell execution: {hook_name}",
                        f"Hook '{hook_name}' executes shell commands which can run arbitrary code",
                        Severity.HIGH,
                        file_path,
                        None,
                        f"{server_name}.hooks.{hook_name}: {hook_cmd}",
                        execution_surface=[ExecutionSurface.HOOK],
                        capabilities=[Capability.SHELL],
                    ))

    return findings


def analyze_mcp_config(file_path: str) -> List[Finding]:
    """Analyze an MCP configuration file for security issues."""
    findings = []

    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
    except OSError:
        return findings

    # Try to parse as JSON
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        # Try YAML
        try:
            import yaml
            data = yaml.safe_load(content)
        except Exception:
            return findings

    if not isinstance(data, dict):
        return findings

    # Run all checks
    findings.extend(_check_auto_approve(data, file_path))
    findings.extend(_check_mcp_servers(data, file_path))

    return findings


def is_mcp_config_file(file_path: str) -> bool:
    """Determine if a file is likely an MCP config file."""
    name = Path(file_path).name.lower()
    mcp_indicators = [
        "mcp", "claude_desktop_config", "claude-desktop-config",
        ".mcp", "agent-config", "skill-config",
    ]
    return any(indicator in name for indicator in mcp_indicators)
