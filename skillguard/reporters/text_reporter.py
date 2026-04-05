"""Text (CLI) reporter for SkillGuard scan results."""

import sys
from typing import Optional, TextIO

from skillguard.models import ScanResult, Decision, Severity

try:
    from rich.console import Console
    from rich.text import Text
    from rich.panel import Panel
    from rich.table import Table
    from rich import box
    HAS_RICH = True
except ImportError:
    HAS_RICH = False


# ANSI color codes for fallback
ANSI_RESET = "\033[0m"
ANSI_BOLD = "\033[1m"
ANSI_RED = "\033[91m"
ANSI_YELLOW = "\033[93m"
ANSI_GREEN = "\033[92m"
ANSI_CYAN = "\033[96m"
ANSI_WHITE = "\033[97m"
ANSI_DIM = "\033[2m"


SEVERITY_COLORS = {
    Severity.CRITICAL: "red",
    Severity.HIGH: "bright_red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "white",
}

SEVERITY_ANSI = {
    Severity.CRITICAL: ANSI_RED + ANSI_BOLD,
    Severity.HIGH: ANSI_RED,
    Severity.MEDIUM: ANSI_YELLOW,
    Severity.LOW: ANSI_CYAN,
    Severity.INFO: ANSI_WHITE,
}

DECISION_COLORS = {
    Decision.PASS: "green",
    Decision.REVIEW: "yellow",
    Decision.BLOCK: "red",
}

DECISION_ANSI = {
    Decision.PASS: ANSI_GREEN + ANSI_BOLD,
    Decision.REVIEW: ANSI_YELLOW + ANSI_BOLD,
    Decision.BLOCK: ANSI_RED + ANSI_BOLD,
}


class TextReporter:
    """Formats scan results as human-readable text output."""

    def __init__(self, use_color: bool = True, file: Optional[TextIO] = None):
        self.use_color = use_color
        self.file = file or sys.stdout

        if HAS_RICH and use_color:
            self._console = Console(file=self.file, highlight=False)
        else:
            self._console = None

    def report(self, result: ScanResult) -> None:
        """Output a formatted scan report."""
        if self._console:
            self._report_rich(result)
        else:
            self._report_plain(result)

    def _report_rich(self, result: ScanResult) -> None:
        """Output report using Rich formatting."""
        console = self._console

        # Header
        console.print()
        console.rule("[bold cyan]SkillGuard Security Scan Report[/bold cyan]")
        console.print()

        # Summary panel
        decision_color = DECISION_COLORS.get(result.decision, "white")
        score_color = "green" if result.score >= 80 else ("yellow" if result.score >= 50 else "red")

        summary_lines = [
            f"[bold]Target:[/bold] {result.target}",
            f"[bold]Risk Score:[/bold] [{score_color}]{result.score}/100[/{score_color}]",
            f"[bold]Decision:[/bold] [{decision_color}]{result.decision.value}[/{decision_color}]",
        ]

        if result.execution_surfaces:
            summary_lines.append(f"[bold]Execution Surface:[/bold] {', '.join(result.execution_surfaces)}")
        if result.capabilities:
            summary_lines.append(f"[bold]Capabilities:[/bold] {', '.join(result.capabilities)}")
        if result.asset_exposure:
            summary_lines.append(f"[bold]Asset Exposure:[/bold] {', '.join(result.asset_exposure)}")

        summary_lines.append(f"[dim]Scanned {len(result.scanned_files)} file(s) in {result.duration_seconds:.2f}s[/dim]")

        console.print(Panel(
            "\n".join(summary_lines),
            title="Summary",
            border_style=decision_color,
        ))
        console.print()

        if not result.findings:
            console.print("[green]No security issues found.[/green]")
            console.print()
            return

        # Findings
        console.print(f"[bold]Findings ({len(result.findings)}):[/bold]")
        console.print()

        for finding in result.findings:
            sev_color = SEVERITY_COLORS.get(finding.severity, "white")
            sev_label = f"[{sev_color}][{finding.severity.value}][/{sev_color}]"

            loc = finding.file_path
            if finding.line_number:
                loc = f"{loc}:{finding.line_number}"

            console.print(f"  {sev_label} [bold]{finding.rule_id}[/bold]")
            console.print(f"    [dim]Title:[/dim] {finding.title}")
            console.print(f"    [dim]File:[/dim] {loc}")

            if finding.matched_text:
                matched = finding.matched_text[:120]
                console.print(f"    [dim]Match:[/dim] [italic]{matched}[/italic]")

            if finding.description:
                desc = finding.description[:200]
                console.print(f"    [dim]Info:[/dim] {desc}")

            tags = []
            if finding.execution_surface:
                tags.append("surface:" + ",".join(s.value for s in finding.execution_surface))
            if finding.capabilities:
                tags.append("caps:" + ",".join(c.value for c in finding.capabilities))
            if finding.asset_reach:
                tags.append("assets:" + ",".join(a.value for a in finding.asset_reach))
            if tags:
                console.print(f"    [dim]Tags:[/dim] [dim]{' '.join(tags)}[/dim]")

            console.print()

        # SBOM summary
        if result.sbom and result.sbom.get("packages"):
            pkgs = result.sbom["packages"]
            console.print(f"[dim]SBOM: {len(pkgs)} package(s) detected[/dim]")
            console.print()

        # Final verdict
        console.rule()
        if result.decision == Decision.PASS:
            console.print("[green bold]PASSED[/green bold] - No significant security issues detected.")
        elif result.decision == Decision.REVIEW:
            console.print("[yellow bold]REVIEW REQUIRED[/yellow bold] - Security issues require human review.")
        else:
            console.print("[red bold]BLOCKED[/red bold] - Critical security issues detected. Do not install.")
        console.print()

    def _report_plain(self, result: ScanResult) -> None:
        """Output report as plain text (no Rich/color)."""
        out = self.file
        sep = "━" * 50

        print(sep, file=out)
        print("  SkillGuard Security Scan Report", file=out)
        print(sep, file=out)
        print(file=out)

        print(f"Target:   {result.target}", file=out)
        print(f"Score:    {result.score}/100", file=out)
        print(f"Decision: {result.decision.value}", file=out)

        if result.execution_surfaces:
            print(f"Execution Surface: {', '.join(result.execution_surfaces)}", file=out)
        if result.capabilities:
            print(f"Capabilities: {', '.join(result.capabilities)}", file=out)
        if result.asset_exposure:
            print(f"Asset Exposure: {', '.join(result.asset_exposure)}", file=out)

        print(f"Scanned:  {len(result.scanned_files)} file(s) in {result.duration_seconds:.2f}s", file=out)
        print(file=out)

        if not result.findings:
            print("No security issues found.", file=out)
            print(file=out)
            return

        print(f"Findings ({len(result.findings)}):", file=out)
        print(file=out)

        for finding in result.findings:
            loc = finding.file_path
            if finding.line_number:
                loc = f"{loc}:{finding.line_number}"

            print(f"  [{finding.severity.value}] {finding.rule_id}", file=out)
            print(f"    Title: {finding.title}", file=out)
            print(f"    File:  {loc}", file=out)

            if finding.matched_text:
                print(f"    Match: {finding.matched_text[:120]}", file=out)
            if finding.description:
                print(f"    Info:  {finding.description[:200]}", file=out)

            tags = []
            if finding.execution_surface:
                tags.append("surface:" + ",".join(s.value for s in finding.execution_surface))
            if finding.capabilities:
                tags.append("caps:" + ",".join(c.value for c in finding.capabilities))
            if finding.asset_reach:
                tags.append("assets:" + ",".join(a.value for a in finding.asset_reach))
            if tags:
                print(f"    Tags:  {' '.join(tags)}", file=out)

            print(file=out)

        print(sep, file=out)
        if result.decision == Decision.PASS:
            print("PASSED - No significant security issues detected.", file=out)
        elif result.decision == Decision.REVIEW:
            print("REVIEW REQUIRED - Security issues require human review.", file=out)
        else:
            print("BLOCKED - Critical security issues detected. Do not install.", file=out)
        print(file=out)
