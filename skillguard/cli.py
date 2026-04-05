"""Command-line interface for SkillGuard."""

import sys
import click

from skillguard.scanner import scan, DEFAULT_PASS_THRESHOLD, DEFAULT_REVIEW_THRESHOLD
from skillguard.models import Decision
from skillguard.reporters.text_reporter import TextReporter
from skillguard.reporters.json_reporter import JsonReporter


@click.group()
@click.version_option(version="0.1.0", prog_name="skillguard")
def main():
    """SkillGuard - AI Agent Skill Supply Chain Security Scanner.

    Agent skills are executable supply chains. Trust nothing you install.
    """
    pass


@main.command()
@click.argument("target")
@click.option(
    "--mode",
    type=click.Choice(["report", "warn", "enforce"], case_sensitive=False),
    default="report",
    show_default=True,
    help=(
        "Scan mode: "
        "'report' always exits 0, "
        "'warn' exits 1 on REVIEW / 2 on BLOCK, "
        "'enforce' same as warn with stricter messaging."
    ),
)
@click.option(
    "--threshold",
    type=int,
    default=None,
    help=(
        f"Pass score threshold (default {DEFAULT_PASS_THRESHOLD}). "
        "Scores below this but above review-threshold result in REVIEW."
    ),
)
@click.option(
    "--review-threshold",
    "review_threshold",
    type=int,
    default=None,
    help=(
        f"Review score threshold (default {DEFAULT_REVIEW_THRESHOLD}). "
        "Scores below this result in BLOCK."
    ),
)
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["text", "json"], case_sensitive=False),
    default="text",
    show_default=True,
    help="Output format.",
)
@click.option(
    "--rules-dir",
    "rules_dir",
    type=click.Path(exists=True, file_okay=False, dir_okay=True),
    default=None,
    help="Path to custom rules directory.",
)
@click.option(
    "--no-color",
    is_flag=True,
    default=False,
    help="Disable colored output.",
)
def scan_cmd(
    target: str,
    mode: str,
    threshold: int,
    review_threshold: int,
    output_format: str,
    rules_dir: str,
    no_color: bool,
) -> None:
    """Scan a skill, plugin, MCP, or directory for security issues.

    TARGET can be:
    \b
      - A local file path (e.g. ./install.sh)
      - A local directory (e.g. ./my-skill/)
      - A GitHub repo (e.g. github:owner/repo or https://github.com/owner/repo)

    Exit codes (in warn/enforce mode):
    \b
      0  PASS
      1  REVIEW
      2  BLOCK
    """
    pass_thresh = threshold if threshold is not None else DEFAULT_PASS_THRESHOLD
    review_thresh = review_threshold if review_threshold is not None else DEFAULT_REVIEW_THRESHOLD

    try:
        result = scan(
            target=target,
            rules_dir=rules_dir,
            pass_threshold=pass_thresh,
            review_threshold=review_thresh,
        )
    except RuntimeError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(3)
    except FileNotFoundError as e:
        click.echo(f"Error: Target not found - {e}", err=True)
        sys.exit(3)

    # Output results
    if output_format == "json":
        reporter = JsonReporter()
        reporter.report(result)
    else:
        use_color = not no_color
        reporter = TextReporter(use_color=use_color)
        reporter.report(result)

    # Determine exit code
    if mode == "report":
        sys.exit(0)
    else:
        # warn or enforce mode
        if result.decision == Decision.PASS:
            if mode == "enforce":
                click.echo("SkillGuard: PASSED", err=True)
            sys.exit(0)
        elif result.decision == Decision.REVIEW:
            if mode == "enforce":
                click.echo(
                    "SkillGuard [enforce]: REVIEW REQUIRED - "
                    "Security issues found. Manual review needed before deployment.",
                    err=True,
                )
            else:
                click.echo("SkillGuard [warn]: REVIEW REQUIRED", err=True)
            sys.exit(1)
        else:  # BLOCK
            if mode == "enforce":
                click.echo(
                    "SkillGuard [enforce]: BLOCKED - "
                    "Critical security issues detected. Deployment rejected.",
                    err=True,
                )
            else:
                click.echo("SkillGuard [warn]: BLOCKED", err=True)
            sys.exit(2)


# Register scan command under both 'scan' and as default
main.add_command(scan_cmd, name="scan")


if __name__ == "__main__":
    main()
