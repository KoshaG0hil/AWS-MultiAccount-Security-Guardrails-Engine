"""AWS Multi-Account Security Governance & SCP Guardrails Interactive CLI.

Provides multi-account landing zone simulation, SCP policy linting, and self-healing enforcement.
"""

import argparse
from pathlib import Path
import sys
from typing import Dict, List

# Ensure UTF-8 output on Windows consoles
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except AttributeError:
        pass

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from .core.config import (
    AccountContext,
    AccountStatus,
    GovernanceConfig,
)
from .remediation.account_quarantine import AccountQuarantineController
from .remediation.self_healing_enforcer import SelfHealingEnforcer
from .reporters.compliance_manifest import ComplianceManifestGenerator
from .scanners.drift_scanner import MultiAccountDriftScanner
from .scanners.scp_linter import ScpLinter

console = Console(force_terminal=True)

BANNER = r"""[bold cyan]
    ___ _       ______   ____                        _          __  _                 
   /   | |     / / ___/ / __ \_________ _____ _____(_)___ _____/ / (_)___  ____ ______
  / /| | | /| / /\__ \ / / / / ___/ __ `/ __ `/ __  / / __ `/ __  / / / __ \/ __ `/ ___/
 / ___ | |/ |/ /___/ // /_/ / /  / /_/ / /_/ / /_/ / / /_/ / /_/ / / / /_/ / /_/ (__  ) 
/_/  |_|__/|__//____/ \____/_/   \__,_/\__, /\__,_/_/\__,_/\__,_/_/_/\____/\__, /____/  
                                      /____/                              /____/        
[/bold cyan][bold dim]Enterprise AWS Multi-Account Security Governance & Landing Zone Guardrails Engine[/bold dim]
"""


def render_banner():
    console.print(BANNER)


def get_demo_accounts() -> List[AccountContext]:
    """Generates standard enterprise multi-account landing zone topology."""
    return [
        AccountContext("111100001111", "Org-Management-Root", "r-root", "Root", "root@enterprise.aws"),
        AccountContext("222200002222", "Security-Tooling-Core", "ou-core", "Core_Security", "sec-tools@enterprise.aws"),
        AccountContext("333300003333", "Workloads-Production", "ou-prod", "Workloads_Prod", "prod-lead@enterprise.aws"),
        AccountContext(
            "444400004444", "Workloads-Staging", "ou-nonprod", "Workloads_NonProd", "dev-lead@enterprise.aws"
        ),
        AccountContext("555500005555", "Developer-Sandbox-Lab", "ou-sandbox", "Sandbox_Lab", "sandbox@enterprise.aws"),
    ]


def cmd_lint_scp(args):
    """Lints and validates all Service Control Policies (SCPs) in policies directory."""
    linter = ScpLinter()
    policies_dir = Path(args.dir) if args.dir else GovernanceConfig.get_policies_dir()

    console.print(
        Panel(
            f"[bold white]Target Policy Directory:[/bold white] {policies_dir}\n"
            f"[dim]Checking AWS Organizations 5,120-byte limit, Deny-effect best practices, and conditions...[/dim]",
            title="[SCP Policy Linter]",
            border_style="cyan",
        )
    )

    results = linter.lint_directory(policies_dir)
    table = Table(title="[SCP Policy Validation Results]", show_header=True, header_style="bold magenta")
    table.add_column("Policy File", style="cyan", width=36)
    table.add_column("Size (Bytes)", style="dim", width=14)
    table.add_column("Status", style="bold", width=12)
    table.add_column("Findings & Warnings", style="yellow", width=45)

    all_valid = True
    for res in results:
        status_str = "[green]VALID[/green]" if res.is_valid else "[red]INVALID[/red]"
        findings = ", ".join(res.errors + res.warnings) or "Passed all checks"
        table.add_row(res.policy_name, f"{res.size_bytes} / 5120", status_str, findings)
        if not res.is_valid:
            all_valid = False

    console.print(table)
    if all_valid:
        console.print(
            "[bold green][✓] All Service Control Policies conform to AWS Organizations specifications![/bold green]\n"
        )


def cmd_simulate(args):
    """Runs end-to-end multi-account landing zone drift simulation and self-healing."""
    accounts = get_demo_accounts()
    scanner = MultiAccountDriftScanner()
    enforcer = SelfHealingEnforcer(dry_run=True)
    quarantine = AccountQuarantineController(dry_run=True)
    reporter = ComplianceManifestGenerator()

    console.print(
        Panel(
            f"[bold yellow]Executing Multi-Account Landing Zone Drift Simulation[/bold yellow]\n"
            f"[dim]Scanning {len(accounts)} accounts across Core, Workloads, and Sandbox OUs...[/dim]\n"
            f"[dim]Mode: {'DRY-RUN (Detection Only)' if args.dry_run else 'ACTIVE AUTONOMOUS SELF-HEALING'}[/dim]",
            title="[Governance Engine Sweep]",
            border_style="green",
        )
    )

    # Inject realistic compliance violations
    violations_by_account: Dict[str, list] = {
        # Management & Core are compliant
        "111100001111": [],
        "222200002222": [],
        # Prod has unauthorized IGW attached
        "333300003333": scanner.scan_account(
            accounts[2],
            simulated_drift={"rogue_igw_attached": True, "igw_id": "igw-0812ab34cd56"},
        ),
        # Staging has disabled S3 Block Public Access & unapproved region (eu-west-1)
        "444400004444": scanner.scan_account(
            accounts[3],
            simulated_drift={
                "s3_public_access_disabled": True,
                "has_unapproved_regions": True,
                "rogue_region": "eu-west-1",
            },
        ),
        # Sandbox has root user activity
        "555500005555": scanner.scan_account(
            accounts[4],
            simulated_drift={"root_account_active": True},
        ),
    }

    all_violations = []
    for v_list in violations_by_account.values():
        all_violations.extend(v_list)

    # Render Initial Drift Table
    table = Table(title="[Multi-Account Compliance Drift Assessment]", show_header=True, header_style="bold cyan")
    table.add_column("Account Name", style="white", width=24)
    table.add_column("OU", style="dim", width=18)
    table.add_column("Rule Violation", style="yellow", width=32)
    table.add_column("Severity", style="bold", width=12)
    table.add_column("Remediation Status", style="bold", width=22)

    for acc in accounts:
        v_list = violations_by_account.get(acc.account_id, [])
        if not v_list:
            table.add_row(
                acc.account_name,
                acc.ou_name,
                "[green]None (Compliant)[/green]",
                "[green]CLEAN[/green]",
                "[green]COMPLIANT[/green]",
            )
        else:
            acc.status = AccountStatus.DRIFT_DETECTED
            for v in v_list:
                sev_color = "red" if v.severity.value == "CRITICAL" else "yellow"
                table.add_row(
                    acc.account_name,
                    acc.ou_name,
                    v.rule_name,
                    f"[{sev_color}]{v.severity.value}[/{sev_color}]",
                    "[yellow]PENDING_REMEDIATION[/yellow]",
                )

    console.print(table)

    # Execute Autonomous Remediation
    console.print("\n[bold yellow][*] Executing Automated Self-Healing Guardrails...[/bold yellow]")
    remediated_count = enforcer.remediate_all(all_violations)

    # Execute quarantine on critically compromised accounts (Sandbox with Root Access)
    sandbox_account = accounts[4]
    quarantined = quarantine.quarantine_account(sandbox_account, reason="Unauthorized Root Console Login")
    if quarantined:
        console.print(
            f"[bold red][!] Account {sandbox_account.account_name} ({sandbox_account.account_id}) moved to Quarantine OU [Lockdown SCP Enforced][/bold red]"
        )

    # Calculate post-remediation score
    final_score = scanner.calculate_compliance(accounts, violations_by_account)
    manifest = reporter.generate(final_score, accounts, all_violations)
    out_file = reporter.save_report(manifest)

    # Executive Summary Panel
    console.print(
        Panel(
            f"[bold green]Overall Compliance Rating:[/bold green] {final_score.overall_percentage}%\n"
            f"[bold white]Total Evaluated Accounts:[/bold white]   {final_score.total_accounts}\n"
            f"[bold green]Compliant Accounts:[/bold green]          {final_score.compliant_accounts}\n"
            f"[bold yellow]Remediated Violations:[/bold yellow]       {remediated_count} of {len(all_violations)}\n"
            f"[bold red]Quarantined Accounts:[/bold red]        {final_score.quarantined_accounts}\n"
            f"[bold cyan]Cryptographic SHA-256:[/bold cyan]        {manifest['sha256_checksum']}\n"
            f"[bold dim]Audit Manifest Saved:[/bold dim]         {out_file}",
            title="[Executive Landing Zone Compliance Posture]",
            border_style="green",
        )
    )


def cmd_quarantine(args):
    """Manually isolates a compromised AWS account."""
    quarantine = AccountQuarantineController(dry_run=args.dry_run)
    acc = AccountContext(
        account_id=args.account_id,
        account_name=args.account_name or f"Account-{args.account_id}",
        ou_id="ou-workloads",
        ou_name="Workloads",
        email="security-lead@enterprise.aws",
    )
    success = quarantine.quarantine_account(acc, reason=args.reason)
    if success:
        console.print(
            f"[bold red][✓] Account {acc.account_id} ({acc.account_name}) isolated into Quarantine OU with DenyAll policy.[/bold red]"
        )


def main():
    parser = argparse.ArgumentParser(description="AWS Multi-Account Security Governance & SCP Guardrails CLI")
    subparsers = parser.add_subparsers(dest="command", help="Operational Subcommands")

    # Lint SCP
    lint_parser = subparsers.add_parser("lint-scp", help="Lint and validate SCP JSON policies")
    lint_parser.add_argument("--dir", default=None, help="Directory containing SCP JSON policies")

    # Simulate
    sim_parser = subparsers.add_parser("simulate", help="Run multi-account landing zone simulation")
    sim_parser.add_argument("--dry-run", action="store_true", help="Run without mutating resources")

    # Quarantine
    quar_parser = subparsers.add_parser("quarantine-account", help="Isolate compromised member account")
    quar_parser.add_argument("--account-id", required=True, help="12-digit AWS Account ID")
    quar_parser.add_argument("--account-name", default=None, help="Descriptive account name")
    quar_parser.add_argument("--reason", default="Manual Security Incident Isolation", help="Quarantine justification")
    quar_parser.add_argument("--dry-run", action="store_true", help="Simulate quarantine without moving account")

    args = parser.parse_args()
    render_banner()

    if args.command == "lint-scp":
        cmd_lint_scp(args)
    elif args.command == "simulate":
        cmd_simulate(args)
    elif args.command == "quarantine-account":
        cmd_quarantine(args)
    else:
        cmd_simulate(args)


if __name__ == "__main__":
    main()
