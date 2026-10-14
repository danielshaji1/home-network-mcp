"""
NetWarden Command Line Interface.
Direct terminal management utility for home network operations and diagnostics.
"""

import sys
import json
import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from typing import Optional
from netwarden.server import ctx

cli = typer.Typer(help="NetWarden: Intelligent Home Network AI Agent & Terraform Orchestrator")
console = Console()


@cli.command("topology")
def show_topology():
    """Display overall network devices, VLANs, and client summary."""
    devices = ctx.inventory.list_devices()
    vlans = ctx.inventory.list_vlans()
    clients = ctx.inventory.list_clients()

    console.print(Panel(
        f"[bold cyan]{ctx.settings.network_name}[/bold cyan] | "
        f"Mgmt VLAN: [yellow]{ctx.settings.management_vlan}[/yellow] | "
        f"Devices: [green]{len(devices)}[/green] | "
        f"Clients: [magenta]{len(clients)}[/magenta]",
        title="Network Overview",
        border_style="cyan",
    ))

    # Devices Table
    dev_table = Table(title="Managed Network Hardware", border_style="blue")
    dev_table.add_column("ID", style="dim")
    dev_table.add_column("Device Name", style="bold white")
    dev_table.add_column("Vendor", style="cyan")
    dev_table.add_column("Type", style="green")
    dev_table.add_column("IP Address", style="yellow")
    dev_table.add_column("Model / Firmware")
    dev_table.add_column("Status", style="bold green")

    for d in devices:
        dev_table.add_row(
            d.id,
            d.name,
            d.vendor.value.upper(),
            d.device_type.value,
            d.ip_address,
            f"{d.model} ({d.firmware_version})",
            d.status.value,
        )
    console.print(dev_table)

    # VLANs Table
    vlan_table = Table(title="Configured VLAN Segments", border_style="magenta")
    vlan_table.add_column("VLAN ID", style="bold yellow")
    vlan_table.add_column("Name", style="bold white")
    vlan_table.add_column("Subnet CIDR", style="cyan")
    vlan_table.add_column("Gateway", style="green")
    vlan_table.add_column("Isolation Level")
    vlan_table.add_column("Purpose")

    for v in vlans:
        vlan_table.add_row(
            str(v.vlan_id),
            v.name,
            v.subnet_cidr,
            v.gateway_ip,
            v.isolation_level.value,
            v.purpose.value,
        )
    console.print(vlan_table)


@cli.command("clients")
def list_clients(status: Optional[str] = typer.Option(None, "--status", "-s", help="Filter: allowed, pending_approval, quarantined, blocked")):
    """List network clients and allowlist status."""
    clients = ctx.allowlist_scenario.list_clients(status)

    table = Table(title="Connected Devices & Admission Status", border_style="green")
    table.add_column("MAC Address", style="bold cyan")
    table.add_column("Hostname", style="bold white")
    table.add_column("IP Address", style="yellow")
    table.add_column("VLAN", style="magenta")
    table.add_column("Category")
    table.add_column("Status", style="bold")
    table.add_column("Switch Port", style="dim")

    for c in clients:
        status_style = {
            "allowed": "[green]ALLOWED[/green]",
            "pending_approval": "[bold yellow]PENDING APPROVAL[/bold yellow]",
            "quarantined": "[bold red]QUARANTINED[/bold red]",
            "blocked": "[red]BLOCKED[/red]",
        }.get(c.status.value, c.status.value)

        table.add_row(
            c.mac_address,
            c.hostname or "Unknown",
            c.ip_address or "Dynamic",
            str(c.vlan_id),
            c.device_category,
            status_style,
            str(c.switch_port or "Wi-Fi"),
        )
    console.print(table)


@cli.command("allow")
def allow_device(
    mac: str = typer.Argument(..., help="MAC address to authorize"),
    vlan: int = typer.Argument(..., help="Target VLAN ID"),
    hostname: Optional[str] = typer.Option(None, "--name", "-n"),
    ip: Optional[str] = typer.Option(None, "--ip", "-i", help="Static DHCP reservation IP"),
    category: str = typer.Option("General", "--category", "-c"),
):
    """Authorize a device onto a VLAN with optional static DHCP binding."""
    res = ctx.allowlist_scenario.allow_device(
        mac_address=mac,
        vlan_id=vlan,
        hostname=hostname,
        ip_reservation=ip,
        category=category,
    )
    console.print(f"[bold green]✓[/bold green] Device [cyan]{mac}[/cyan] approved on VLAN [yellow]{vlan}[/yellow].")
    console.print(json.dumps(res, indent=2))


@cli.command("quarantine")
def quarantine_device(
    mac: str = typer.Argument(..., help="MAC address to isolate"),
    vlan: int = typer.Option(99, "--vlan", "-v", help="Quarantine Sandbox VLAN"),
):
    """Isolate a suspect or rogue device into Quarantine Sandbox."""
    try:
        res = ctx.allowlist_scenario.quarantine_device(mac, vlan)
        console.print(f"[bold red]✓[/bold red] Device [cyan]{mac}[/cyan] moved to Quarantine Sandbox VLAN [yellow]{vlan}[/yellow].")
        console.print(json.dumps(res, indent=2))
    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {e}")


@cli.command("audit")
def audit_security():
    """Run security audit across network infrastructure."""
    report = ctx.hardening_scenario.run_security_audit()

    score_color = "green" if report.overall_score >= 80 else ("yellow" if report.overall_score >= 60 else "red")
    console.print(Panel(
        f"Hardening Score: [{score_color}]{report.overall_score} / 100[/{score_color}] | "
        f"Risk Level: [bold {score_color}]{report.risk_level}[/bold {score_color}] | "
        f"Total Findings: {report.total_findings}",
        title="Security Hardening Report",
        border_style=score_color,
    ))

    table = Table(title="Identified Security Findings", border_style="yellow")
    table.add_column("Severity", style="bold")
    table.add_column("Category")
    table.add_column("Title", style="bold white")
    table.add_column("Affected Device")
    table.add_column("Remediation Suggestion", style="dim")

    for f in report.findings:
        sev_style = {
            "critical": "[bold red]CRITICAL[/bold red]",
            "high": "[red]HIGH[/red]",
            "medium": "[yellow]MEDIUM[/yellow]",
            "low": "[cyan]LOW[/cyan]",
        }.get(f.severity.value, f.severity.value)

        table.add_row(
            sev_style,
            f.category,
            f.title,
            f.affected_device_name,
            f.remediation_suggestion,
        )
    console.print(table)


@cli.command("diagnose")
def diagnose_target(target: str = typer.Argument(..., help="IP address, hostname, or domain")):
    """Run deep network connectivity triage."""
    res = ctx.troubleshooting_scenario.diagnose_target(target)

    status_icon = "[bold green]✓ REACHABLE[/bold green]" if res.reachable else "[bold red]✗ UNREACHABLE[/bold red]"
    console.print(Panel(
        f"Target: [bold cyan]{res.target}[/bold cyan] ({res.resolved_ip or 'DNS unresolvable'}) | {status_icon}\n"
        f"Latency: [yellow]{res.latency_ms or 0:.1f} ms[/yellow] | Packet Loss: [red]{res.packet_loss_pct:.1f}%[/red] | "
        f"Switch Port CRC Errors: [magenta]{res.switch_port_errors}[/magenta]\n\n"
        f"[bold]Root Cause:[/bold] {res.root_cause}\n"
        f"[bold]Recommended Fix:[/bold] {res.recommended_action}",
        title="Diagnostic Analysis",
        border_style="cyan",
    ))


@cli.command("plan")
def terraform_plan():
    """Compile network state into Terraform manifests and run plan."""
    tfvars_path = ctx.generator.generate_tfvars(
        vlans=ctx.inventory.list_vlans(),
        clients=ctx.inventory.list_clients(),
        firewall_rules=ctx.inventory.list_firewall_rules(),
        devices=ctx.inventory.list_devices(),
    )
    plan = ctx.runner.plan(var_file=tfvars_path.name)
    engine = ctx.runner.get_engine_status()

    console.print(f"[bold cyan]Engine:[/bold cyan] {engine['engine_type']}")
    console.print(Panel(
        f"To Add: [green]+{plan.resources_to_add}[/green] | "
        f"To Change: [yellow]~{plan.resources_to_change}[/yellow] | "
        f"To Destroy: [red]-{plan.resources_to_destroy}[/red] | "
        f"Risk: [bold green]{plan.risk_assessment}[/bold green]",
        title="Terraform Plan Summary",
        border_style="green",
    ))
    console.print(plan.raw_plan_output)


@cli.command("apply")
def terraform_apply():
    """Apply declarative configuration to hardware with automatic snapshot."""
    snapshot_state = {
        "vlans": [v.model_dump(mode="json") for v in ctx.inventory.list_vlans()],
        "clients": [c.model_dump(mode="json") for c in ctx.inventory.list_clients()],
        "firewall_rules": [r.model_dump(mode="json") for r in ctx.inventory.list_firewall_rules()],
    }
    snap_id = ctx.state_manager.create_snapshot("CLI Apply Snapshot", snapshot_state)
    res = ctx.runner.apply(auto_approve=True)
    console.print(f"[bold green]✓ Applied Successfully![/bold green] Snapshot: [yellow]{snap_id}[/yellow]")
    console.print(json.dumps(res, indent=2))


def main():
    cli()


if __name__ == "__main__":
    main()
