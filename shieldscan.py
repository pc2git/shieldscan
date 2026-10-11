#!/usr/bin/env python3
"""
ShieldScan — a single-command Linux security scanner.
Checks firewall status, SSH hardening, listening ports, and risky file
permissions, then gives you an overall risk score.

Usage:
    python3 shieldscan.py
"""

import argparse
import os
import re
import shutil
import stat
import subprocess
import time
from pathlib import Path

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Confirm

console = Console()

# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------
# Every issue we find subtracts points from a starting score of 100.
SEVERITY_POINTS = {
    "critical": 25,
    "high": 15,
    "medium": 8,
    "low": 3,
}

findings = []  # list of dicts: {severity, category, message, fix}


def add_finding(severity, category, message, fix, evidence=None, fix_actions=None):
    """evidence is an optional list of concrete items (paths, ports, etc.)
    this finding is about, so the action plan can show exactly what to fix.

    fix_actions is an optional list of (description, callable) pairs.
    Only truly safe, well-understood changes get a fix_action — anything
    requiring human judgment (SUID review, unidentified ports) is left
    evidence-only, with no auto-fix, on purpose."""
    findings.append(
        {
            "severity": severity,
            "category": category,
            "message": message,
            "fix": fix,
            "evidence": evidence or [],
            "fix_actions": fix_actions or [],
        }
    )


def run(cmd):
    """Run a shell command, return stdout as text, or '' if it fails."""
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=5
        )
        return result.stdout
    except Exception:
        return ""


# ---------------------------------------------------------------------------
# Check 1: Firewall status
# ---------------------------------------------------------------------------
def check_firewall():
    console.print("[cyan]→ Checking firewall...[/cyan]")

    # Try firewalld first (Fedora/RHEL default)
    firewalld = run("systemctl is-active firewalld")
    if "active" in firewalld:
        console.print("  [green]firewalld is active[/green]")
        return

    # Try ufw (Debian/Ubuntu default)
    ufw = run("ufw status 2>/dev/null")
    if "Status: active" in ufw:
        console.print("  [green]ufw is active[/green]")
        return

    # Fall back to checking if iptables has any real rules
    iptables = run("iptables -L -n 2>/dev/null")
    rule_lines = [
        l for l in iptables.splitlines() if l and not l.startswith(("Chain", "target"))
    ]
    if rule_lines:
        console.print("  [green]iptables has active rules[/green]")
        return

    def enable_firewall():
        if shutil.which("firewall-cmd"):
            run("sudo systemctl enable --now firewalld")
        elif shutil.which("ufw"):
            run("sudo ufw --force enable")
        else:
            console.print("  [yellow]Neither firewalld nor ufw is installed — install one manually.[/yellow]")

    add_finding(
        "critical",
        "Firewall",
        "No active firewall detected (firewalld, ufw, and iptables all appear off/empty).",
        "Enable a firewall: `sudo systemctl enable --now firewalld` "
        "or `sudo ufw enable`.",
        fix_actions=[("Enable firewalld or ufw (whichever is installed)", enable_firewall)],
    )
    console.print("  [red]No active firewall detected[/red]")


# ---------------------------------------------------------------------------
# Check 2: SSH hardening
# ---------------------------------------------------------------------------
def check_ssh_config():
    console.print("[cyan]→ Checking SSH configuration...[/cyan]")
    config_path = Path("/etc/ssh/sshd_config")

    if not config_path.exists():
        console.print("  [yellow]No sshd_config found (SSH server likely not installed) — skipping[/yellow]")
        return

    try:
        text = config_path.read_text(errors="ignore")
    except PermissionError:
        console.print("  [yellow]Can't read sshd_config (permission denied) — try running with sudo[/yellow]")
        return

    def get_setting(name):
        match = re.search(rf"^\s*{name}\s+(\S+)", text, re.IGNORECASE | re.MULTILINE)
        return match.group(1).lower() if match else None

    def set_sshd_option(name, value):
        """Backup sshd_config, then set or append `name value`, then restart sshd."""
        backup_path = f"/etc/ssh/sshd_config.shieldscan-backup-{int(time.time())}"
        run(f"sudo cp /etc/ssh/sshd_config {backup_path}")

        current_text = config_path.read_text(errors="ignore")
        pattern = re.compile(rf"^\s*#?\s*{name}\s+\S+", re.IGNORECASE | re.MULTILINE)
        if pattern.search(current_text):
            new_text = pattern.sub(f"{name} {value}", current_text)
        else:
            new_text = current_text.rstrip() + f"\n{name} {value}\n"

        tmp_path = "/tmp/shieldscan_sshd_config_new"
        Path(tmp_path).write_text(new_text)
        run(f"sudo cp {tmp_path} /etc/ssh/sshd_config")
        run("sudo systemctl restart sshd")
        console.print(f"   [dim](backup saved to {backup_path})[/dim]")

    root_login = get_setting("PermitRootLogin")
    if root_login in ("yes", None):
        add_finding(
            "high",
            "SSH",
            f"PermitRootLogin is {'enabled' if root_login == 'yes' else 'not explicitly disabled (defaults vary)'}.",
            "Set `PermitRootLogin no` in /etc/ssh/sshd_config, then `sudo systemctl restart sshd`.",
            fix_actions=[("Set PermitRootLogin no and restart sshd (backs up config first)",
                           lambda: set_sshd_option("PermitRootLogin", "no"))],
        )
        console.print("  [red]Root login over SSH is allowed or undefined[/red]")
    else:
        console.print("  [green]Root login is restricted[/green]")

    password_auth = get_setting("PasswordAuthentication")
    if password_auth in ("yes", None):
        add_finding(
            "medium",
            "SSH",
            "Password authentication is enabled (or not explicitly disabled).",
            "Prefer key-based auth: set `PasswordAuthentication no` once your SSH keys are set up.",
            fix_actions=[("Set PasswordAuthentication no and restart sshd — ONLY do this if you already have SSH key login working",
                           lambda: set_sshd_option("PasswordAuthentication", "no"))],
        )
        console.print("  [yellow]Password authentication is allowed[/yellow]")
    else:
        console.print("  [green]Password authentication is disabled (key-only)[/green]")


# ---------------------------------------------------------------------------
# Check 3: Listening ports
# ---------------------------------------------------------------------------
def check_listening_ports():
    console.print("[cyan]→ Checking listening ports...[/cyan]")
    output = run("ss -tulnH")  # -H = no header
    if not output:
        console.print("  [yellow]Could not read listening ports (is `ss` installed?)[/yellow]")
        return

    table = Table(title="Listening Ports")
    table.add_column("Proto")
    table.add_column("Local Address")
    table.add_column("Exposure")

    exposed = []  # (proto, address) pairs that are open to all interfaces
    for line in output.splitlines():
        parts = line.split()
        if len(parts) < 5:
            continue
        proto = parts[0]
        local_addr = parts[4]

        if local_addr.startswith("0.0.0.0") or local_addr.startswith("*:") or local_addr.startswith(":::"):
            exposure = "[red]All interfaces[/red]"
            exposed.append((proto, local_addr))
        elif local_addr.startswith("127.0.0.1") or local_addr.startswith("[::1]"):
            exposure = "[green]Localhost only[/green]"
        else:
            exposure = "[yellow]Specific interface[/yellow]"

        table.add_row(proto, local_addr, exposure)

    console.print(table)

    if exposed:
        running_as_root = os.geteuid() == 0

        # try to name the process using each exposed port (only works with root)
        process_output = run("ss -tulnpH")
        port_to_process = {}
        for line in process_output.splitlines():
            parts = line.split()
            if len(parts) < 5:
                continue
            addr = parts[4]
            proc_match = re.search(r'users:\(\("([^"]+)"', line)
            if proc_match:
                port_to_process[addr] = proc_match.group(1)

        fix_lines = []
        unidentified_count = 0
        for proto, addr in exposed:
            port = addr.rsplit(":", 1)[-1]
            proc = port_to_process.get(addr)

            if port in KNOWN_SYSTEM_PORTS:
                name, note = KNOWN_SYSTEM_PORTS[port]
                fix_lines.append(f"Port {port} = {name}. {note}")
            elif proc:
                fix_lines.append(
                    f"Port {port} ({proc}): if it doesn't need LAN/internet access, "
                    f"edit {proc}'s config to bind 127.0.0.1 instead of 0.0.0.0, then restart it."
                )
            else:
                unidentified_count += 1
                fix_lines.append(
                    f"Port {port}: run `sudo ss -tulnp | grep :{port}` to see which process owns it, "
                    f"then decide if it needs to be open."
                )

        if unidentified_count:
            fix_lines.insert(
                0,
                f"Tip: rerun with sudo (`sudo python3 shieldscan.py`) to auto-identify "
                f"{unidentified_count} process name(s) shown as unknown below.",
            )

        add_finding(
            "medium",
            "Network",
            f"{len(exposed)} service(s) are listening on all network interfaces (0.0.0.0), "
            "making them reachable from your LAN (or the internet, if exposed).",
            "Check each port below — known system services are explained, others need identifying first.",
            evidence=fix_lines,
        )


# ---------------------------------------------------------------------------
# Check 4: Risky file permissions (world-writable, unexpected SUID)
# ---------------------------------------------------------------------------
# Common system ports that are normal background OS services, not something
# a user configured — we still show them, but explain what they are instead
# of just flagging them as a generic unknown exposure.
KNOWN_SYSTEM_PORTS = {
    "5353": ("mDNS / Avahi", "Local device discovery (printers, Chromecasts, etc). Usually safe on a home LAN. Disable with: sudo systemctl disable --now avahi-daemon"),
    "5355": ("LLMNR / systemd-resolved", "Legacy local name resolution. Known spoofing target on untrusted networks. Disable: set LLMNR=no in /etc/systemd/resolved.conf"),
    "67": ("DHCP server", "Only a concern if you're not intentionally running a DHCP server."),
    "68": ("DHCP client", "Normal — your machine requesting an IP address."),
    "631": ("CUPS printing", "Printer sharing. Safe on a trusted LAN, disable if you don't print: sudo systemctl disable --now cups"),
    "5900": ("VNC", "Remote desktop. Make sure it requires a strong password or is firewalled if enabled."),
}

KNOWN_SAFE_SUID = {
    "/usr/bin/sudo",
    "/usr/bin/passwd",
    "/usr/bin/su",
    "/usr/bin/mount",
    "/usr/bin/umount",
    "/usr/bin/ping",
    "/usr/bin/newgrp",
    "/usr/bin/chsh",
    "/usr/bin/chfn",
    "/usr/bin/fusermount3",
    "/usr/bin/crontab",
    "/usr/sbin/mount.nfs",
}

SCAN_DIRS = ["/etc", "/tmp", "/var/tmp", "/usr/bin", "/usr/local/bin"]


def check_file(path: Path):
    issues = []
    try:
        st = path.stat()
    except (PermissionError, FileNotFoundError, OSError):
        return issues

    mode = st.st_mode

    if mode & stat.S_IWOTH and not path.is_dir():
        issues.append(("World-writable file", path))

    if mode & stat.S_ISUID and str(path) not in KNOWN_SAFE_SUID:
        issues.append(("Unexpected SUID binary", path))

    if path.is_dir() and (mode & stat.S_IWOTH) and not (mode & stat.S_ISVTX):
        issues.append(("World-writable dir, no sticky bit", path))

    return issues


def check_permissions():
    console.print("[cyan]→ Checking file permissions (this may take a few seconds)...[/cyan]")
    all_issues = []
    for root in SCAN_DIRS:
        if not os.path.exists(root):
            continue
        for dirpath, dirnames, filenames in os.walk(root, onerror=lambda e: None):
            # Don't recurse forever into huge trees — cap depth for speed
            depth = dirpath[len(root):].count(os.sep)
            if depth >= 3:
                dirnames[:] = []
            for name in dirnames + filenames:
                p = Path(dirpath) / name
                all_issues.extend(check_file(p))

    if not all_issues:
        console.print("  [green]No risky file permissions found[/green]")
        return

    world_writable = [i for i in all_issues if "World-writable" in i[0]]
    suid = [i for i in all_issues if "SUID" in i[0]]

    def remove_world_write(path):
        try:
            current_mode = os.stat(path).st_mode
            os.chmod(path, current_mode & ~stat.S_IWOTH)
        except PermissionError:
            run(f"sudo chmod o-w \"{path}\"")

    def add_sticky_bit(path):
        try:
            current_mode = os.stat(path).st_mode
            os.chmod(path, current_mode | stat.S_ISVTX)
        except PermissionError:
            run(f"sudo chmod +t \"{path}\"")

    if world_writable:
        ww_evidence = [f"chmod o-w \"{p}\"   # review first: ls -la \"{p}\"" for _, p in world_writable[:10]]
        if len(world_writable) > 10:
            ww_evidence.append(f"...and {len(world_writable) - 10} more (rerun scan after fixing these to see the rest)")

        # one fix_action per path, capped at 10 for the same reason evidence is capped —
        # beyond that, rerun the scan after fixing the first batch
        ww_fix_actions = [
            (f"Remove world-write bit on {p}" if "dir" not in issue else f"Add sticky bit on {p}",
             (lambda p=p: remove_world_write(p)) if "dir" not in issue else (lambda p=p: add_sticky_bit(p)))
            for issue, p in world_writable[:10]
        ]

        add_finding(
            "high",
            "Filesystem",
            f"{len(world_writable)} world-writable file(s)/folder(s) found in sensitive locations.",
            "Run `ls -la <path>` first to confirm it's really unintended, then run the chmod command for each path below.",
            evidence=ww_evidence,
            fix_actions=ww_fix_actions,
        )
        console.print(f"  [red]{len(world_writable)} world-writable item(s) found[/red]")

    if suid:
        suid_evidence = [f"ls -la \"{p}\"   # then: chmod u-s \"{p}\"  (only if you don't recognize this binary)" for _, p in suid[:10]]
        if len(suid) > 10:
            suid_evidence.append(f"...and {len(suid) - 10} more (rerun scan with a narrower directory to see the rest)")
        add_finding(
            "medium",
            "Filesystem",
            f"{len(suid)} SUID binary/binaries found outside the known-safe list.",
            "Run `ls -la <path>` on each one below. Most will be legitimate system tools you can add to "
            "the KNOWN_SAFE_SUID list in the script — only remove the SUID bit on ones you don't recognize.",
            evidence=suid_evidence,
            # Deliberately no fix_actions here — removing SUID on the wrong binary
            # can break sudo/mount/etc. This one always requires a human to look first.
        )
        console.print(f"  [yellow]{len(suid)} unexpected SUID binary(ies) found[/yellow]")

    # show detail table, capped at 15 rows so it doesn't flood the terminal
    table = Table(title="File Permission Findings (showing up to 15)")
    table.add_column("Issue")
    table.add_column("Path")
    for issue, p in all_issues[:15]:
        table.add_row(issue, str(p))
    console.print(table)
    if len(all_issues) > 15:
        console.print(f"  ...and {len(all_issues) - 15} more not shown.")


# ---------------------------------------------------------------------------
# Final report
# ---------------------------------------------------------------------------
def print_report():
    console.print()
    console.print(Panel.fit("[bold]ShieldScan Report[/bold]", border_style="cyan"))

    if not findings:
        console.print(Panel.fit("[bold green]No issues found. System looks healthy.[/bold green]", border_style="green"))
        return

    score = 100
    for f in findings:
        score -= SEVERITY_POINTS.get(f["severity"], 0)
    score = max(score, 0)

    color = "green" if score >= 80 else "yellow" if score >= 50 else "red"

    severity_colors = {"critical": "red", "high": "red", "medium": "yellow", "low": "cyan"}
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    sorted_findings = sorted(findings, key=lambda x: order[x["severity"]])

    # --- Section 1: what's wrong (short, scannable table) ---
    table = Table(title="What's Wrong")
    table.add_column("Severity", style="bold")
    table.add_column("Category")
    table.add_column("Issue")

    for f in sorted_findings:
        sev_color = severity_colors.get(f["severity"], "white")
        table.add_row(
            f"[{sev_color}]{f['severity'].upper()}[/{sev_color}]",
            f["category"],
            f["message"],
        )

    console.print(table)
    console.print()

    # --- Section 2: how to fix it (the part you asked for — a clear action plan) ---
    console.print(Panel.fit("[bold]How To Fix This — Action Plan[/bold]", border_style="cyan"))
    console.print()

    for i, f in enumerate(sorted_findings, start=1):
        sev_color = severity_colors.get(f["severity"], "white")
        console.print(f"[bold]{i}. [{sev_color}]{f['severity'].upper()}[/{sev_color}] — {f['category']}: {f['message']}[/bold]")
        console.print(f"   [green]Fix:[/green] {f['fix']}")
        if f["evidence"]:
            console.print("   [dim]Exact items to fix:[/dim]")
            for item in f["evidence"]:
                console.print(f"     [cyan]$[/cyan] {item}")
        console.print()

    # --- Section 3: overall score ---
    console.print(
        Panel.fit(
            f"[bold {color}]Security Score: {score}/100[/bold {color}]\n"
            f"{len(findings)} issue(s) found — fix the CRITICAL and HIGH items first.",
            border_style=color,
        )
    )


def run_fixes(auto_yes):
    """Walk every finding that has fix_actions and apply them, asking for
    confirmation per-action unless auto_yes is set. Findings with no
    fix_actions (SUID, unidentified ports) are listed as skipped — those
    always need a human to look first."""
    console.print()
    console.print(Panel.fit("[bold]Applying Fixes[/bold]", border_style="cyan"))
    console.print()

    if os.geteuid() != 0:
        console.print(
            "[yellow]Not running as root — firewall/SSH/some file fixes may fail. "
            "Consider: sudo python3 shieldscan.py --fix[/yellow]\n"
        )

    fixable = [f for f in findings if f["fix_actions"]]
    unfixable = [f for f in findings if not f["fix_actions"]]

    if not fixable:
        console.print("[yellow]No auto-fixable issues found — everything remaining needs manual review.[/yellow]")
    else:
        for f in fixable:
            console.print(f"[bold]{f['category']}:[/bold] {f['message']}")
            for description, action in f["fix_actions"]:
                if auto_yes or Confirm.ask(f"  Apply: {description}?", default=False):
                    try:
                        action()
                        console.print(f"  [green]✓ Done:[/green] {description}")
                    except Exception as e:
                        console.print(f"  [red]✗ Failed:[/red] {description} — {e}")
                else:
                    console.print(f"  [dim]Skipped:[/dim] {description}")
            console.print()

    if unfixable:
        console.print("[bold]Not auto-fixed (needs your judgment):[/bold]")
        for f in unfixable:
            console.print(f"  • {f['category']}: {f['message']}")
        console.print()


def main():
    parser = argparse.ArgumentParser(description="ShieldScan — Linux security scanner")
    parser.add_argument("--fix", action="store_true", help="Interactively apply safe fixes after scanning")
    parser.add_argument("--yes", action="store_true", help="With --fix, apply all safe fixes without asking")
    args = parser.parse_args()

    console.print(Panel.fit("[bold cyan]ShieldScan — Linux Security Scanner[/bold cyan]"))
    console.print()

    check_firewall()
    console.print()
    check_ssh_config()
    console.print()
    check_listening_ports()
    console.print()
    check_permissions()

    print_report()

    if args.fix:
        run_fixes(auto_yes=args.yes)
        console.print("[cyan]Rerun `python3 shieldscan.py` to confirm the fixes took effect.[/cyan]")


if __name__ == "__main__":
    main()
