# 🛡️ ShieldScan

A single-command Linux security scanner. Run it and get a full report on
your system's firewall status, SSH hardening, exposed network ports, and
risky file permissions — plus an overall security score and an action
plan with exact commands to fix what it finds.

```
ShieldScan — Linux Security Scanner

→ Checking firewall...
  No active firewall detected

→ Checking SSH configuration...
  Root login over SSH is allowed or undefined
  Password authentication is allowed

→ Checking listening ports...
  3 service(s) are listening on all network interfaces (0.0.0.0)

→ Checking file permissions...
  3 world-writable item(s) found
  18 unexpected SUID binary(ies) found

Security Score: 31/100
5 issue(s) found — fix the CRITICAL and HIGH items first.
```

## Why

Checking your own system's security usually means running several separate
tools by hand — `ufw status`, `ss -tulnp`, manually reading `sshd_config`,
hunting for bad file permissions with `find` — and then figuring out what
each result actually means and what to do about it.

ShieldScan runs all of these checks in one go and explains each finding in
plain language: what it is, why it matters, and the exact command to fix
it.

## What it checks

| Check | What it looks for |
|---|---|
| **Firewall** | Is firewalld, ufw, or iptables actually active |
| **SSH hardening** | `PermitRootLogin` and `PasswordAuthentication` settings in `sshd_config` |
| **Listening ports** | Services bound to `0.0.0.0` (reachable from your LAN/internet) instead of `127.0.0.1`. Known system ports (mDNS, LLMNR, CUPS, etc.) are identified and explained, not just flagged |
| **File permissions** | World-writable files/directories and unexpected SUID/SGID binaries across `/etc`, `/tmp`, `/var/tmp`, `/usr/bin`, `/usr/local/bin` |

Every finding is scored by severity (critical / high / medium / low), and
the final score (0–100) reflects the total.

## Install

```bash
git clone https://github.com/<your-username>/shieldscan.git
cd shieldscan
pip3 install rich
```

No other setup required — it's a single file, pure Python plus `rich` for
terminal output.

## Usage

**Run a scan:**
```bash
python3 shieldscan.py
```

**Run a scan with full detail (recommended)** — some checks (like seeing
which process owns an exposed port, or reading all of `/etc`) need root:
```bash
sudo python3 shieldscan.py
```

**Scan and interactively fix what it safely can:**
```bash
sudo python3 shieldscan.py --fix
```
Asks for confirmation before each change.

**Scan and auto-fix everything safe, no prompts:**
```bash
sudo python3 shieldscan.py --fix --yes
```

## What `--fix` will and won't touch

ShieldScan only auto-fixes changes that are safe and reversible. Anything
that requires human judgment is left for you to review manually — this is
a deliberate design choice, not a limitation.

| Finding | Auto-fixed? | Why |
|---|---|---|
| Firewall inactive | ✅ Enables firewalld/ufw | Safe, reversible |
| SSH root login / password auth enabled | ✅ Edits `sshd_config` (backs it up first), restarts sshd | Safe, with a timestamped rollback available |
| World-writable files | ✅ Removes the world-write bit | Narrow, safe change |
| World-writable directories | ✅ Adds the sticky bit | Safer than removing write access outright, which could break legitimate shared directories |
| Unexpected SUID/SGID binaries | ❌ Never auto-fixed | Removing the SUID bit on the wrong binary can break `sudo`, `mount`, or other core tools |
| Unidentified open ports | ❌ Never auto-fixed | Can't safely guess what a port should do without knowing what's using it |

**⚠️ Warning:** the `PasswordAuthentication no` fix will lock you out over
SSH if you don't already have key-based login set up. Make sure SSH keys
are working before applying this one, especially if you're connected to
the target machine over SSH rather than sitting at it directly.

## Example: fixing an exposed port

ShieldScan doesn't just say "port 5353 is open" — it tells you what it is:

```
Port 5353 = mDNS / Avahi. Local device discovery (printers, Chromecasts,
etc). Usually safe on a home LAN. Disable with:
sudo systemctl disable --now avahi-daemon
```

And for ports it doesn't recognize, it tells you exactly how to find out:

```
Port 8080: run `sudo ss -tulnp | grep :8080` to see which process owns
it, then decide if it needs to be open.
```

## Project structure

```
shieldscan.py   — the entire tool (checks, scoring, report, --fix)
README.md       — this file
```

Everything lives in one file by design — it's meant to be easy to read
top to bottom and easy to extend.

## Limitations

- Linux only (relies on `ss`, `systemctl`, `/etc/ssh/sshd_config`, Linux
  permission bits).
- File permission scanning is capped at a depth of 3 directories and a
  fixed set of locations (`/etc`, `/tmp`, `/var/tmp`, `/usr/bin`,
  `/usr/local/bin`) for speed — it is not a full filesystem audit.
- The `KNOWN_SAFE_SUID` and `KNOWN_SYSTEM_PORTS` lists are a starting
  point, not exhaustive. Extend them in `shieldscan.py` as needed for your
  distro.
- This is a point-in-time scanner, not a monitoring tool — it doesn't
  track changes between runs.

## License

MIT
