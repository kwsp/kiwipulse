#!/usr/bin/env python3
"""kiwipulse - system health monitor with Discord alerts."""

import argparse
import os
import re
import shutil
import socket
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timezone

import requests
from dotenv import load_dotenv

load_dotenv()

DISCORD_WEBHOOK_URL = os.getenv("DISCORD_WEBHOOK_URL", "")

# Configurable thresholds
DISK_ALERT_PCT = int(os.getenv("DISK_ALERT_PCT", "80"))
INODE_ALERT_PCT = int(os.getenv("INODE_ALERT_PCT", "80"))
LOAD_ALERT_MULTIPLIER = float(os.getenv("LOAD_ALERT_MULTIPLIER", "2.0"))  # x CPU count
MEMORY_ALERT_PCT = int(os.getenv("MEMORY_ALERT_PCT", "70"))
SSL_WARN_DAYS = int(os.getenv("SSL_WARN_DAYS", "30"))

# Space-separated list of system services to check, e.g. "nginx postgresql ssh"
SERVICES = os.getenv("SERVICES", "").split()

# Space-separated list of systemd --user services to check, e.g. "syncthing gpg-agent"
USER_SERVICES = os.getenv("USER_SERVICES", "").split()

# Space-separated list of domains to check SSL, e.g. "example.com api.example.com"
SSL_DOMAINS = os.getenv("SSL_DOMAINS", "").split()


@dataclass
class Alert:
    level: str  # "warning" or "critical"
    category: str
    message: str


@dataclass
class CheckResult:
    alerts: list[Alert] = field(default_factory=list)
    ok_lines: list[str] = field(default_factory=list)
    verbose: bool = False

    def warn(self, category: str, message: str) -> None:
        self.alerts.append(Alert("warning", category, message))

    def critical(self, category: str, message: str) -> None:
        self.alerts.append(Alert("critical", category, message))

    def ok(self, category: str, message: str) -> None:
        if self.verbose:
            self.ok_lines.append(f"OK {category} {message}")


# ---------------------------------------------------------------------------
# Checks
# ---------------------------------------------------------------------------

def check_disk(result: CheckResult) -> None:
    for part in _df_output():
        use_pct = int(part["use%"].rstrip("%"))
        if use_pct >= DISK_ALERT_PCT:
            result.critical("disk", f"{part['mounted']} usage at {use_pct}% ({part['used']}/{part['size']})")
        else:
            result.ok("disk", f"{part['mounted']} {use_pct}% used ({part['used']}/{part['size']})")

    for part in _df_inode_output():
        iuse_pct_str = part.get("iuse%", "0%").rstrip("%")
        if iuse_pct_str == "-":
            continue
        iuse_pct = int(iuse_pct_str)
        if iuse_pct >= INODE_ALERT_PCT:
            result.critical("disk", f"{part['mounted']} inode usage at {iuse_pct}%")
        else:
            result.ok("disk", f"{part['mounted']} inodes {iuse_pct}% used")


def check_services(result: CheckResult) -> None:
    _check_service_list(result, SERVICES, user=False)
    _check_service_list(result, USER_SERVICES, user=True)


def _check_service_list(result: CheckResult, services: list[str], user: bool) -> None:
    if not services:
        return
    label = " (user)" if user else ""
    cmd_prefix = ["systemctl", "--user"] if user else ["systemctl"]
    for svc in services:
        try:
            proc = subprocess.run(
                [*cmd_prefix, "is-active", svc],
                capture_output=True, text=True, timeout=10
            )
            status = proc.stdout.strip()
            if status != "active":
                result.critical("service", f"{svc!r}{label} is {status!r}")
            else:
                result.ok("service", f"{svc!r}{label} is active")
        except FileNotFoundError:
            result.warn("service", "systemctl not found — skipping service checks")
            break
        except subprocess.TimeoutExpired:
            result.warn("service", f"timeout checking {svc!r}{label}")


def check_security_updates(result: CheckResult) -> None:
    # Debian/Ubuntu
    if shutil.which("apt-get"):
        try:
            subprocess.run(["apt-get", "-qq", "update"], capture_output=True, timeout=60)
            proc = subprocess.run(
                ["apt-get", "--just-print", "upgrade"],
                capture_output=True, text=True, timeout=30
            )
            upgradable = [
                line for line in proc.stdout.splitlines()
                if line.startswith("Inst")
            ]
            security_upgrades = [l for l in upgradable if "security" in l.lower()]
            if security_upgrades:
                result.critical(
                    "security",
                    f"{len(security_upgrades)} security update(s) pending"
                )
            elif upgradable:
                result.warn("security", f"{len(upgradable)} package update(s) pending")
            else:
                result.ok("security", "all packages up to date")
        except subprocess.TimeoutExpired:
            result.warn("security", "apt-get update timed out")
        return

    # RHEL/Fedora
    if shutil.which("dnf"):
        try:
            proc = subprocess.run(
                ["dnf", "check-update", "--security", "-q"],
                capture_output=True, text=True, timeout=60
            )
            # exit code 100 means updates available
            if proc.returncode == 100:
                count = len([l for l in proc.stdout.splitlines() if l.strip()])
                result.critical("security", f"{count} security update(s) pending (dnf)")
        except subprocess.TimeoutExpired:
            result.warn("security", "dnf check-update timed out")
        return


def check_ssl(result: CheckResult) -> None:
    if not SSL_DOMAINS:
        return
    for domain in SSL_DOMAINS:
        try:
            proc = subprocess.run(
                [
                    "openssl", "s_client",
                    "-connect", f"{domain}:443",
                    "-servername", domain,
                ],
                input="Q\n", capture_output=True, text=True, timeout=10
            )
            cert_info = subprocess.run(
                ["openssl", "x509", "-noout", "-enddate"],
                input=proc.stdout, capture_output=True, text=True, timeout=5
            )
            match = re.search(r"notAfter=(.*)", cert_info.stdout)
            if not match:
                result.warn("ssl", f"{domain}: could not parse cert expiry")
                continue
            expiry = datetime.strptime(match.group(1).strip(), "%b %d %H:%M:%S %Y %Z")
            expiry = expiry.replace(tzinfo=timezone.utc)
            days_left = (expiry - datetime.now(timezone.utc)).days
            if days_left < 0:
                result.critical("ssl", f"{domain}: certificate EXPIRED {-days_left}d ago")
            elif days_left < SSL_WARN_DAYS:
                level = "critical" if days_left < 7 else "warning"
                getattr(result, level)("ssl", f"{domain}: cert expires in {days_left}d")
            else:
                result.ok("ssl", f"{domain}: cert valid for {days_left}d")
        except subprocess.TimeoutExpired:
            result.warn("ssl", f"{domain}: connection timed out")
        except Exception as e:
            result.warn("ssl", f"{domain}: {e}")


def check_backups(result: CheckResult) -> None:
    """Check common backup indicators. Extend BACKUP_PATHS in .env as needed."""
    backup_paths_env = os.getenv("BACKUP_PATHS", "")
    backup_paths = [p.strip() for p in backup_paths_env.split(",") if p.strip()]
    max_age_hours = int(os.getenv("BACKUP_MAX_AGE_HOURS", "26"))

    if not backup_paths:
        return

    for path in backup_paths:
        if not os.path.exists(path):
            result.critical("backup", f"backup path not found: {path}")
            continue
        mtime = datetime.fromtimestamp(os.path.getmtime(path), tz=timezone.utc)
        age_hours = (datetime.now(timezone.utc) - mtime).total_seconds() / 3600
        if age_hours > max_age_hours:
            result.critical(
                "backup",
                f"{path}: last modified {age_hours:.1f}h ago (threshold {max_age_hours}h)"
            )
        else:
            result.ok("backup", f"{path}: last modified {age_hours:.1f}h ago")


def check_load_and_memory(result: CheckResult) -> None:
    cpu_count = os.cpu_count() or 1

    # Load average (1-min)
    load1 = os.getloadavg()[0]
    threshold = cpu_count * LOAD_ALERT_MULTIPLIER
    if load1 > threshold:
        result.critical("load", f"1-min load {load1:.2f} > threshold {threshold:.2f} ({cpu_count} CPUs)")
    else:
        result.ok("load", f"1-min load {load1:.2f} (threshold {threshold:.2f}, {cpu_count} CPUs)")

    # Memory
    try:
        with open("/proc/meminfo") as f:
            meminfo = {
                line.split(":")[0]: int(line.split()[1])
                for line in f
                if ":" in line
            }
        total = meminfo.get("MemTotal", 0)
        available = meminfo.get("MemAvailable", 0)
        if total > 0:
            used_pct = round((1 - available / total) * 100)
            if used_pct >= MEMORY_ALERT_PCT:
                result.critical(
                    "memory",
                    f"memory usage at {used_pct}% "
                    f"({_human(total - available)} used / {_human(total)} total)"
                )
            else:
                result.ok(
                    "memory",
                    f"{used_pct}% used ({_human(total - available)} / {_human(total)})"
                )
    except OSError:
        pass


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _df_output() -> list[dict]:
    proc = subprocess.run(
        ["df", "-h", "--output=source,size,used,avail,pcent,target"],
        capture_output=True, text=True
    )
    return _parse_df(proc.stdout)


def _df_inode_output() -> list[dict]:
    proc = subprocess.run(
        ["df", "--output=source,itotal,iused,iavail,ipcent,target"],
        capture_output=True, text=True
    )
    headers = ["filesystem", "itotal", "iused", "iavail", "iuse%", "mounted"]
    rows = []
    for line in proc.stdout.splitlines()[1:]:
        parts = line.split()
        if len(parts) == len(headers):
            rows.append(dict(zip(headers, parts)))
    return [r for r in rows if not r["filesystem"].startswith("tmpfs")]


def _parse_df(output: str) -> list[dict]:
    # --output=source,size,used,avail,pcent,target
    headers = ["filesystem", "size", "used", "avail", "use%", "mounted"]
    rows = []
    for line in output.splitlines()[1:]:
        parts = line.split()
        if len(parts) == len(headers):
            rows.append(dict(zip(headers, parts)))
    return [
        r for r in rows
        if not r["filesystem"].startswith("tmpfs")
        and r["mounted"] not in ("/dev", "/sys", "/proc", "/run")
    ]


def _human(kb: int) -> str:
    for unit in ("KB", "MB", "GB", "TB"):
        if kb < 1024:
            return f"{kb:.0f}{unit}"
        kb /= 1024
    return f"{kb:.1f}PB"


# ---------------------------------------------------------------------------
# Discord notification
# ---------------------------------------------------------------------------

LEVEL_EMOJI = {"warning": "⚠️", "critical": "🔴"}
LEVEL_COLOR = {"warning": 0xFFA500, "critical": 0xFF0000}


def send_discord_alert(alerts: list[Alert]) -> None:
    if not DISCORD_WEBHOOK_URL:
        print("DISCORD_WEBHOOK_URL not set — printing alerts only")
        for a in alerts:
            print(f"[{a.level.upper()}] {a.category}: {a.message}")
        return

    hostname = socket.gethostname()
    has_critical = any(a.level == "critical" for a in alerts)
    color = LEVEL_COLOR["critical"] if has_critical else LEVEL_COLOR["warning"]

    by_category: dict[str, list[Alert]] = {}
    for a in alerts:
        by_category.setdefault(a.category, []).append(a)

    fields = []
    for category, items in by_category.items():
        value = "\n".join(
            f"{LEVEL_EMOJI[a.level]} {a.message}" for a in items
        )
        fields.append({"name": category.upper(), "value": value, "inline": False})

    payload = {
        "embeds": [
            {
                "title": f"System Monitor Alert — {hostname}",
                "color": color,
                "fields": fields,
                "footer": {"text": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")},
            }
        ]
    }

    resp = requests.post(DISCORD_WEBHOOK_URL, json=payload, timeout=10)
    resp.raise_for_status()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="kiwipulse system health monitor")
    parser.add_argument("-v", "--verbose", action="store_true", help="print all checks, not just alerts")
    args = parser.parse_args()

    result = CheckResult(verbose=args.verbose)

    checks = [
        check_disk,
        check_services,
        check_security_updates,
        check_ssl,
        check_backups,
        check_load_and_memory,
    ]

    for check in checks:
        try:
            check(result)
        except Exception as e:
            result.warn("monitor", f"{check.__name__} failed: {e}")

    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    for line in result.ok_lines:
        print(f"{ts} {line}")
    if result.alerts:
        for a in result.alerts:
            print(f"{ts} {a.level.upper()} {a.category} {a.message}")
        send_discord_alert(result.alerts)
    elif not result.ok_lines:
        print(f"{ts} OK all checks passed")


if __name__ == "__main__":
    main()
