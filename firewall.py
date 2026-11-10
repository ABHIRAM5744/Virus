"""Real IP blocking. Dry-run by default: set ENABLE_FIREWALL=1 (and run as root/Administrator) to execute.

Commands are built as argv lists after strict IP validation - nothing is passed through a shell.
"""
import ipaddress
import os
import platform
import subprocess


def _cmds(ip):
    sysname = platform.system()
    if sysname == "Linux":
        return [["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"], ["iptables", "-I", "OUTPUT", "-d", ip, "-j", "DROP"]]
    if sysname == "Windows":
        return [["netsh", "advfirewall", "firewall", "add", "rule", f"name=VIRUS-block-{ip}", "dir=in", "action=block", f"remoteip={ip}"],
                ["netsh", "advfirewall", "firewall", "add", "rule", f"name=VIRUS-block-out-{ip}", "dir=out", "action=block", f"remoteip={ip}"]]
    return []  # macOS etc: no safe default, report the manual command instead


def block(ip):
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return {"ok": False, "error": "invalid ip"}
    if not addr.is_global:
        return {"ok": False, "error": "refusing to block a private/loopback address"}
    ip = str(addr)
    cmds = _cmds(ip)
    shown = " && ".join(" ".join(c) for c in cmds) or f"pfctl rule for {ip} (manual on this OS)"
    if os.getenv("ENABLE_FIREWALL") != "1" or not cmds:
        return {"ok": True, "executed": False, "dry_run": True, "command": shown}
    try:
        for c in cmds:
            p = subprocess.run(c, capture_output=True, text=True, timeout=15)
            if p.returncode != 0:
                return {"ok": False, "executed": False, "command": shown, "error": (p.stderr or p.stdout).strip()[:200]}
        return {"ok": True, "executed": True, "command": shown}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "executed": False, "command": shown, "error": str(e)[:200]}
