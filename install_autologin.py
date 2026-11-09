#!/usr/bin/env python3
"""Install or update the college autologin LaunchAgent for the current macOS user."""
import getpass
import json
import os
from pathlib import Path
import plistlib
import re
import shutil
import subprocess
import sys
import venv


def main():
    if sys.platform != "darwin":
        raise SystemExit("Run this installer on your Mac.")
    source = Path(__file__).resolve().with_name("autologin.py")
    if not source.is_file():
        raise SystemExit("Place autologin.py and install_autologin.py in the same folder.")
    base = Path.home() / "Library/Application Support/FortiGateAutoLogin"
    base.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(base, 0o700)
    python = base / ".venv/bin/python"
    if "--finish" not in sys.argv:
        print("Setting up the private Python environment. Internet access is needed for installation.")
        if not python.exists():
            venv.EnvBuilder(with_pip=True).create(base / ".venv")
        subprocess.run([str(python), "-m", "pip", "install", "requests"], check=True)
        subprocess.run([str(python), str(Path(__file__).resolve()), "--finish"], check=True)
        return

    import autologin

    print("Connect to college Wi-Fi and complete any browser login before continuing.")
    if input("Are you currently on the college Wi-Fi? [yes/no] ").strip().lower() != "yes":
        raise SystemExit("Connect to college Wi-Fi, then run the installer again.")
    identity = autologin.wifi_identity()
    ports = autologin.networksetup("-listallhardwareports")
    wifi = re.findall(r"^Hardware Port: (?:Wi-Fi|AirPort)\s*\nDevice: (en\d+)\s*$", ports, re.M)
    if not identity or identity["interface"] not in wifi:
        raise SystemExit("Cannot identify the active Wi-Fi router. Turn off any VPN, connect to college Wi-Fi, open a website, and retry.")
    config = dict(autologin.CONFIG)
    networks = config.setdefault("networks", [])
    if identity not in networks:
        networks.append(identity)
    print(f"Enrolling router {identity['gateway']} ({identity['mac']}) on {identity['interface']}.")
    username = input("College username (Enter keeps the saved value): ").strip()
    password = getpass.getpass("College password (Enter keeps the saved value): ")
    config["username"] = username or config.get("username", "")
    config["password"] = password or config.get("password", "")
    if not config["username"] or not config["password"]:
        raise SystemExit("A username and password are required.")
    config["wifi_recovery"] = input("Enable Wi-Fi power recovery after sustained failure on this router? [yes/no] ").strip().lower() == "yes"
    temporary = base / "config.json.tmp"
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as handle:
        json.dump(config, handle, indent=2)
    os.chmod(temporary, 0o600)
    temporary.replace(base / "config.json")

    label = "local.college.autologin"
    domain = f"gui/{os.getuid()}"
    agents = Path.home() / "Library/LaunchAgents"
    agents.mkdir(parents=True, exist_ok=True)
    plist = agents / f"{label}.plist"
    # Stop the previous instance before replacing its executable.
    subprocess.run(["/bin/launchctl", "bootout", f"{domain}/{label}"], capture_output=True)
    installed = base / "autologin.py"
    if source != installed:
        shutil.copy2(source, installed)
    job = {
        "Label": label,
        "ProgramArguments": [str(python), str(installed)],
        "RunAtLoad": True,
        "KeepAlive": {"SuccessfulExit": False},
        "ThrottleInterval": 30,
        "WorkingDirectory": str(base),
        "StandardOutPath": "/dev/null",
        "StandardErrorPath": "/dev/null",
        "Umask": 63,
    }
    with plist.open("wb") as handle:
        plistlib.dump(job, handle)
    os.chmod(plist, 0o600)
    subprocess.run(["/bin/launchctl", "enable", f"{domain}/{label}"], check=True)
    subprocess.run(["/bin/launchctl", "bootstrap", domain, str(plist)], check=True)
    print("Installed and started. It will run in the background at each macOS login.")
    print("Credentials are saved in an owner-only config.json in " + str(base))
    print("Log: ~/Library/Logs/FortiGateAutoLogin/autologin.log")


if __name__ == "__main__":
    main()
