# College Wi-Fi autologin

Place autologin.py and install_autologin.py together in Downloads. Stop any old copy with Ctrl+C. Connect to college Wi-Fi and complete the browser login so pip can install requests.

Run in Terminal.

```zsh
cd ~/Downloads
python3 install_autologin.py
```

Confirm that you are on college Wi-Fi, enter your college credentials, and choose whether to enable Wi-Fi power recovery. The installer creates its own Python environment, installs requests, enrolls the active Wi-Fi router, and starts the background LaunchAgent.

It runs automatically after you log into your macOS account, including after reboot. Terminal can be closed. Keep the Python installation used for setup available.

Credentials are stored as plaintext in an owner-only configuration file at ~/Library/Application Support/FortiGateAutoLogin/config.json. The directory has mode 700 and the file has mode 600. The LaunchAgent plist contains no credentials.

## Behavior

- On an enrolled college router, a lightweight HTTP check runs every two seconds. An available portal triggers immediate login, subject to rejection cooldowns.
- Full cross-checks run every five minutes while online and when the primary check fails. All existing discovery endpoints and known FortiGate gateways remain available.
- Background output goes to a rotating log. Normal online logging is limited to once a minute.
- On a different or unidentified router, the script idles and checks the local route every ten seconds. It sends no connectivity probes, credentials, or Wi-Fi power commands in that state.
- Optional power recovery runs after six consecutive NO_NETWORK results on an identified college router, at most once every three minutes.

Router enrollment matches its IP address, hardware address, and Wi-Fi interface. It is a network-selection guard, not cryptographic authentication. Run the installer again while connected to another college router to add it. Existing enrollments are preserved. A router hardware replacement also requires re-enrollment.

If a VPN hides the Wi-Fi route, or macOS loses the route or router hardware address entirely, the script idles until it can identify the college network again. This intentionally limits automatic radio recovery to an identifiable college connection. Wi-Fi must be configured to auto-join the saved college network.

Detection typically begins within the two-second polling interval on the enrolled network. Entering from idle can take up to ten seconds before checking. Gateway response, Wi-Fi association, DHCP, and backoff can add time. Instantaneous reconnection cannot be guaranteed.

The inherited campus portal compatibility allows HTTP and skips HTTPS certificate verification for the configured campus gateway hosts. Internet HTTPS checks still verify certificates.

## View status and logs

```zsh
launchctl print "gui/$(id -u)/local.college.autologin"
tail -f "$HOME/Library/Logs/FortiGateAutoLogin/autologin.log"
```

Ctrl+C exits the log viewer. The background agent continues running.

## Stop and disable automatic startup

```zsh
launchctl bootout "gui/$(id -u)/local.college.autologin"
launchctl disable "gui/$(id -u)/local.college.autologin"
```

Run the installer again to re-enable it.

## Validation

Syntax and simulated checks cover router identity, idle behavior on other networks, the network-change guard before credential submission, prompt portal handling, and immediate verification. Live macOS startup and college network behavior require testing on the Mac. Power recovery command failures, including permission failures, appear in the rotating log.

Apple documents user LaunchAgents and login startup in its [launchd guide](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html).
