# FortiGate Wi-Fi Autologin

Automatically signs in to the NIT Goa FortiGate captive portal. Use the script for your operating system.

## Windows

Download [autologin-windows.py](autologin-windows.py). Install Python 3, then open PowerShell in the folder where you saved the script. Run the following once while you have internet access.

```powershell
py -3 -m venv .autologin-venv
.\.autologin-venv\Scripts\python.exe -m pip install requests
```

Connect to campus Wi-Fi and run the following each time you start the script. PowerShell hides your password as you type.

```powershell
$env:AUTOLOGIN_USER = Read-Host "Campus username"
$campusPassword = Read-Host "Campus password" -AsSecureString
$env:AUTOLOGIN_PASS = [System.Net.NetworkCredential]::new("", $campusPassword).Password
try {
    .\.autologin-venv\Scripts\python.exe .\autologin-windows.py
} finally {
    Remove-Item Env:AUTOLOGIN_USER, Env:AUTOLOGIN_PASS
    Remove-Variable campusPassword
}
```

Press **Ctrl+C** to stop. For a run without a console window, replace the command inside the `try` block with `Start-Process .\.autologin-venv\Scripts\pythonw.exe -ArgumentList '.\autologin-windows.py'`. The script writes `autologin.log` beside the script in both modes. To stop a hidden run, end its `pythonw.exe` process in Task Manager.

This is the original Windows version. Run it only on campus Wi-Fi. It has no router enrollment, and its portal requests permit HTTP and skip HTTPS certificate verification.

## macOS

Save [autologin.py](autologin.py) and [install_autologin.py](install_autologin.py) together. Connect to campus Wi-Fi, complete the browser login, and run `python3 install_autologin.py` from that folder. The installer enrolls the campus router and sets up background startup at macOS account login.

See the [macOS guide](README-macOS.md) for enrollment, logs, and how to stop the background agent.
