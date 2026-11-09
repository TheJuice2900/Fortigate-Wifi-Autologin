# FortiGate Wi-Fi Autologin

Automatically signs in to the NIT Goa FortiGate captive portal. Use the script for your operating system.

## Windows

### Windows app

[Download FortiGate-Autologin.exe (64-bit Windows)](https://github.com/TheJuice2900/Fortigate-Wifi-Autologin/releases/download/windows-gui-v1/FortiGate-Autologin.exe). The executable is unsigned and bundles Python and its dependencies.

1. Connect to campus Wi-Fi and close any manual run of the Python script.
2. Open the executable and enter your campus username and password.
3. Choose whether the app should start when you sign in to Windows, then click **Save and Start**.

You can close the window while autologin runs in the background. The app encrypts the saved password for your Windows account on that PC. Reopen the app to **Pause**, **Resume**, or **Open Log Folder**. Pause it before leaving campus because the Windows script checks the active network.

### Manual Python setup

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

### Start automatically after a restart

Save [install-autologin-windows.ps1](install-autologin-windows.ps1) alongside `autologin-windows.py`. Stop any existing manual run. With Python 3 installed and internet access available, open Windows PowerShell in that folder and run:

```powershell
Unblock-File .\install-autologin-windows.ps1
powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File .\install-autologin-windows.ps1
```

Enter your campus credentials. The installer saves the password encrypted for your Windows account on this PC, starts a background task now, and starts it again whenever you sign in to Windows, including after a reboot. Setup copies the files to `%LOCALAPPDATA%\FortiGateAutologin`. Rerun the installer to update the credentials or script.

The Windows script monitors the active network and does not identify campus Wi-Fi before probing. If you also use this PC on other networks, disable the task before leaving campus and enable it when you return.

```powershell
Get-ScheduledTask -TaskName 'FortiGate Wi-Fi Autologin'
Get-Content "$env:LOCALAPPDATA\FortiGateAutologin\autologin.log" -Tail 20
```

To stop the current run and prevent it from starting at the next sign-in:

```powershell
Stop-ScheduledTask -TaskName 'FortiGate Wi-Fi Autologin'
Disable-ScheduledTask -TaskName 'FortiGate Wi-Fi Autologin'
```

To resume, run `Enable-ScheduledTask -TaskName 'FortiGate Wi-Fi Autologin'` followed by `Start-ScheduledTask -TaskName 'FortiGate Wi-Fi Autologin'`.

## macOS

Save [autologin.py](autologin.py) and [install_autologin.py](install_autologin.py) together. Connect to campus Wi-Fi, complete the browser login, and run `python3 install_autologin.py` from that folder. The installer enrolls the campus router and sets up background startup at macOS account login.

See the [macOS guide](README-macOS.md) for enrollment, logs, and how to stop the background agent.
