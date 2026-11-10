"""Desktop setup and scheduled runner for the Windows autologin script."""
import base64
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import traceback

import windows_autologin as autologin


TASK_NAME = "FortiGate Wi-Fi Autologin"
INSTALL_DIR = Path(os.environ["LOCALAPPDATA"]) / "FortiGateAutologin"
CREDENTIAL_FILE = INSTALL_DIR / "credential.xml"
POWERSHELL = Path(os.environ["SystemRoot"]) / "System32/WindowsPowerShell/v1.0/powershell.exe"


def powershell(script, **settings):
    prefix = """
$ErrorActionPreference = 'Stop'
[Console]::InputEncoding = [Text.UTF8Encoding]::new($false)
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
$config = [Console]::In.ReadToEnd() | ConvertFrom-Json
"""
    encoded = base64.b64encode((prefix + script).encode("utf-16-le")).decode("ascii")
    env = os.environ.copy()
    env.pop("PSModulePath", None)  # let Windows PowerShell select its own modules
    result = subprocess.run(
        [str(POWERSHELL), "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded],
        input=json.dumps({"task": TASK_NAME, **settings}), encoding="utf-8",
        capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW, timeout=25, env=env,
    )
    if result.returncode:
        raise RuntimeError(result.stderr.strip() or f"PowerShell exited with code {result.returncode}.")
    return result.stdout.strip()


def install_executable(source, directory):
    with source.open("rb") as executable:
        digest = hashlib.file_digest(executable, "sha256").hexdigest()
    destination = directory / f"FortiGate-Autologin-{digest}.exe"
    if destination.exists():
        return destination

    # Publish a complete copy under a new name. A running copy may be locked.
    with tempfile.NamedTemporaryFile(dir=directory, delete=False) as temporary:
        staged = Path(temporary.name)
    try:
        shutil.copyfile(source, staged)
        try:
            staged.rename(destination)
        except FileExistsError:
            # Another setup window installed this same build first.
            pass
    finally:
        staged.unlink(missing_ok=True)
    return destination


def save_and_start(username, password, startup):
    INSTALL_DIR.mkdir(parents=True, exist_ok=True)
    installed_exe = install_executable(Path(sys.executable), INSTALL_DIR)
    powershell("""
$secret = [Security.SecureString]::new()
foreach ($character in $config.password.ToCharArray()) { $secret.AppendChar($character) }
$credential = [pscredential]::new($config.username, $secret)
$user = [Security.Principal.WindowsIdentity]::GetCurrent().Name
$action = New-ScheduledTaskAction -Execute $config.exe -Argument '--background' -WorkingDirectory $config.directory
$principal = New-ScheduledTaskPrincipal -UserId $user -LogonType Interactive -RunLevel Limited
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
    -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew
$task = @{ TaskName = $config.task; Action = $action; Principal = $principal; Settings = $settings }
if ($config.startup) {
    $task.Trigger = New-ScheduledTaskTrigger -AtLogOn -User $user
}
if ((Get-ScheduledTask -TaskName $config.task -ErrorAction SilentlyContinue).State -eq 'Running') {
    Stop-ScheduledTask -TaskName $config.task
    $deadline = [DateTime]::UtcNow.AddSeconds(10)
    while ((Get-ScheduledTask -TaskName $config.task).State -eq 'Running') {
        if ([DateTime]::UtcNow -ge $deadline) { throw 'The background task did not stop. Wait a moment and try again.' }
        Start-Sleep -Milliseconds 200
    }
}
$credential | Export-Clixml -LiteralPath $config.credential
Register-ScheduledTask @task -Force | Out-Null
Start-ScheduledTask -TaskName $config.task
""", username=username, password=password, startup=startup, exe=str(installed_exe),
        directory=str(INSTALL_DIR), credential=str(CREDENTIAL_FILE))


def run_background():
    try:
        credential = json.loads(powershell("""
$credential = Import-Clixml -LiteralPath $config.credential
@{username=$credential.UserName; password=$credential.GetNetworkCredential().Password} | ConvertTo-Json -Compress
""", credential=str(CREDENTIAL_FILE)))
        autologin.USERNAME = credential["username"]
        autologin.PASSWORD = credential["password"]
        autologin.BASE = str(INSTALL_DIR)
        autologin.LOG_FILE = str(INSTALL_DIR / "autologin.log")
        autologin.main()
    except Exception:
        with (INSTALL_DIR / "autologin.log").open("a", encoding="utf-8") as log:
            log.write(traceback.format_exc())
        return 1
    return 0


def show_window():
    import tkinter as tk
    from tkinter import messagebox, ttk

    window = tk.Tk()
    window.title("FortiGate Wi-Fi Autologin")
    window.resizable(False, False)
    form = ttk.Frame(window, padding=22)
    form.grid(sticky="nsew")
    username = tk.StringVar()
    password = tk.StringVar()
    startup = tk.BooleanVar(value=True)
    status = tk.StringVar(value="Enter your campus credentials to get started.")

    ttk.Label(form, text="NIT Goa Wi-Fi Autologin", font=("Segoe UI", 16)).grid(row=0, columnspan=3, sticky="w")
    ttk.Label(form, text="Campus username").grid(row=1, column=0, sticky="w", pady=(14, 4))
    user_field = ttk.Entry(form, textvariable=username, width=35)
    user_field.grid(row=1, column=1, columnspan=2, sticky="ew", pady=(14, 4))
    ttk.Label(form, text="Campus password").grid(row=2, column=0, sticky="w", pady=4)
    ttk.Entry(form, textvariable=password, show="*", width=35).grid(row=2, column=1, columnspan=2, sticky="ew")
    ttk.Checkbutton(form, text="Start automatically when I sign in to Windows", variable=startup).grid(
        row=3, columnspan=3, sticky="w", pady=10)
    ttk.Label(form, text="Use on campus Wi-Fi. Pause on other networks.",
              wraplength=380).grid(row=4, columnspan=3, sticky="w", pady=(0, 12))

    def save():
        if not username.get().strip() or not password.get():
            messagebox.showwarning("Campus credentials", "Enter your campus username and password.")
            return
        try:
            save_and_start(username.get().strip(), password.get(), startup.get())
        except (OSError, subprocess.SubprocessError, RuntimeError) as error:
            messagebox.showerror("Setup failed", str(error))
            return
        password.set("")
        status.set("Settings saved. Background start requested.")

    def pause():
        try:
            powershell("""
if (Get-ScheduledTask -TaskName $config.task -ErrorAction SilentlyContinue) {
    Disable-ScheduledTask -TaskName $config.task | Out-Null
    Stop-ScheduledTask -TaskName $config.task
}
""")
        except (OSError, subprocess.SubprocessError, RuntimeError) as error:
            messagebox.showerror("Could not pause", str(error))
            return
        status.set("Paused. Use Resume to restore your saved settings.")

    def resume():
        try:
            powershell("""
Enable-ScheduledTask -TaskName $config.task | Out-Null
Start-ScheduledTask -TaskName $config.task
""")
        except (OSError, subprocess.SubprocessError, RuntimeError) as error:
            messagebox.showerror("Could not resume", str(error))
            return
        status.set("Background start requested.")

    def open_logs():
        INSTALL_DIR.mkdir(parents=True, exist_ok=True)
        os.startfile(str(INSTALL_DIR))

    ttk.Button(form, text="Save and Start", command=save).grid(row=5, column=0, sticky="w")
    ttk.Button(form, text="Pause", command=pause).grid(row=5, column=1, sticky="w")
    ttk.Button(form, text="Resume", command=resume).grid(row=5, column=2, sticky="w")
    ttk.Button(form, text="Open Log Folder", command=open_logs).grid(row=6, column=0, sticky="w", pady=(8, 0))
    ttk.Label(form, textvariable=status, wraplength=380).grid(row=7, columnspan=3, sticky="w", pady=(10, 0))
    user_field.focus_set()
    if "--self-test" in sys.argv:
        assert powershell("$null = New-ScheduledTaskTrigger -AtLogOn; 'ready'") == "ready"
        window.update_idletasks()
        window.destroy()
    else:
        window.mainloop()


if __name__ == "__main__":
    if "--background" in sys.argv:
        sys.exit(run_background())
    show_window()
