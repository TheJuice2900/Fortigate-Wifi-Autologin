param([switch]$Run)

$ErrorActionPreference = 'Stop'
$taskName = 'FortiGate Wi-Fi Autologin'
$installDir = Join-Path $env:LOCALAPPDATA 'FortiGateAutologin'
$credentialPath = Join-Path $installDir 'credential.xml'
$installedScript = Join-Path $installDir 'autologin-windows.py'
$python = Join-Path $installDir '.venv\Scripts\python.exe'
$pythonw = Join-Path $installDir '.venv\Scripts\pythonw.exe'

if ($Run) {
    $credential = Import-Clixml -LiteralPath $credentialPath
    $env:AUTOLOGIN_USER = $credential.UserName
    $env:AUTOLOGIN_PASS = $credential.GetNetworkCredential().Password
    try {
        $process = Start-Process -FilePath $pythonw -ArgumentList 'autologin-windows.py' `
            -WorkingDirectory $installDir -WindowStyle Hidden -PassThru -Wait
        exit $process.ExitCode
    } finally {
        Remove-Item Env:AUTOLOGIN_USER, Env:AUTOLOGIN_PASS -ErrorAction SilentlyContinue
    }
}

$sourceScript = Join-Path $PSScriptRoot 'autologin-windows.py'
if (-not (Test-Path -LiteralPath $sourceScript -PathType Leaf)) {
    throw 'Save autologin-windows.py in the same folder as this installer.'
}

New-Item -ItemType Directory -Path $installDir -Force | Out-Null
if (-not (Test-Path -LiteralPath $python)) {
    py -3 -m venv (Join-Path $installDir '.venv')
    if ($LASTEXITCODE -ne 0) { throw 'Could not create the Python virtual environment.' }
}
& $python -m pip install requests
if ($LASTEXITCODE -ne 0) { throw 'Could not install requests.' }
if (-not (Test-Path -LiteralPath $pythonw -PathType Leaf)) {
    throw 'This Python installation does not provide pythonw.exe.'
}

$username = Read-Host 'Campus username'
$password = Read-Host 'Campus password' -AsSecureString
if ([string]::IsNullOrWhiteSpace($username) -or $password.Length -eq 0) {
    throw 'Enter both campus credentials.'
}
$credential = [pscredential]::new($username, $password)

$existingTask = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
if ($existingTask -and $existingTask.State -eq 'Running') {
    Stop-ScheduledTask -InputObject $existingTask
}
Copy-Item -LiteralPath $sourceScript -Destination $installedScript -Force
$runner = Join-Path $installDir 'install-autologin-windows.ps1'
# Write a local copy so the task remains independent of the Downloads folder.
[IO.File]::WriteAllText($runner, [IO.File]::ReadAllText($PSCommandPath))
$credential | Export-Clixml -LiteralPath $credentialPath

$user = [Security.Principal.WindowsIdentity]::GetCurrent().Name
$powerShell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$arguments = "-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy RemoteSigned -File `"$runner`" -Run"
$action = New-ScheduledTaskAction -Execute $powerShell -Argument $arguments -WorkingDirectory $installDir
$trigger = New-ScheduledTaskTrigger -AtLogOn -User $user
$principal = New-ScheduledTaskPrincipal -UserId $user -LogonType Interactive -RunLevel Limited
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
    -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew
Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger `
    -Principal $principal -Settings $settings -Force | Out-Null
Start-ScheduledTask -TaskName $taskName
Write-Host "Autologin starts at Windows sign-in. Log file is in $installDir\autologin.log"
