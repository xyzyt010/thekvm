# TheKVM complete purge for Windows.
#
# Removes EVERYTHING from a confused machine so one clean install can follow:
# the service, firewall rule, both install folders, daemon state, registry
# entries, and shortcuts. Run ONCE from an elevated PowerShell, then install
# the current thekvm-*-setup.exe to the DEFAULT folder without changing it.
#
# Elevated one-liner (right-click PowerShell -> Run as Administrator):
#   irm https://raw.githubusercontent.com/xyzyt010/thekvm/main/packaging/windows/purge-thekvm.ps1 | iex
#
# Pairing must be redone afterwards: identities and trusted peers are deleted.

$principal = New-Object Security.Principal.WindowsPrincipal(
    [Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Right-click PowerShell and choose 'Run as Administrator', then run this again."
}

$failures = @()
function Step([string]$Name, [scriptblock]$Action) {
    try {
        & $Action
        Write-Host "[ok] $Name"
    } catch {
        $failures += $Name
        Write-Host "[FAILED] $Name : $($_.Exception.Message)"
    }
}

Step "stop service" { sc.exe stop TheKVM 2>$null | Out-Null }
Step "delete service" { sc.exe delete TheKVM 2>$null | Out-Null }
Step "kill leftover processes" {
    Get-Process kvm-daemon, kvm-ui -ErrorAction SilentlyContinue |
        Stop-Process -Force -ErrorAction SilentlyContinue
}
Step "remove firewall rule" {
    netsh advfirewall firewall delete rule name="TheKVM QUIC and discovery" | Out-Null
}
Step "remove install folders" {
    Remove-Item -Recurse -Force "$env:ProgramFiles\TheKVM" -ErrorAction SilentlyContinue
    Remove-Item -Recurse -Force "${env:ProgramFiles(x86)}\TheKVM" -ErrorAction SilentlyContinue
    if ((Test-Path "$env:ProgramFiles\TheKVM") -or (Test-Path "${env:ProgramFiles(x86)}\TheKVM")) {
        throw "a folder is locked; reboot and run this script again"
    }
}
Step "remove daemon state (identities and peers)" {
    Remove-Item -Recurse -Force "$env:ProgramData\TheKVM" -ErrorAction SilentlyContinue
    if (Test-Path "$env:ProgramData\TheKVM") {
        throw "state folder is locked; reboot and run this script again"
    }
}
Step "remove user state" {
    Remove-Item -Recurse -Force "$env:APPDATA\TheKVM" -ErrorAction SilentlyContinue
    Remove-Item -Recurse -Force "$env:LOCALAPPDATA\TheKVM" -ErrorAction SilentlyContinue
}
Step "remove Add/Remove Programs entries" {
    Remove-Item -Recurse -Force "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\TheKVM" -ErrorAction SilentlyContinue
}
Step "remove shortcuts" {
    Remove-Item -Force "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\TheKVM*" -ErrorAction SilentlyContinue
    Remove-Item -Force "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\TheKVM*" -ErrorAction SilentlyContinue
}

Write-Host ""
if ($failures.Count -eq 0) {
    Write-Host "Purge complete. Now run the current thekvm-*-setup.exe and accept the DEFAULT folder."
} else {
    Write-Host "Purge finished with failures: $($failures -join ', ')"
}
