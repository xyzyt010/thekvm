# Deploy the current Windows release build to C:\Program Files\TheKVM.
# Must run elevated (service stop/start + Program Files writes).
# Stop service -> kill UI/user daemons -> backup -> hash-verified install
# -> start service -> relaunch UI. Logs to dist\deploy-windows-v4.log.
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$log = Join-Path $PSScriptRoot 'deploy-windows-v4.log'
function Write-Log($msg) {
    $line = "$(Get-Date -Format HH:mm:ss) $msg"
    Write-Host $line
    Add-Content -Path $log -Value $line
}
Set-Content -Path $log -Value "=== deploy $(Get-Date -Format o)"

$installDir = 'C:\Program Files\TheKVM'
$backupDir = Join-Path $PSScriptRoot 'deploy-backup-v4'
New-Item -ItemType Directory -Force $backupDir | Out-Null

Write-Log 'stopping service TheKVM'
Stop-Service -Name TheKVM -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2
Get-Process kvm-ui, kvm-daemon -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2
Write-Log "kvm processes after wait: $((Get-Process kvm-ui,kvm-daemon -ErrorAction SilentlyContinue | Measure-Object).Count)"

foreach ($name in 'kvm-daemon.exe', 'kvm-ui.exe') {
    $src = Join-Path $root "target\release\$name"
    $dst = Join-Path $installDir $name
    if (Test-Path $dst) {
        Copy-Item -Force $dst (Join-Path $backupDir "$name.bak")
        Write-Log "backed up $name"
    }
    Copy-Item -Force $src $dst
    Write-Log "installed $name"
}

Start-Service -Name TheKVM
Start-Sleep -Seconds 2
Write-Log "service after restart: $((Get-Service TheKVM).Status)"

foreach ($name in 'kvm-daemon.exe', 'kvm-ui.exe') {
    $srcHash = (Get-FileHash (Join-Path $root "target\release\$name")).Hash
    $dstHash = (Get-FileHash (Join-Path $installDir $name)).Hash
    Write-Log "$name hash match: $($srcHash -eq $dstHash)"
    if ($srcHash -ne $dstHash) { throw "hash mismatch for $name" }
}

Write-Log 'relaunching kvm-ui'
$ui = Start-Process (Join-Path $installDir 'kvm-ui.exe') -PassThru
Start-Sleep -Seconds 3
Write-Log "kvm-ui pid $($ui.Id) alive: $(-not $ui.HasExited)"
Write-Log '=== deploy complete'
