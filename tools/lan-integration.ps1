param(
    [string]$Binary = ""
)

$ErrorActionPreference = "Stop"

if ([string]::IsNullOrWhiteSpace($Binary)) {
    $Binary = Join-Path $PSScriptRoot "..\target\release\kvm-daemon.exe"
    if (-not (Test-Path -LiteralPath $Binary)) {
        $Binary = Join-Path $PSScriptRoot "..\target\debug\kvm-daemon.exe"
    }
}
$Binary = (Resolve-Path -LiteralPath $Binary).Path

$root = Join-Path ([System.IO.Path]::GetTempPath()) "thekvm-lan-integration-$PID"
$dataA = Join-Path $root "node-a"
$dataB = Join-Path $root "node-b"
$pipeA = "\\.\pipe\thekvm-integration-a-$PID"
$pipeB = "\\.\pipe\thekvm-integration-b-$PID"
$processes = [System.Collections.Generic.List[System.Diagnostics.Process]]::new()
$previousDataDir = $env:THEKVM_DATA_DIR
$previousControlPipe = $env:THEKVM_CONTROL_PIPE
$previousAutoConfirm = $env:THEKVM_AUTO_CONFIRM

function Invoke-TheKvm {
    param(
        [string]$DataDirectory,
        [string]$ControlPipe,
        [string[]]$Arguments
    )
    $env:THEKVM_DATA_DIR = $DataDirectory
    $env:THEKVM_CONTROL_PIPE = $ControlPipe
    & $Binary @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "TheKVM command failed ($LASTEXITCODE): $($Arguments -join ' ')"
    }
}

function Invoke-TheKvmExpectedFailure {
    param(
        [string]$DataDirectory,
        [string]$ControlPipe,
        [string[]]$Arguments
    )
    $env:THEKVM_DATA_DIR = $DataDirectory
    $env:THEKVM_CONTROL_PIPE = $ControlPipe
    $previousErrorAction = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        $output = & $Binary @Arguments 2>&1
        $exitCode = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $previousErrorAction
    }
    if ($exitCode -eq 0) {
        throw "TheKVM command unexpectedly succeeded: $($Arguments -join ' ')"
    }
    return ($output -join [Environment]::NewLine)
}

function Start-TheKvmDaemon {
    param(
        [string]$DataDirectory,
        [string]$ControlPipe
    )
    $env:THEKVM_DATA_DIR = $DataDirectory
    $env:THEKVM_CONTROL_PIPE = $ControlPipe
    $savedAutoConfirm = $env:THEKVM_AUTO_CONFIRM
    Remove-Item Env:THEKVM_AUTO_CONFIRM -ErrorAction SilentlyContinue
    $process = Start-Process `
        -FilePath $Binary `
        -ArgumentList @("serve") `
        -WindowStyle Hidden `
        -PassThru
    if ($null -eq $savedAutoConfirm) {
        Remove-Item Env:THEKVM_AUTO_CONFIRM -ErrorAction SilentlyContinue
    } else {
        $env:THEKVM_AUTO_CONFIRM = $savedAutoConfirm
    }
    $processes.Add($process)
    return $process
}

function Start-TheKvmPair {
    param([string]$DataDirectory, [string]$ControlPipe, [string]$Address, [string]$LogName)
    $env:THEKVM_DATA_DIR = $DataDirectory
    $env:THEKVM_CONTROL_PIPE = $ControlPipe
    $savedAutoConfirm = $env:THEKVM_AUTO_CONFIRM
    $env:THEKVM_AUTO_CONFIRM = "1"
    $stdout = Join-Path $root "$LogName.out"
    $stderr = Join-Path $root "$LogName.err"
    try {
        $process = Start-Process -FilePath $Binary -ArgumentList @("pair", $Address) -RedirectStandardOutput $stdout -RedirectStandardError $stderr -WindowStyle Hidden -PassThru
    } finally {
        if ($null -eq $savedAutoConfirm) {
            Remove-Item Env:THEKVM_AUTO_CONFIRM -ErrorAction SilentlyContinue
        } else {
            $env:THEKVM_AUTO_CONFIRM = $savedAutoConfirm
        }
    }
    $processes.Add($process)
    return $process
}

function Wait-TheKvmPairing {
    param([string]$DataDirectory, [string]$ControlPipe, [string]$Label)
    for ($attempt = 0; $attempt -lt 60; $attempt++) {
        $fingerprint = $null
        $code = $null
        try {
            $raw = @(Invoke-TheKvm $DataDirectory $ControlPipe @("pending-pairings")) -join "`n"
            if (-not [string]::IsNullOrWhiteSpace($raw)) {
                $pending = @($raw | ConvertFrom-Json)
                if ($pending.Count -gt 0 -and $null -ne $pending[0]) {
                    $fingerprint = [string]$pending[0].fingerprint_hex
                    $code = [string]$pending[0].verification_code
                }
            }
        } catch {
            # The daemon may still be starting or the request may not exist yet.
        }
        if (-not [string]::IsNullOrWhiteSpace($fingerprint)) {
            if ($code -notmatch '^[0-9]{6}$') {
                throw "pending pairing on $Label carries no valid six-digit verification code: '$code'"
            }
            return $fingerprint
        }
        Start-Sleep -Milliseconds 100
    }
    throw "Timed out waiting for pending pairing on $Label"
}

function Assert-TheKvmPairSucceeded {
    param([System.Diagnostics.Process]$Process, [string]$LogName)

    $Process.Refresh()
    if (-not $Process.HasExited) {
        throw "$LogName pairing process did not exit after approval"
    }
    $stdout = [System.IO.File]::ReadAllText((Join-Path $root "$LogName.out"))
    if ($stdout -notmatch "(?m)^paired: [0-9a-f]{64}\s*$") {
        $stderr = [System.IO.File]::ReadAllText((Join-Path $root "$LogName.err"))
        throw "$LogName pairing failed: $stderr$stdout"
    }
}

try {
    New-Item -ItemType Directory -Path $dataA,$dataB -Force | Out-Null
    Invoke-TheKvm $dataA $pipeA @("configure", "--listen-port", "42120", "--device-name", "Integration A", "--mode", "server-client", "--allow-lock-screen-control")
    Invoke-TheKvm $dataB $pipeB @("configure", "--listen-port", "42122", "--device-name", "Integration B", "--mode", "receiver-only", "--allow-lock-screen-control")

    $null = Start-TheKvmDaemon $dataA $pipeA
    $null = Start-TheKvmDaemon $dataB $pipeB
    Start-Sleep -Milliseconds 750

    $pairA = Start-TheKvmPair $dataA $pipeA "127.0.0.1:42122" "pair-a"
    $pendingB = Wait-TheKvmPairing $dataB $pipeB "node-b"
    Invoke-TheKvm $dataB $pipeB @("approve-pairing", $pendingB)
    $pairA.WaitForExit()
    Assert-TheKvmPairSucceeded $pairA "pair-a"

    $pairB = Start-TheKvmPair $dataB $pipeB "127.0.0.1:42120" "pair-b"
    $pendingA = Wait-TheKvmPairing $dataA $pipeA "node-a"
    Invoke-TheKvm $dataA $pipeA @("approve-pairing", $pendingA)
    $pairB.WaitForExit()
    Assert-TheKvmPairSucceeded $pairB "pair-b"

    $statusA = (Invoke-TheKvm $dataA $pipeA @("status") | ConvertFrom-Json)
    $statusB = (Invoke-TheKvm $dataB $pipeB @("status") | ConvertFrom-Json)
    if ($statusA.node_name -ne "Integration A" -or $statusB.node_name -ne "Integration B") {
        throw "configured device names did not survive daemon startup"
    }
    if ($statusA.peer_count -ne 1 -or $statusB.peer_count -ne 1) {
        throw "reciprocal pairing did not produce one trusted peer on each daemon"
    }
    if ($statusA.mode -ne "ServerClient" -or $statusB.mode -ne "ClientOnly") {
        throw "strict one-way roles were not preserved by daemon startup"
    }

    $receiverFailure = Invoke-TheKvmExpectedFailure $dataB $pipeB @("send", "127.0.0.1:42120")
    if ($receiverFailure -notmatch "receiver-only mode cannot initiate an input session") {
        throw "receiver-only mode did not reject an outbound input session"
    }

    $fingerprintA = (Invoke-TheKvm $dataA $pipeA @("fingerprint") | Select-Object -Last 1).Trim()
    Invoke-TheKvm $dataB $pipeB @("unpair", $fingerprintA.ToUpperInvariant())
    $statusB = (Invoke-TheKvm $dataB $pipeB @("status") | ConvertFrom-Json)
    if ($statusB.peer_count -ne 0) {
        throw "uppercase fingerprint revocation was not applied immediately"
    }

    Write-Host "LAN integration passed: two-sided approval, QUIC pairing, strict controller/receiver roles, configured names, status, and live revocation."
}
finally {
    foreach ($process in $processes) {
        if (-not $process.HasExited) {
            Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
        }
    }
    if ($null -eq $previousDataDir) {
        Remove-Item Env:THEKVM_DATA_DIR -ErrorAction SilentlyContinue
    } else {
        $env:THEKVM_DATA_DIR = $previousDataDir
    }
    if ($null -eq $previousControlPipe) {
        Remove-Item Env:THEKVM_CONTROL_PIPE -ErrorAction SilentlyContinue
    } else {
        $env:THEKVM_CONTROL_PIPE = $previousControlPipe
    }
    if ($null -eq $previousAutoConfirm) {
        Remove-Item Env:THEKVM_AUTO_CONFIRM -ErrorAction SilentlyContinue
    } else {
        $env:THEKVM_AUTO_CONFIRM = $previousAutoConfirm
    }
    if (Test-Path -LiteralPath $root) {
        $resolvedRoot = (Resolve-Path -LiteralPath $root).Path
        $tempRoot = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath())
        if ($resolvedRoot.StartsWith($tempRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
            Remove-Item -LiteralPath $resolvedRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}
