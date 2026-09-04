param(
    [string]$InstallDirectory = "$env:ProgramFiles\TheKVM",
    [string]$DataDirectory = "$env:ProgramData\TheKVM",
    [string]$PeerAddress = "",
    [string]$DeviceName = "",
    [ValidateSet("bidirectional", "server-client", "receiver-only")]
    [string]$Mode = "",
    [switch]$EnableLockScreenControl
)

$serviceName = "TheKVM"
$binary = Join-Path $InstallDirectory "kvm-daemon.exe"

if (-not (Test-Path -LiteralPath $binary)) {
    throw "kvm-daemon.exe was not found at $binary"
}

New-Item -ItemType Directory -Path $DataDirectory -Force | Out-Null

$effectiveMode = if (-not [string]::IsNullOrWhiteSpace($Mode)) {
    $Mode
} elseif ([string]::IsNullOrWhiteSpace($PeerAddress)) {
    "receiver-only"
} else {
    "server-client"
}
if ($effectiveMode -eq "receiver-only" -and -not [string]::IsNullOrWhiteSpace($PeerAddress)) {
    throw "-Mode receiver-only cannot be combined with -PeerAddress"
}

# The service runs as LocalSystem and resolves its default state below
# ProgramData. Configure that same directory here; otherwise an elevated
# installer can accidentally write the peer/configuration to the installing
# user's profile and the service will start with a different identity.
$previousDataDirectory = $env:THEKVM_DATA_DIR
$env:THEKVM_DATA_DIR = $DataDirectory

sc.exe stop $serviceName 2>$null | Out-Null
sc.exe delete $serviceName 2>$null | Out-Null

$configureArguments = @("configure", "--mode", $effectiveMode)
if (-not [string]::IsNullOrWhiteSpace($DeviceName)) {
    $configureArguments += @("--device-name", $DeviceName)
}
if ($EnableLockScreenControl) {
    $configureArguments += "--allow-lock-screen-control"
} else {
    $configureArguments += "--disable-lock-screen-control"
}
if (-not [string]::IsNullOrWhiteSpace($PeerAddress)) {
    $configureArguments += @("--auto-connect", $PeerAddress)
} else {
    # A receiver-only reinstall must not inherit a previously configured
    # privileged controller peer.
    $configureArguments += "--clear-auto-connect"
}
& $binary @configureArguments
$configureExitCode = $LASTEXITCODE
if ($configureExitCode -ne 0) {
    if ($null -eq $previousDataDirectory) {
        Remove-Item Env:THEKVM_DATA_DIR -ErrorAction SilentlyContinue
    } else {
        $env:THEKVM_DATA_DIR = $previousDataDirectory
    }
    throw "TheKVM configuration failed with exit code $configureExitCode"
}

if ($null -eq $previousDataDirectory) {
    Remove-Item Env:THEKVM_DATA_DIR -ErrorAction SilentlyContinue
} else {
    $env:THEKVM_DATA_DIR = $previousDataDirectory
}

# The identity key is DPAPI machine-protected because both an elevated CLI and
# LocalSystem may need to use the daemon-owned identity. Keep the directory
# itself readable only by the service and local administrators.
icacls.exe $DataDirectory /inheritance:r /grant:r `
    '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Host
if ($LASTEXITCODE -ne 0) {
    throw "Could not secure TheKVM data directory $DataDirectory"
}

sc.exe create $serviceName binPath= "`"$binary`" serve --service" start= auto obj= LocalSystem | Out-Host
sc.exe description $serviceName "TheKVM privileged receiver service" | Out-Host
sc.exe failure $serviceName reset= 86400 actions= restart/5000/restart/5000/restart/10000 | Out-Host
sc.exe start $serviceName | Out-Host

New-NetFirewallRule -DisplayName "TheKVM QUIC and discovery" -Direction Inbound -Action Allow -Protocol UDP -LocalPort 42110,42111 -Program $binary -Profile Domain,Private | Out-Null
