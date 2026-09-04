param(
    [string]$PeerAddress,
    [string]$InstallDirectory = "$env:ProgramFiles\TheKVM"
)

$taskName = "TheKVM controller"
$binary = Join-Path $InstallDirectory "kvm-daemon.exe"

if (-not (Test-Path -LiteralPath $binary)) {
    throw "kvm-daemon.exe was not found at $binary"
}

$arguments = if ([string]::IsNullOrWhiteSpace($PeerAddress)) {
    "connect"
} else {
    "connect `"$PeerAddress`""
}
$action = New-ScheduledTaskAction `
    -Execute $binary `
    -Argument $arguments
$trigger = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME
$principal = New-ScheduledTaskPrincipal `
    -UserId $env:USERNAME `
    -LogonType Interactive `
    -RunLevel Limited

Register-ScheduledTask `
    -TaskName $taskName `
    -Action $action `
    -Trigger $trigger `
    -Principal $principal `
    -Description "TheKVM interactive controller session ($arguments)" `
    -Force | Out-Host
