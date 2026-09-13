<#
.SYNOPSIS
  Update TheKVM on the Linux Mint machine over SSH by building from GitHub source.

.DESCRIPTION
  GitHub repo (download + source of truth):
    https://github.com/xyzyt010/thekvm

  What this script does, from this Windows machine:
    1. Picks a working SSH key (auto-converts a CRLF key to LF and locks
       down ACLs in a temp copy, as required by OpenSSH).
    2. Finds the Mint host among -MintHosts (Mint gets a new DHCP lease
       often, so several candidates are tried).
    3. On Mint: git clone/pull the repo, ensure Rust, install build deps,
       cargo build --release, install via packaging/linux/install.sh
       (preserves /var/lib/thekvm peers/config), restart thekvmd, verify.
    4. With -AutoUpdate: installs a daily systemd timer on Mint that pulls,
       rebuilds and restarts only when the GitHub HEAD moved.

  Sudo on Mint: hs01 needs a password (no NOPASSWD by default). The script
  detects that and runs the privileged steps with an interactive TTY so you
  type the Mint password once (sudo timestamp caching covers the rest).
  For fully unattended runs, add this sudoers line on Mint (via visudo):
    hs01 ALL=(ALL) NOPASSWD: /usr/bin/apt-get, /bin/systemctl, /usr/bin/systemctl, /bin/sh

.EXAMPLE
  powershell -File tools/mint-ssh-update.ps1
.EXAMPLE
  powershell -File tools/mint-ssh-update.ps1 -MintHosts 192.168.1.7 -AutoUpdate
#>
[CmdletBinding()]
param(
  [string[]]$MintHosts = @("192.168.1.7", "192.168.1.4"),
  [string]$MintUser = "hs01",
  [string]$KeyPath = (Join-Path $HOME ".ssh\hs01_windows_key"),
  [string]$RepoUrl = "https://github.com/xyzyt010/thekvm.git",
  [string]$Branch = "main",
  [string]$CheckoutDir = "~/thekvm",
  [string]$DesktopUser = "hs01",
  [switch]$AutoUpdate,
  [switch]$SkipBuildDeps
)

$ErrorActionPreference = "Stop"
$Ssh = "C:\Windows\System32\OpenSSH\ssh.exe"

function Write-Step([string]$Message) {
  Write-Host ""
  Write-Host "=== $Message ===" -ForegroundColor Cyan
}

function Invoke-MintSsh {
  param(
    [string]$Target,
    [string]$Key,
    [string]$RemoteCommand,
    [switch]$NeedTty
  )
  $args = @("-4", "-o", "ConnectTimeout=8", "-o", "BatchMode=yes",
            "-o", "StrictHostKeyChecking=no", "-i", $Key)
  if ($NeedTty) { $args += "-t" }
  $args += @("$MintUser@$Target", $RemoteCommand)
  & $Ssh @args
}

function Get-UsableKey([string]$Path) {
  if (-not (Test-Path -LiteralPath $Path)) {
    throw "SSH key not found: $Path (pass -KeyPath, e.g. C:\Users\<you>\Downloads\windowsss.key)"
  }
  $bytes = [IO.File]::ReadAllBytes($Path)
  $text = [Text.Encoding]::ASCII.GetString($bytes) -replace "`r`n", "`n"
  $tempKey = Join-Path ([IO.Path]::GetTempPath()) "thekvm-mint.key"
  [IO.File]::WriteAllText($tempKey, $text, [Text.Encoding]::ASCII)
  # Owner-only ACL (others: none), like a working $HOME\.ssh key: OpenSSH
  # requires this, and Full control (not Read-only) so cleanup can delete it.
  & icacls $tempKey /inheritance:r | Out-Null
  & icacls $tempKey /grant:r "$($env:USERNAME):(F)" | Out-Null
  return $tempKey
}

function Find-MintHost([string[]]$Hosts, [string]$Key) {
  foreach ($h in $Hosts) {
    Write-Host "Probing $h ..."
    $tcp = New-Object Net.Sockets.TcpClient
    try {
      $iar = $tcp.BeginConnect($h, 22, $null, $null)
      if (-not $iar.AsyncWaitHandle.WaitOne(1500)) { continue }
      $tcp.EndConnect($iar)
    } catch { continue } finally { $tcp.Close() }
    try {
      $out = Invoke-MintSsh -Target $h -Key $Key -RemoteCommand 'echo SSH_OK; hostname'
      if ($out -contains "SSH_OK") { return $h }
    } catch { continue }
  }
  throw "No Mint host answered on 22/tcp with this key (tried: $($Hosts -join ', ')). Pass -MintHosts with the current Mint IP (see the Mint Status tab)."
}

Write-Step "SSH key"
$key = Get-UsableKey $KeyPath
Write-Host "Using key: $key"

Write-Step "Finding the Mint machine"
$mint = Find-MintHost $MintHosts $key
Write-Host "Mint is at $mint" -ForegroundColor Green

Write-Step "Mint versions before update"
Invoke-MintSsh -Target $mint -Key $key -RemoteCommand 'echo "thekvm checkout: $(git -C ~/thekvm rev-parse --short HEAD 2>/dev/null || echo none)"; /usr/bin/kvm-daemon status 2>/dev/null | head -12'

Write-Step "Clone/pull https://github.com/xyzyt010/thekvm ($Branch)"
$pullScript = @'
set -eu
if [ -d ~/thekvm/.git ]; then
  git -C ~/thekvm fetch --prune origin
  git -C ~/thekvm checkout __BRANCH__
  git -C ~/thekvm pull --ff-only origin __BRANCH__
else
  git clone --branch __BRANCH__ __REPO__ ~/thekvm
fi
git -C ~/thekvm rev-parse HEAD
'@ -replace '__BRANCH__', $Branch -replace '__REPO__', $RepoUrl
Invoke-MintSsh -Target $mint -Key $key -RemoteCommand $pullScript

Write-Step "Rust toolchain on Mint"
Invoke-MintSsh -Target $mint -Key $key -RemoteCommand 'export PATH="$HOME/.cargo/bin:$PATH"; if command -v cargo >/dev/null; then rustc --version; else curl --proto "=https" --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain stable; fi'

$needsSudo = $true
try {
  Invoke-MintSsh -Target $mint -Key $key -RemoteCommand 'sudo -n true' | Out-Null
  $needsSudo = ($LASTEXITCODE -ne 0)
} catch { $needsSudo = $true }
if ($needsSudo) {
  Write-Host "Mint sudo needs your password: it will prompt once (TTY), the timestamp covers the rest." -ForegroundColor Yellow
}

if (-not $SkipBuildDeps) {
  Write-Step "Build dependencies (apt)"
  $aptScript = 'sudo -n apt-get update 2>/dev/null || sudo apt-get update; sudo apt-get install --yes libdbus-1-dev libinput-dev libwayland-dev libx11-xcb-dev libxi-dev libxkbcommon-dev libxtst-dev pkg-config build-essential'
  if ($needsSudo) { Invoke-MintSsh -Target $mint -Key $key -NeedTty -RemoteCommand $aptScript }
  else { Invoke-MintSsh -Target $mint -Key $key -RemoteCommand ($aptScript -replace 'sudo ', 'sudo -n ') }
}

Write-Step "cargo build --release (takes several minutes on first run)"
Invoke-MintSsh -Target $mint -Key $key -RemoteCommand 'export PATH="$HOME/.cargo/bin:$PATH"; cd ~/thekvm && cargo build --release -p kvm-daemon -p kvm-ui 2>&1 | tail -5'

Write-Step "Install + restart thekvmd (preserves peers/config)"
$installScript = 'cd ~/thekvm && sudo -n sh packaging/linux/install.sh --desktop-user __DESKTOP__ --no-dependencies 2>/dev/null || sudo sh packaging/linux/install.sh --desktop-user __DESKTOP__ --no-dependencies; sudo systemctl restart thekvmd' -replace '__DESKTOP__', $DesktopUser
if ($needsSudo) { Invoke-MintSsh -Target $mint -Key $key -NeedTty -RemoteCommand $installScript }
else { Invoke-MintSsh -Target $mint -Key $key -RemoteCommand ($installScript -replace 'sudo ', 'sudo -n ') }

if ($AutoUpdate) {
  Write-Step "Installing daily auto-update timer on Mint"
  # Everything installs from the Mint checkout (no quoting-sensitive
  # heredocs over SSH): the watcher from tools/, the units from
  # packaging/linux/ (see those files for what runs daily at ~04:00).
  $watcher = 'sudo -n install -m 0755 ~/thekvm/tools/thekvm-auto-update.sh /usr/local/bin/thekvm-auto-update 2>/dev/null || sudo install -m 0755 ~/thekvm/tools/thekvm-auto-update.sh /usr/local/bin/thekvm-auto-update; sudo install -m 0644 ~/thekvm/packaging/linux/thekvm-update.service ~/thekvm/packaging/linux/thekvm-update.timer /etc/systemd/system/; sudo systemctl daemon-reload; sudo systemctl enable --now thekvm-update.timer; git -C ~/thekvm rev-parse HEAD | sudo tee /var/lib/thekvm-built-commit >/dev/null; systemctl list-timers thekvm-update.timer --no-pager'
  if ($needsSudo) { Invoke-MintSsh -Target $mint -Key $key -NeedTty -RemoteCommand $watcher }
  else { Invoke-MintSsh -Target $mint -Key $key -RemoteCommand ($watcher -replace 'sudo ', 'sudo -n ') }
}

Write-Step "Verify"
Invoke-MintSsh -Target $mint -Key $key -RemoteCommand 'systemctl is-active thekvmd; /usr/bin/kvm-daemon status 2>/dev/null | head -14; git -C ~/thekvm rev-parse --short HEAD'

Remove-Item -LiteralPath $key -Force -ErrorAction SilentlyContinue
Write-Host ""
Write-Host "Done. Mint at $mint tracks $RepoUrl ($Branch)." -ForegroundColor Green
