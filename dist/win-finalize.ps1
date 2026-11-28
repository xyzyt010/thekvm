# Elevated: deploy the release build, enable the pre-login (boot/login
# screen) opt-in on the service config, relaunch the UI.
$ErrorActionPreference = 'Continue'
& (Join-Path $PSScriptRoot 'deploy-windows-v4.ps1')
& 'C:\Program Files\TheKVM\kvm-daemon.exe' configure --allow-prelogin-auto-connect 2>&1 |
    Add-Content (Join-Path $PSScriptRoot 'deploy-windows-v4.log')
