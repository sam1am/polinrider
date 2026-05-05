<#
.SYNOPSIS
  Block C2 / IOC domains and IPs on Windows.

.DESCRIPTION
  Reads iocs.txt and adds:
    - 0.0.0.0 entries to %SystemRoot%\System32\drivers\etc\hosts
    - Block-Out rules to Windows Defender Firewall for IPv4/IPv6 addresses
  Backs up the hosts file before modifying.
  Re-running is safe (idempotent): existing entries are removed and rewritten.

.PARAMETER Unblock
  Remove all entries this script previously added.

.PARAMETER DryRun
  Print what would happen without making any changes.

.PARAMETER HostsOnly
  Only modify the hosts file; skip Windows Firewall rules.

.PARAMETER IocFile
  Path to the IOC list. Defaults to .\iocs.txt next to the script.

.EXAMPLE
  # Run from an elevated PowerShell session:
  PS> Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
  PS> .\block-iocs.ps1

.EXAMPLE
  PS> .\block-iocs.ps1 -Unblock

.EXAMPLE
  PS> .\block-iocs.ps1 -DryRun

.NOTES
  Requires: Windows 10/11 or Windows Server, PowerShell 5.1+, Administrator.
#>

[CmdletBinding()]
param(
  [switch]$Unblock,
  [switch]$DryRun,
  [switch]$HostsOnly,
  [string]$IocFile
)

$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Paths and constants
# ---------------------------------------------------------------------------
$ScriptDir   = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $IocFile) { $IocFile = Join-Path $ScriptDir 'iocs.txt' }

$HostsFile   = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
$MarkerBegin = '# === BEGIN polinrider IOC block ==='
$MarkerEnd   = '# === END polinrider IOC block ==='
$RuleNamePrefix = 'polinrider-block'
$RuleGroup   = 'polinrider'

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
function Write-Log  { param($m) Write-Host "[*] $m" -ForegroundColor Cyan }
function Write-Ok   { param($m) Write-Host "[+] $m" -ForegroundColor Green }
function Write-Warn2{ param($m) Write-Host "[!] $m" -ForegroundColor Yellow }
function Write-Err  { param($m) Write-Host "[X] $m" -ForegroundColor Red }
function Write-Dry  { param($m) Write-Host "[dry] $m" -ForegroundColor Magenta }

function Test-Admin {
  $current = [Security.Principal.WindowsIdentity]::GetCurrent()
  $principal = New-Object Security.Principal.WindowsPrincipal($current)
  return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-IPv4 {
  param($s)
  return ($s -match '^(\d{1,3}\.){3}\d{1,3}$')
}
function Test-IPv6 {
  param($s)
  return ($s -match ':' -and $s -match '^[0-9A-Fa-f:]+$')
}
function Test-IP {
  param($s)
  return ((Test-IPv4 $s) -or (Test-IPv6 $s))
}

function Invoke-Or-Dry {
  param([scriptblock]$Action, [string]$Description)
  if ($DryRun) {
    Write-Dry $Description
  } else {
    & $Action
  }
}

# ---------------------------------------------------------------------------
# Pre-flight
# ---------------------------------------------------------------------------
if (-not (Test-Path $IocFile)) {
  Write-Err "IOC file not found: $IocFile"
  exit 1
}
if (-not (Test-Admin) -and -not $DryRun) {
  Write-Err 'This script must be run from an elevated (Administrator) PowerShell session.'
  exit 1
}

# ---------------------------------------------------------------------------
# Parse IOCs
# ---------------------------------------------------------------------------
$Domains = New-Object System.Collections.Generic.List[string]
$IPs     = New-Object System.Collections.Generic.List[string]

Get-Content $IocFile | ForEach-Object {
  # Strip inline comments and whitespace
  $line = ($_ -split '#', 2)[0].Trim()
  if ([string]::IsNullOrEmpty($line)) { return }
  if (Test-IP $line) { [void]$IPs.Add($line) }
  else { [void]$Domains.Add($line) }
}

Write-Log "Loaded $($Domains.Count) domains and $($IPs.Count) IPs from $IocFile"

# ---------------------------------------------------------------------------
# /etc/hosts editing
# ---------------------------------------------------------------------------
function Backup-Hosts {
  $ts = Get-Date -Format 'yyyyMMdd-HHmmss'
  $bak = "$HostsFile.bak.$ts"
  Invoke-Or-Dry { Copy-Item -Path $HostsFile -Destination $bak -Force } "Backup hosts -> $bak"
  Write-Ok "Backed up hosts file to $bak"
}

function Remove-HostsBlock {
  if (-not (Test-Path $HostsFile)) { return }
  $content = Get-Content $HostsFile -Raw -ErrorAction SilentlyContinue
  if ($null -eq $content) { return }
  if ($content -notmatch [regex]::Escape($MarkerBegin)) { return }

  $pattern = "(?s)\r?\n?$([regex]::Escape($MarkerBegin)).*?$([regex]::Escape($MarkerEnd))\r?\n?"
  $new = [regex]::Replace($content, $pattern, '')
  Invoke-Or-Dry { Set-Content -Path $HostsFile -Value $new -NoNewline -Encoding ascii } "Strip existing IOC block from hosts"
  Write-Ok "Removed existing IOC block from hosts"
}

function Write-HostsBlock {
  if ($Domains.Count -eq 0) {
    Write-Log "No domains to block in hosts file"
    return
  }
  $lines = @()
  $lines += ''
  $lines += $MarkerBegin
  $lines += "# Generated by block-iocs.ps1 on $(Get-Date -Format 'u')"
  $lines += "# Source: $IocFile"
  foreach ($d in $Domains) {
    $lines += "0.0.0.0 $d"
    $lines += ":: $d"
  }
  $lines += $MarkerEnd
  $payload = ($lines -join "`r`n")

  if ($DryRun) {
    Write-Dry "would append to ${HostsFile}:"
    Write-Host $payload
  } else {
    Add-Content -Path $HostsFile -Value $payload -Encoding ascii
    Write-Ok "Wrote $($Domains.Count) domains to $HostsFile"
  }
}

# ---------------------------------------------------------------------------
# Windows Defender Firewall
# ---------------------------------------------------------------------------
function Block-IPsFirewall {
  if ($IPs.Count -eq 0) {
    Write-Log "No IPs to block via firewall"
    return
  }

  # Remove pre-existing rules from this group so we don't duplicate
  $existing = Get-NetFirewallRule -Group $RuleGroup -ErrorAction SilentlyContinue
  if ($existing) {
    foreach ($r in $existing) {
      Invoke-Or-Dry { Remove-NetFirewallRule -InputObject $r -ErrorAction SilentlyContinue } "Remove old rule $($r.Name)"
    }
  }

  $i = 0
  foreach ($ip in $IPs) {
    $i++
    $name = "$RuleNamePrefix-$('{0:D3}' -f $i)"
    Invoke-Or-Dry {
      New-NetFirewallRule `
        -DisplayName $name `
        -Group $RuleGroup `
        -Direction Outbound `
        -Action Block `
        -RemoteAddress $ip `
        -Profile Any `
        -Description "polinrider IOC block: $ip" | Out-Null
    } "New-NetFirewallRule outbound block $ip"
  }
  Write-Ok "Created $($IPs.Count) Windows Firewall outbound block rules"
}

function Unblock-IPsFirewall {
  $existing = Get-NetFirewallRule -Group $RuleGroup -ErrorAction SilentlyContinue
  if ($null -eq $existing -or $existing.Count -eq 0) {
    Write-Log "No polinrider firewall rules to remove"
    return
  }
  foreach ($r in $existing) {
    Invoke-Or-Dry { Remove-NetFirewallRule -InputObject $r -ErrorAction SilentlyContinue } "Remove rule $($r.Name)"
  }
  Write-Ok "Removed $(@($existing).Count) Windows Firewall rules"
}

# ---------------------------------------------------------------------------
# DNS cache flush
# ---------------------------------------------------------------------------
function Flush-Dns {
  Invoke-Or-Dry { ipconfig /flushdns | Out-Null } "ipconfig /flushdns"
  Write-Ok "DNS cache flushed"
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
$Action = if ($Unblock) { 'unblock' } else { 'block' }
Write-Log "Action: $Action  (DryRun: $DryRun, HostsOnly: $HostsOnly)"

if ($Action -eq 'block') {
  Backup-Hosts
  Remove-HostsBlock
  Write-HostsBlock
  if (-not $HostsOnly) { Block-IPsFirewall }
  Flush-Dns
  $sample = if ($Domains.Count -gt 0) { $Domains[0] } else { 'api.trongrid.io' }
  Write-Ok "Block complete. Verify with:  Resolve-DnsName $sample  (should return 0.0.0.0 / no answer)"
}
elseif ($Action -eq 'unblock') {
  Remove-HostsBlock
  if (-not $HostsOnly) { Unblock-IPsFirewall }
  Flush-Dns
  Write-Ok "Unblock complete."
}
