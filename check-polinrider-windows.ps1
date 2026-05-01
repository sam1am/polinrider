# PolinRider / Beavertail / TasksJacker comprehensive scanner — Windows (PowerShell 5.1+)
# IOCs from https://github.com/OpenSourceMalware/PolinRider
#
# Usage:
#   PS> Set-ExecutionPolicy -Scope Process Bypass
#   PS> .\check-polinrider-windows.ps1                     # quick (default repo paths)
#   PS> .\check-polinrider-windows.ps1 -RepoRoot C:\dev    # scan repos under a path
#   PS> .\check-polinrider-windows.ps1 -Full               # adds Event Log + system-wide checks
#   (run elevated as Administrator for Part C)

[CmdletBinding()]
param(
    [string[]] $RepoRoot = @("$HOME\Documents\GitHub", "$HOME\source\repos", "$HOME\code", "$HOME\dev", "$HOME\projects"),
    [switch]   $Full
)

$ErrorActionPreference = 'SilentlyContinue'
$script:Hits = 0
$script:Warns = 0

function Section($t)  { Write-Host "`n=== $t ===" -ForegroundColor Cyan }
function Sub($t)      { Write-Host "`n-- $t --" -ForegroundColor DarkGray }
function Hit($t)      { Write-Host "  [HIT] $t" -ForegroundColor Red;    $script:Hits++ }
function Warn($t)     { Write-Host "  [REV] $t" -ForegroundColor Yellow; $script:Warns++ }
function Ok($t)       { Write-Host "  [ok ] $t" -ForegroundColor Green }
function Note($t)     { Write-Host "  $t" -ForegroundColor DarkGray }

# ═════════════════ IOC CONSTANTS ═════════════════
$V1_Marker  = "rmcej%otb%"
$V1_Global  = "global\['!'\]='8-1638-2'"
$V2_Marker  = "Cot%3t=shtP"
$TronAddrs  = "TMfKQEd7TJJa5xNZJZ2Lep838vrzrs7mAP|TXfxHUet9pJVU1BgVkBAbrES4YUc1nGzcG"
$BscTx      = "0xbe037400670fbf1c32364f762975908dc43eeb38759263e7dfcdabc76380811e|0x3f0e5781d0855fb460661ac63257376db1941b2bb522499e4757ecb3ebd5dce3"
$C2_IP      = "166\.88\.54\.158"
$C2_Vercel  = "260120\.vercel\.app|default-configuration\.vercel\.app|vscode-settings-bootstrap\.vercel\.app|vscode-settings-config\.vercel\.app|vscode-bootstrapper\.vercel\.app|vscode-load-config\.vercel\.app"
$C2_RPC     = "api\.trongrid\.io|api\.telegram\.org|bsc-dataseed\.binance\.org|bsc-rpc\.publicnode\.com"
$Propagation = "temp_auto_push\.bat|temp_interactive_push\.bat"
$EvilNpm    = "tailwindcss-style-animate"
$EvilUuid   = "e9b53a7c-2342-4b15-b02d-bd8b8f6a03f9"
$NpmDirRe   = '^[\w._-]+\$[\w._-]+_\d{6}_\d{6}$'
$ExfilZipRe = '\$[\w._-]+_\d{6}_\d{6}(_2)?#[a-f0-9]{6,}\.zip$'

$AllSig = "$V1_Marker|$V2_Marker|$V1_Global|$TronAddrs|$BscTx|$C2_IP|$C2_Vercel"

function Find-FilesFast {
    param([string]$Root, [string[]]$Include, [int]$MaxDepth = 8, [string[]]$Exclude = @('node_modules','.git','venv','.venv','dist','build','.next','.nuxt','target'))
    if (-not (Test-Path $Root)) { return }
    $excludeRegex = ($Exclude | ForEach-Object { [Regex]::Escape($_) }) -join '|'
    Get-ChildItem -Path $Root -Recurse -Force -Include $Include -Depth $MaxDepth -File 2>$null |
        Where-Object { $_.FullName -notmatch "[\\/](?:$excludeRegex)[\\/]" }
}

# ═════════════════════════════════════════════════════════
Section "PART A - REPO PAYLOAD SCAN"

Sub "A1. JS payload signatures in tracked source files"
$found = $false
foreach ($root in $RepoRoot) {
    if (-not (Test-Path $root)) { continue }
    Find-FilesFast -Root $root -Include @("*.js","*.mjs","*.cjs","*.ts","*.tsx","*.jsx","*.vue","*.svelte") `
        | Select-String -Pattern "$V1_Marker|$V2_Marker|$V1_Global" -List 2>$null `
        | ForEach-Object { Hit $_.Path; $found = $true }
}
if (-not $found) { Ok "no payload signatures" }

Sub "A2. Fake font/asset payloads (wrong magic + signature)"
$found = $false
foreach ($root in $RepoRoot) {
    if (-not (Test-Path $root)) { continue }
    Find-FilesFast -Root $root -Include @("*.woff2","*.woff","*.ttf") | ForEach-Object {
        $bytes = [System.IO.File]::ReadAllBytes($_.FullName) | Select-Object -First 4
        $hex   = ($bytes | ForEach-Object { $_.ToString('x2') }) -join ''
        $expected = switch -Regex ($_.Extension) {
            '\.woff2$' { '774f4632' }
            '\.woff$'  { '774f4646' }
            '\.ttf$'   { '00010000|74727565|4f54544f' }
            default    { $null }
        }
        if (-not $expected) { return }
        if ($hex -notmatch "^($expected)$") {
            $content = Get-Content $_.FullName -Raw -ErrorAction SilentlyContinue
            if ($content -match "$V1_Marker|$V2_Marker|$V1_Global|require\(|process\.|child_process") {
                Hit "$($_.FullName) (magic=$hex, looks like JS)"
                $found = $true
            }
        }
    }
}
if (-not $found) { Ok "no fake fonts" }

Sub "A3. Malicious .vscode/tasks.json with auto-execute (TasksJacker)"
$found = $false
foreach ($root in $RepoRoot) {
    if (-not (Test-Path $root)) { continue }
    Get-ChildItem -Path $root -Recurse -Force -Filter "tasks.json" -ErrorAction SilentlyContinue |
        Where-Object { $_.DirectoryName -match '\\\.vscode$' -and $_.FullName -notmatch '\\node_modules\\' } |
        ForEach-Object {
            $c = Get-Content $_.FullName -Raw -ErrorAction SilentlyContinue
            if ($c -match 'runOn["'' ]*:["'' ]*folderOpen') {
                if ($c -match "node\s+.*\.(woff|woff2|ttf|eot)|curl[^|]*\|\s*(bash|sh|powershell|cmd)|$C2_Vercel|$C2_RPC|$EvilUuid") {
                    Hit $_.FullName; $found = $true
                } else {
                    Warn "$($_.FullName) has runOn:folderOpen — manual review"
                }
            }
        }
}
if (-not $found -and $script:Warns -eq 0) { Ok "no folderOpen auto-tasks" }

Sub "A4. .vscode/settings.json with task.allowAutomaticTasks:true"
$found = $false
foreach ($root in $RepoRoot) {
    if (-not (Test-Path $root)) { continue }
    Get-ChildItem -Path $root -Recurse -Force -Filter "settings.json" -ErrorAction SilentlyContinue |
        Where-Object { $_.DirectoryName -match '\\\.vscode$' -and $_.FullName -notmatch '\\node_modules\\' } |
        ForEach-Object {
            $c = Get-Content $_.FullName -Raw -ErrorAction SilentlyContinue
            if ($c -match '"task\.allowAutomaticTasks"\s*:\s*true') {
                Warn "$($_.FullName) sets allowAutomaticTasks:true"
                $found = $true
            }
        }
}
if (-not $found) { Ok "no allowAutomaticTasks:true" }

Sub "A5. Propagation script names referenced"
$found = $false
foreach ($root in $RepoRoot) {
    if (-not (Test-Path $root)) { continue }
    Get-ChildItem -Path $root -Recurse -Force -File -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -notmatch '\\(node_modules|\.git|venv|\.next)\\' -and $_.Length -lt 5MB } |
        Select-String -Pattern $Propagation -List 2>$null |
        ForEach-Object { Hit $_.Path; $found = $true }
}
if (-not $found) { Ok "no propagation refs" }

Sub "A6. Malicious npm package '$EvilNpm' in package.json"
$found = $false
foreach ($root in $RepoRoot) {
    if (-not (Test-Path $root)) { continue }
    Get-ChildItem -Path $root -Recurse -Force -Filter "package.json" -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -notmatch '\\node_modules\\' } |
        Select-String -Pattern $EvilNpm -List 2>$null |
        ForEach-Object { Hit $_.Path; $found = $true }
}
if (-not $found) { Ok "no malicious npm dep" }

Sub "A7. Weaponized take-home UUIDs"
$found = $false
foreach ($root in $RepoRoot) {
    if (-not (Test-Path $root)) { continue }
    Find-FilesFast -Root $root -Include @("*.json") |
        Select-String -Pattern $EvilUuid -List 2>$null |
        ForEach-Object { Hit $_.Path; $found = $true }
}
if (-not $found) { Ok "no take-home UUIDs" }

Sub "A8. Git history: TZ-mismatch spoofing fingerprint"
$found = $false
foreach ($root in $RepoRoot) {
    if (-not (Test-Path $root)) { continue }
    Get-ChildItem -Path $root -Recurse -Force -Filter ".git" -Directory -Depth 4 -ErrorAction SilentlyContinue |
        ForEach-Object {
            $repo = Split-Path $_.FullName -Parent
            Push-Location $repo
            try {
                $log = git log --all --format='%h|%ai|%ci|%ae|%ce|%s' 2>$null
                $sus = $log | ForEach-Object {
                    $p = $_ -split '\|', 6
                    if ($p.Count -lt 6) { return }
                    $atz = $p[1].Substring($p[1].Length - 5)
                    $ctz = $p[2].Substring($p[2].Length - 5)
                    if ($atz -ne $ctz -and $p[3] -eq $p[4]) {
                        "$($p[0]) $atz/$ctz $($p[3]) $($p[5].Substring(0,[Math]::Min(50,$p[5].Length)))"
                    }
                } | Select-Object -First 3
                if ($sus) {
                    Warn $repo
                    $sus | ForEach-Object { Write-Host "      $_" -ForegroundColor DarkYellow }
                    $found = $true
                }
            } finally { Pop-Location }
        }
}
if (-not $found) { Ok "no TZ-mismatch commits" }

# ═════════════════════════════════════════════════════════
Section "PART B - HOST EXECUTION-EVIDENCE SCAN"

Sub "B1. Beavertail staging directories ($env:USERPROFILE\.npm and Temp)"
$found = $false
$bases = @("$env:USERPROFILE\.npm", $env:TEMP, $env:LOCALAPPDATA, "$env:USERPROFILE\AppData\Local\Temp")
foreach ($base in $bases | Sort-Object -Unique) {
    if (-not (Test-Path $base)) { continue }
    Get-ChildItem -Path $base -Directory -Force -Depth 2 -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match $NpmDirRe } |
        ForEach-Object { Hit $_.FullName; $found = $true }
}
if (-not $found) { Ok "no staging directories" }

Sub "B2. Staged file names (_credentials.json, _sysenv.json, _info.json)"
$found = $false
foreach ($base in $bases | Sort-Object -Unique) {
    if (-not (Test-Path $base)) { continue }
    Get-ChildItem -Path $base -Recurse -Force -Depth 5 -Include "_credentials.json","_sysenv.json","_sysenv.env","_info.json" -ErrorAction SilentlyContinue |
        ForEach-Object { Hit $_.FullName; $found = $true }
}
if (-not $found) { Ok "no staged JSONs" }

Sub "B3. Exfil archive '*\$*_*#*.zip'"
$found = $false
Get-ChildItem -Path $env:USERPROFILE -Recurse -Force -Depth 6 -Filter "*.zip" -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -match $ExfilZipRe } |
    ForEach-Object { Hit $_.FullName; $found = $true }
if (-not $found) { Ok "no exfil archives" }

Sub "B4. Lock file tmp7A863DD1.tmp"
$found = $false
foreach ($p in @("$env:TEMP\tmp7A863DD1.tmp", "$env:LOCALAPPDATA\Temp\tmp7A863DD1.tmp")) {
    if (Test-Path $p) { Hit $p; $found = $true }
}
if (-not $found) { Ok "no lock files" }

Sub "B5. Run / RunOnce registry keys (persistence)"
$keys = @(
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce'
)
$found = $false
foreach ($k in $keys) {
    if (-not (Test-Path $k)) { continue }
    $vals = Get-ItemProperty -Path $k -ErrorAction SilentlyContinue
    foreach ($prop in $vals.PSObject.Properties) {
        if ($prop.Name -match '^PS' ) { continue }
        $v = "$($prop.Value)"
        if ($v -match "node\s+.*\.(woff|woff2|ttf|eot)|node\s+.*fonts[\\/]|$C2_RPC|$C2_IP|$C2_Vercel|$TronAddrs|\.npm[\\/].*\$.*_\d{6}_") {
            Hit "$k\$($prop.Name) -> $v"
            $found = $true
        }
    }
}
if (-not $found) { Ok "no Run/RunOnce IOCs" }

Sub "B6. Scheduled Tasks referencing IOCs"
$found = $false
$tasks = Get-ScheduledTask -ErrorAction SilentlyContinue
foreach ($t in $tasks) {
    foreach ($action in $t.Actions) {
        $cmd = "$($action.Execute) $($action.Arguments)"
        if ($cmd -match "node\s+.*\.(woff|woff2|ttf|eot)|node\s+.*fonts[\\/]|$C2_RPC|$C2_IP|$C2_Vercel|$TronAddrs") {
            Hit "Scheduled task '$($t.TaskName)' -> $cmd"
            $found = $true
        }
    }
}
if (-not $found) { Ok "no scheduled tasks reference IOCs" }

Sub "B7. Startup folder entries"
$found = $false
$startups = @(
    "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
    "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
)
foreach ($s in $startups) {
    if (-not (Test-Path $s)) { continue }
    Get-ChildItem -Path $s -Force -ErrorAction SilentlyContinue | ForEach-Object {
        Note "Startup item: $($_.FullName)"
    }
}

Sub "B8. WMI Event Subscriptions (silent persistence)"
$found = $false
$filters = Get-WmiObject -Namespace root\subscription -Class __EventFilter -ErrorAction SilentlyContinue
foreach ($f in $filters) {
    if ($f.Query -match "node|woff|trongrid|telegram|$C2_IP") {
        Hit "WMI EventFilter: $($f.Name) -> $($f.Query)"
        $found = $true
    }
}
$consumers = Get-WmiObject -Namespace root\subscription -Class CommandLineEventConsumer -ErrorAction SilentlyContinue
foreach ($c in $consumers) {
    if ($c.CommandLineTemplate -match "node|woff|trongrid|telegram|$C2_IP") {
        Hit "WMI Consumer: $($c.Name) -> $($c.CommandLineTemplate)"
        $found = $true
    }
}
if (-not $found) { Ok "no WMI event subscriptions reference IOCs" }

Sub "B9. Dropper files in Temp/AppData (last 180 days)"
$found = $false
$cutoff = (Get-Date).AddDays(-180)
foreach ($base in @($env:TEMP, "$env:LOCALAPPDATA\Temp", "$env:APPDATA")) {
    if (-not (Test-Path $base)) { continue }
    Get-ChildItem -Path $base -Recurse -Force -Depth 4 -Include "*.py","*.js","*.ps1","*.bat","*.cmd" -ErrorAction SilentlyContinue |
        Where-Object { $_.LastWriteTime -gt $cutoff -and $_.Length -lt 2MB } |
        ForEach-Object {
            $c = Get-Content $_.FullName -Raw -ErrorAction SilentlyContinue
            if ($c -match "$C2_RPC|$C2_IP|$TronAddrs|$BscTx|portalocker|tmp7A863DD1|$V1_Marker|$V2_Marker") {
                Hit $_.FullName
                $found = $true
            }
        }
}
if (-not $found) { Ok "no droppers matching IOC content" }

Sub "B10. Running processes referencing IOCs"
$processes = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue
$matched = $processes | Where-Object {
    $_.CommandLine -match "node\s+.*\.(woff|woff2|ttf|eot)|node\s+.*fonts[\\/]|$C2_RPC|$C2_IP|$C2_Vercel"
}
if ($matched) {
    Hit "process matches:"
    $matched | ForEach-Object { Note "  PID $($_.ProcessId): $($_.CommandLine)" }
} else { Ok "no running processes match" }

Sub "B11. Open network connections to known C2"
$conns = Get-NetTCPConnection -ErrorAction SilentlyContinue | Where-Object { $_.State -eq 'Established' }
$bad = $conns | Where-Object { $_.RemoteAddress -match $C2_IP }
if ($bad) {
    Hit "C2 connection(s):"
    $bad | ForEach-Object { Note "  $($_.LocalAddress):$($_.LocalPort) -> $($_.RemoteAddress):$($_.RemotePort) (PID $($_.OwningProcess))" }
} else { Ok "no live connections to known C2 IP" }

Sub "B12. DNS client cache for IOC domains"
$dns = Get-DnsClientCache -ErrorAction SilentlyContinue
$hosts = @("api.trongrid.io","api.telegram.org","260120.vercel.app","default-configuration.vercel.app",
           "vscode-settings-bootstrap.vercel.app","vscode-settings-config.vercel.app",
           "vscode-bootstrapper.vercel.app","vscode-load-config.vercel.app")
foreach ($h in $hosts) {
    $match = $dns | Where-Object { $_.Entry -eq $h -or $_.Name -eq $h }
    if ($match) { Warn "DNS cache: $h" }
}

Sub "B13. PowerShell history search"
$histPath = (Get-PSReadlineOption -ErrorAction SilentlyContinue).HistorySavePath
if ($histPath -and (Test-Path $histPath)) {
    $h = Get-Content $histPath -Raw -ErrorAction SilentlyContinue
    if ($h -match "$C2_RPC|$C2_IP|$C2_Vercel|$TronAddrs|$V1_Marker|$V2_Marker|$Propagation|fa-solid-400\.woff2") {
        Hit "PS history mentions IOCs (review manually): $histPath"
    } else { Ok "PS history clean" }
}

Sub "B14. Browser credential DB last-modified (informational)"
$dbs = @(
    "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Login Data",
    "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Cookies",
    "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data\Default\Login Data",
    "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Login Data",
    "$env:LOCALAPPDATA\Vivaldi\User Data\Default\Login Data"
)
foreach ($p in $dbs) {
    if (Test-Path $p) {
        $i = Get-Item $p
        Note "$p  ($($i.LastWriteTime))"
    }
}
$ff = "$env:APPDATA\Mozilla\Firefox\Profiles"
if (Test-Path $ff) {
    Get-ChildItem $ff -Recurse -Filter "logins.json" -ErrorAction SilentlyContinue | Select-Object -First 5 |
        ForEach-Object { Note "$($_.FullName)  ($($_.LastWriteTime))" }
}

Sub "B15. Crypto wallet directories"
$wallets = @(
    "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Local Extension Settings\nkbihfbeogaeaoehlefnkodbefgpgknn",  # MetaMask
    "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data\Default\Local Extension Settings\nkbihfbeogaeaoehlefnkodbefgpgknn",
    "$env:APPDATA\Exodus", "$env:APPDATA\atomic", "$env:APPDATA\Electrum",
    "$env:APPDATA\Bitcoin", "$env:APPDATA\Ethereum"
)
foreach ($w in $wallets) {
    if (Test-Path $w) {
        $i = Get-Item $w
        Note "wallet found: $w  ($($i.LastWriteTime))"
    }
}

# ═════════════════════════════════════════════════════════
if ($Full) {
    Section "PART C - DEEP SYSTEM-LOG SCAN (admin recommended)"

    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        Note "Some checks need elevation. Re-run from an elevated PowerShell."
    }

    Sub "C1. Sysmon Network Connection events (Event ID 3) referencing C2"
    try {
        Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -MaxEvents 20000 -ErrorAction Stop |
            Where-Object { $_.Id -eq 3 -and $_.Message -match "$C2_IP|trongrid|telegram|260120|default-configuration|vscode-settings" } |
            Select-Object -First 20 |
            ForEach-Object { Note "  $($_.TimeCreated): $($_.Message.Split([Environment]::NewLine)[0])" }
    } catch { Note "(Sysmon not installed or no events)" }

    Sub "C2. Sysmon Process Creation events (Event ID 1) for node loading fonts"
    try {
        Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -MaxEvents 20000 -ErrorAction Stop |
            Where-Object { $_.Id -eq 1 -and $_.Message -match "node.*\.(woff|woff2|ttf|eot)|node.*fonts[\\/]" } |
            Select-Object -First 20 |
            ForEach-Object { Note "  $($_.TimeCreated): $(($_.Message -split [Environment]::NewLine | Select-String 'CommandLine').Line)" }
    } catch { Note "(Sysmon not installed or no events)" }

    Sub "C3. PowerShell Script Block Logging (Event ID 4104) referencing IOCs"
    try {
        Get-WinEvent -LogName 'Microsoft-Windows-PowerShell/Operational' -MaxEvents 20000 -ErrorAction Stop |
            Where-Object { $_.Id -eq 4104 -and $_.Message -match "$C2_RPC|$C2_IP|$C2_Vercel|$TronAddrs|$V1_Marker|$V2_Marker" } |
            Select-Object -First 10 |
            ForEach-Object { Note "  $($_.TimeCreated): match in script block" }
    } catch { Note "(no matches or logging disabled)" }

    Sub "C4. Windows Defender detection history"
    Get-MpThreatDetection -ErrorAction SilentlyContinue | Select-Object -First 10 |
        ForEach-Object { Note "  $($_.InitialDetectionTime): $($_.ThreatID) - $($_.Resources)" }
}

# ═════════════════════════════════════════════════════════
Section "SUMMARY"
if ($script:Hits -eq 0 -and $script:Warns -eq 0) {
    Write-Host "  No IOC matches and no items requiring review." -ForegroundColor Green
} elseif ($script:Hits -eq 0) {
    Write-Host "  $($script:Warns) item(s) flagged for manual review." -ForegroundColor Yellow
} else {
    Write-Host "  $($script:Hits) HIT(s), $($script:Warns) for manual review." -ForegroundColor Red
}
Write-Host "  A clean scan does not prove uninfection - Beavertail variants self-clean." -ForegroundColor DarkGray
exit $script:Hits
