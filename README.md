# PolinRider scanners

Cross-platform IOC scanners for the **PolinRider** supply-chain campaign — a DPRK
(Lazarus) operation that injects obfuscated JavaScript into developers' build-config
files (`tailwind.config.js`, `postcss.config.mjs`, `vite.config.js`, etc.), drops
fake `.woff2` payloads, and weaponizes `.vscode/tasks.json` with `runOn: folderOpen`
to deliver the **Beavertail** Stage-4 credential stealer.

Background: <https://github.com/OpenSourceMalware/PolinRider> · <https://opensourcemalware.com/blog/polinrider-attack>

## Files

| File | Purpose |
|---|---|
| `check-polinrider-mac.sh` | macOS scanner (bash) |
| `check-polinrider-linux.sh` | Linux scanner (bash) |
| `check-polinrider-windows.ps1` | Windows scanner (PowerShell 5.1+) |
| `decoded-malware-analysis.js.do_not_execute` | Reference decoder for the v1 obfuscator. **Do not run.** Reading-only. |

## Usage

**macOS / Linux:**

```bash
bash check-polinrider-mac.sh                       # scans ~/Documents/GitHub
bash check-polinrider-mac.sh --repos ~/code        # custom repo root
sudo -A bash check-polinrider-mac.sh --full        # adds unified-log search
```

**Windows:**

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\check-polinrider-windows.ps1
.\check-polinrider-windows.ps1 -RepoRoot C:\dev -Full   # run elevated for Part C
```

Each script exits `0` if clean, otherwise the hit count.

## What gets checked

**Part A — Repo payload scan**
1. JS payload signatures (v1 `rmcej%otb%` and v2 `Cot%3t=shtP`)
2. Fake `.woff2`/`.woff`/`.ttf` files (wrong magic + JS payload)
3. Malicious `.vscode/tasks.json` with `runOn: folderOpen`
4. `.vscode/settings.json` with `task.allowAutomaticTasks: true`
5. Propagation script names (`temp_auto_push.bat`, `temp_interactive_push.bat`)
6. Malicious npm dep `tailwindcss-style-animate`
7. Weaponized take-home UUID `e9b53a7c-2342-4b15-b02d-bd8b8f6a03f9` (StakingGame)
8. Git history for TZ-mismatched author/committer (server-side amend fingerprint)

**Part B — Host execution-evidence scan**
- Beavertail staging dirs (`{user}${host}_{YYMMDD_HHMMSS}`)
- Staged credential files (`_credentials.json`, `_sysenv.json`, `_info.json`)
- Exfil archives (`*${host}_*#{hash}.zip`)
- Lock file `tmp7A863DD1.tmp`
- Persistence: LaunchAgents (Mac), systemd/cron/shell-rc (Linux), Run/RunOnce/Scheduled Tasks/WMI (Windows)
- Live processes / network connections referencing IOCs
- Browser credential DB and crypto wallet locations (informational)

**Part C — Deep log search** (`--full`, root/admin)
- macOS unified log · Linux journalctl · Windows Sysmon + PowerShell ScriptBlock + Defender history

## IOCs covered

```
JS variant 1:    rmcej%otb%    seeds 2857687/2667686    decoder _$_1e42
JS variant 2:    Cot%3t=shtP   seeds 1111436/3896884    decoder MDy
                 global['!']='8-1638-2'
Tron addresses:  TMfKQEd7TJJa5xNZJZ2Lep838vrzrs7mAP
                 TXfxHUet9pJVU1BgVkBAbrES4YUc1nGzcG
BSC tx hashes:   0xbe037400670fbf1c32364f762975908dc43eeb38759263e7dfcdabc76380811e
                 0x3f0e5781d0855fb460661ac63257376db1941b2bb522499e4757ecb3ebd5dce3
C2 IP:           166.88.54.158
RPC/exfil:       api.trongrid.io  api.telegram.org
                 bsc-dataseed.binance.org  bsc-rpc.publicnode.com
Vercel C2:       260120.vercel.app
                 default-configuration.vercel.app
                 vscode-{settings-bootstrap,settings-config,bootstrapper,load-config}.vercel.app
Propagation:     temp_auto_push.bat  temp_interactive_push.bat
Malicious npm:   tailwindcss-style-animate
Take-home UUID:  e9b53a7c-2342-4b15-b02d-bd8b8f6a03f9 (StakingGame)
Lock file:       tmp7A863DD1.tmp
```

## Caveats

- **A clean scan does not prove uninfection.** Beavertail self-cleans its staging
  directory after a successful exfil; if it ran and finished, there's nothing
  left to find.
- IOCs reflect what's *publicly documented* as of 2026-04-11. The campaign
  rotates fingerprints (v1 → v2 happened in April 2026 in response to the
  published YARA rule) — re-pull this list periodically against the upstream
  PolinRider repo.
- Part B's "running processes" / "open connections" only catch infections that
  are *currently active*. For historical execution evidence, run `--full` and
  rely on Part C's log search.

## Blocking the C2 infrastructure

Defense-in-depth: even if a payload runs, blocking outbound traffic to the
known C2 prevents exfil and second-stage download. Block at two layers —
**hosts file** (for domains) and **firewall** (for the IP). Re-check upstream
periodically; the actor rotates infrastructure.

Domains to block:

```
166.88.54.158                              # raw C2 IP — block at firewall
api.trongrid.io                            # blockchain dead-drop reads
bsc-dataseed.binance.org                   # BSC fallback dead-drop
bsc-rpc.publicnode.com                     # BSC fallback dead-drop
260120.vercel.app                          # original loader subdomain
default-configuration.vercel.app           # most-used loader subdomain
vscode-settings-bootstrap.vercel.app       # TasksJacker bootstrap
vscode-settings-config.vercel.app          # TasksJacker bootstrap
vscode-bootstrapper.vercel.app             # TasksJacker bootstrap
vscode-load-config.vercel.app              # TasksJacker bootstrap
```

Note on `api.telegram.org`: it's the documented exfil endpoint, but it's also
a legitimate API used by many real apps. Don't blanket-block it unless you're
certain you don't use any Telegram bots / clients on the host.

Note on `*.trongrid.io` and `bsc-*`: only block these on machines that don't
legitimately interact with Tron/BSC blockchains. They're public RPC endpoints
used by real wallets and dApps.

### macOS

```bash
# Add to /etc/hosts (sudo required)
sudo tee -a /etc/hosts >/dev/null <<'EOF'

# PolinRider C2 — added YYYY-MM-DD
0.0.0.0  260120.vercel.app
0.0.0.0  default-configuration.vercel.app
0.0.0.0  vscode-settings-bootstrap.vercel.app
0.0.0.0  vscode-settings-config.vercel.app
0.0.0.0  vscode-bootstrapper.vercel.app
0.0.0.0  vscode-load-config.vercel.app
0.0.0.0  api.trongrid.io
0.0.0.0  bsc-dataseed.binance.org
0.0.0.0  bsc-rpc.publicnode.com
EOF

# Flush DNS cache
sudo dscacheutil -flushcache && sudo killall -HUP mDNSResponder

# Block the raw C2 IP via pf
sudo tee /etc/pf.anchors/polinrider >/dev/null <<'EOF'
block drop out quick to 166.88.54.158
block drop in  quick from 166.88.54.158
EOF
echo 'anchor "polinrider" all' | sudo tee -a /etc/pf.conf
echo 'load anchor "polinrider" from "/etc/pf.anchors/polinrider"' | sudo tee -a /etc/pf.conf
sudo pfctl -f /etc/pf.conf -e
```

### Linux

```bash
# Add to /etc/hosts (sudo required)
sudo tee -a /etc/hosts >/dev/null <<'EOF'

# PolinRider C2 — added YYYY-MM-DD
0.0.0.0  260120.vercel.app
0.0.0.0  default-configuration.vercel.app
0.0.0.0  vscode-settings-bootstrap.vercel.app
0.0.0.0  vscode-settings-config.vercel.app
0.0.0.0  vscode-bootstrapper.vercel.app
0.0.0.0  vscode-load-config.vercel.app
0.0.0.0  api.trongrid.io
0.0.0.0  bsc-dataseed.binance.org
0.0.0.0  bsc-rpc.publicnode.com
EOF

# Flush DNS (varies by distro)
sudo systemd-resolve --flush-caches 2>/dev/null || sudo resolvectl flush-caches 2>/dev/null || true

# Block the raw C2 IP — nftables (modern systems)
sudo nft add table inet filter 2>/dev/null || true
sudo nft 'add chain inet filter output { type filter hook output priority 0; }' 2>/dev/null || true
sudo nft add rule inet filter output ip daddr 166.88.54.158 drop
sudo nft add rule inet filter output ip saddr 166.88.54.158 drop

# Or iptables (legacy)
# sudo iptables -A OUTPUT -d 166.88.54.158 -j DROP
# sudo iptables -A INPUT  -s 166.88.54.158 -j DROP
# Persist with iptables-persistent / netfilter-persistent
```

### Windows (PowerShell, run as Administrator)

```powershell
# Append to hosts file
$hosts = "$env:WINDIR\System32\drivers\etc\hosts"
$entries = @(
  '0.0.0.0  260120.vercel.app',
  '0.0.0.0  default-configuration.vercel.app',
  '0.0.0.0  vscode-settings-bootstrap.vercel.app',
  '0.0.0.0  vscode-settings-config.vercel.app',
  '0.0.0.0  vscode-bootstrapper.vercel.app',
  '0.0.0.0  vscode-load-config.vercel.app',
  '0.0.0.0  api.trongrid.io',
  '0.0.0.0  bsc-dataseed.binance.org',
  '0.0.0.0  bsc-rpc.publicnode.com'
)
Add-Content -Path $hosts -Value "`n# PolinRider C2 — added $(Get-Date -Format 'yyyy-MM-dd')"
$entries | ForEach-Object { Add-Content -Path $hosts -Value $_ }

# Flush DNS
ipconfig /flushdns

# Block raw C2 IP via Windows Firewall
New-NetFirewallRule -DisplayName 'Block PolinRider C2 (out)' `
  -Direction Outbound -Action Block -RemoteAddress 166.88.54.158 -Profile Any
New-NetFirewallRule -DisplayName 'Block PolinRider C2 (in)' `
  -Direction Inbound  -Action Block -RemoteAddress 166.88.54.158 -Profile Any
```

### Verifying the blocks

```bash
# macOS / Linux — should resolve to 0.0.0.0 or fail
getent hosts default-configuration.vercel.app    # Linux
dscacheutil -q host -a name default-configuration.vercel.app   # macOS

# Should refuse / time out (not 200)
curl -m 5 -I https://default-configuration.vercel.app/
curl -m 5 -I http://166.88.54.158/
```

```powershell
# Windows
Resolve-DnsName default-configuration.vercel.app
Test-NetConnection 166.88.54.158 -Port 443
```

### Network-wide blocking (recommended for shared infrastructure)

For home/office networks, prefer DNS-level blocking on the resolver instead of
per-host hosts files — it covers every device and is harder to bypass. Add the
domains above as a custom blocklist in **Pi-hole**, **AdGuard Home**, **NextDNS**,
or your router's DNS filtering. Block the IP `166.88.54.158` at the router
firewall.

## If a hit is found

1. Stop and **rotate every credential** that lived on the host:
   browser-saved passwords, cloud keys (`.env`), GitHub PATs, SSH keys,
   password-manager master password (with 2FA on the vault).
2. **Crypto wallets**: assume seed phrases / private keys are stolen.
   Migrate funds to a fresh wallet from a clean device.
3. Clean the repos (remove the payload, then `git push --force-with-lease`).
   See the OpenSourceMalware incident-response guide for full host cleanup.
4. Audit GitHub OAuth apps, GitHub Apps, deploy keys, and webhooks across all
   your repos — the actor's primary persistence is stolen tokens.
5. **Block the C2 infrastructure** at host or network level — see above.
