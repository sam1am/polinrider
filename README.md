# IOC Blocking Toolkit

Cross-platform scripts that prevent the EtherHiding-style malware described in
`malware-investigation.md` from reaching its command-and-control (C2)
infrastructure. Works on Linux, macOS, and Windows.

## What this does

The malware reads its second-stage payload from transactions on the TRON and
BSC public blockchains, fetched via well-known public RPC endpoints. If it
can't resolve those endpoints, the second stage cannot execute, and the
infostealer/wallet-drainer behavior is neutralized — even if the obfuscated
loader is still sitting in your `tailwind.config.js`.

The scripts:

1. Add `0.0.0.0` entries to the system `hosts` file for every domain in
   `iocs.txt` (covers IPv4 and IPv6).
2. Add outbound block rules to the system firewall for every IP in
   `iocs.txt` (nftables/iptables/ufw on Linux, pf on macOS,
   Windows Defender Firewall on Windows).
3. Flush the DNS cache so the changes take effect immediately.
4. Are fully reversible — re-run with `--unblock` (or `-Unblock` on Windows)
   to remove everything.
5. Are idempotent — re-running `block` does not duplicate entries.
6. Always back up the hosts file with a timestamped suffix before modifying.

## Files in this folder

| File | Purpose |
|---|---|
| `iocs.txt` | The single source of truth for what to block. Edit freely. |
| `block-iocs.sh` | Linux + macOS blocking script. |
| `block-iocs.ps1` | Windows blocking script (PowerShell 5.1+). |
| `check-polinrider-linux.sh` | Pre-existing detection scan for Linux. |
| `check-polinrider-mac.sh` | Pre-existing detection scan for macOS. |
| `check-polinrider-windows.ps1` | Pre-existing detection scan for Windows. |
| `decoded-malware-analysis.js.do_not_execute` | Annotated deobfuscated payload — analysis only, never run. |
| `malware-investigation.md` | Full first-person narrative of how this was discovered and traced. |
| `README.md` | This file. |

The `check-polinrider-*` scripts and `block-iocs.*` scripts are complementary:
run the `check-` scripts to find infections; run the `block-` scripts to
prevent any remaining infection from reaching its C2.

## Quick start

### Linux / macOS

```bash
cd /Users/johngarfield/Documents/GitHub/polinrider     # or wherever you cloned this
chmod +x block-iocs.sh
sudo ./block-iocs.sh                       # block (default)
sudo ./block-iocs.sh --dry-run             # show what would happen
sudo ./block-iocs.sh --hosts-only          # skip firewall, just hosts file
sudo ./block-iocs.sh --unblock             # remove everything this script added
```

### Windows

Open PowerShell **as Administrator**, then:

```powershell
cd C:\path\to\polinrider
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
.\block-iocs.ps1                           # block (default)
.\block-iocs.ps1 -DryRun                   # show what would happen
.\block-iocs.ps1 -HostsOnly                # skip firewall
.\block-iocs.ps1 -Unblock                  # remove everything this script added
```

## Scanning for infection (`check-polinrider-*`)

The `check-polinrider-*` scripts are read-only detection scanners. They never
modify your system — they only report findings. Run one **before** blocking to
see whether any host or repo is already infected, and again afterward to
confirm cleanup.

Each script is self-contained: pick the one that matches your OS.

### Linux / macOS

```bash
bash check-polinrider-mac.sh                          # quick scan, default repo paths
bash check-polinrider-linux.sh --repos ~/code         # scan a specific repo root
sudo -A bash check-polinrider-mac.sh --full           # add deep system-log scan
```

| Argument | Description |
|---|---|
| `--repos PATH` | Override the default repo-root list with a single path. Without it, the macOS script scans `~/Documents/GitHub`; the Linux script scans `~/code`, `~/src`, `~/projects`, `~/dev`, `~/git`, `~/repos`, `~/Documents/GitHub`. |
| `--full` | Adds Part C: deep system-log scan (`log show` on macOS, `journalctl` / iptables logs / `/var/log` on Linux) plus a system-wide process listing. Requires root. |

Exit code is `0` on a clean scan and the hit count otherwise.

### Windows

Open PowerShell (Administrator recommended for Part C):

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
.\check-polinrider-windows.ps1                                # quick, default repo paths
.\check-polinrider-windows.ps1 -RepoRoot C:\dev,C:\src        # scan one or more roots
.\check-polinrider-windows.ps1 -Full                          # add Event Log + system-wide checks
```

| Argument | Description |
|---|---|
| `-RepoRoot <string[]>` | One or more repo roots to scan. Default: `$HOME\Documents\GitHub`, `$HOME\source\repos`, `$HOME\code`, `$HOME\dev`, `$HOME\projects`. |
| `-Full` | Adds Part C: Sysmon Network Connection (Event ID 3), Process Creation (Event ID 1), PowerShell Script Block Logging (Event ID 4104), and Windows Defender detection history. Run elevated. |

### What the scripts look for

All three platforms share the same IOC set and section layout:

**Part A — repo payload scan**
- JS payload signatures for both known variants: V1 (`rmcej%otb%`,
  `global['!']='8-1638-2'`) and V2 (`Cot%3t=shtP`) across `.js`, `.mjs`,
  `.cjs`, `.ts`, `.tsx`, `.jsx`, `.vue`, `.svelte`.
- Fake font/asset files: `.woff2` / `.woff` / `.ttf` whose magic bytes don't
  match the format and whose contents look like JavaScript (`require`,
  `process.`, `child_process`, or a payload marker).
- TasksJacker `.vscode/tasks.json` with `runOn: folderOpen` that also
  references node-loading-a-font, piped curl/wget shell, a known C2 domain,
  or the weaponized take-home UUID.
- `.vscode/settings.json` with `task.allowAutomaticTasks: true`.
- References to the propagation scripts `temp_auto_push.bat` /
  `temp_interactive_push.bat`.
- `package.json` files depending on the malicious npm package
  `tailwindcss-style-animate`.
- The weaponized take-home UUID `e9b53a7c-2342-4b15-b02d-bd8b8f6a03f9`.
- Git commits with author/committer timezone mismatch under the same
  identity (post-commit amend on a different machine — a spoofing
  fingerprint).

**Part B — host execution-evidence scan**
- Beavertail staging directories matching `{user}${host}_YYMMDD_HHMMSS`
  under `~/.npm`, `/tmp`, `/var/tmp`, `~/Library/...` (mac), or `%TEMP%` /
  `%APPDATA%` (Windows).
- Staged exfil files: `_credentials.json`, `_sysenv.json`, `_sysenv.env`,
  `_info.json`.
- Exfil archives matching `*${host}_*#<hex>.zip`.
- Known mutex / lock file `tmp7A863DD1.tmp`.
- Persistence: LaunchAgents/Daemons (mac), systemd user services + cron +
  XDG autostart + shell rc files (Linux), Run/RunOnce keys + Scheduled
  Tasks + Startup folder + WMI Event Subscriptions (Windows) — flagged
  when they reference any IOC.
- Dropper-shaped files (`*.py`, `*.js`, `*.sh`) modified in the last 180
  days under `/tmp`, `~/Library`, or `%TEMP%` whose contents reference C2
  endpoints, the C2 IP `166.88.54.158`, hardcoded TRON wallets, BSC
  transaction hashes, `portalocker`, the lock-file name, or a payload
  marker.
- Running processes loading fonts via node, or matching any C2 domain.
- Open network connections to the known C2 IP, Vercel C2 hostnames, or
  the blockchain RPC endpoints.
- Shell / PowerShell history mentioning any IOC.
- Browser credential DB last-modified timestamps (informational, helps you
  decide what to rotate).
- Installed crypto wallet directories (informational).
- macOS only: keychain-access events from `node`, `python`, `curl`, or
  `wget` in the last 7 days.

**Part C — deep system-log scan (`--full` / `-Full`)**
- macOS: unified log search (`log show --last 14d`) for any IOC string,
  full process list, and pf state table for the C2 IP.
- Linux: `journalctl` search, full process list, iptables/nftables logs,
  and `/var/log` grep.
- Windows: Sysmon Event IDs 3 (network) and 1 (process), PowerShell Event
  ID 4104 (script block logging), and Defender detection history.

Findings are tagged `HIT` (confirmed match), `REVIEW` (needs a human look),
or `ok` (clean). A clean scan does not prove uninfection — Beavertail
variants are known to self-clean after exfil — so re-run periodically and
keep `iocs.txt` blocked at the network layer regardless.

## What's in `iocs.txt`

Confidence levels are documented inline:

- `[CONFIRMED]` — directly observed in our decoded sample
  (`decoded-malware-analysis.js.do_not_execute`). Four endpoints carry the
  entire C2 retrieval chain:
  - `api.trongrid.io` — primary TRON RPC; the malware reads the latest
    confirmed outbound transaction from a hardcoded TRON wallet, decodes
    `raw_data.data` from hex, and reverses the resulting string to obtain
    a stage-2 transaction hash.
  - `fullnode.mainnet.aptoslabs.com` — Aptos fallback if the TRON fetch
    fails; reads `payload.arguments[0]` from the latest tx of a hardcoded
    Aptos account.
  - `bsc-dataseed.binance.org` — primary BSC RPC; calls
    `eth_getTransactionByHash` with the stage-2 hash and decodes the input
    field's hex into the encrypted payload.
  - `bsc-rpc.publicnode.com` — BSC RPC fallback.

  The retrieved payload is XOR-decrypted with one of two hardcoded keys,
  then either `eval()`'d or executed in a detached `node -e` child process.

- `[HIGH]` — same providers, alternate subdomains the attacker can pivot to
  (TRON Shasta/Nile testnets, BSC mirrors, Aptos testnet/devnet, etc.).
- `[MEDIUM]` — explorers and APIs commonly used as attribution or fallback
  C2 (BscScan, Aptos Explorer).
- `[PRECAUTION]` — defensive blocks; legitimate uses also exist (commented
  out by default).

Non-blockable IOCs (TRON wallet addresses, Aptos transaction hashes, XOR
keys, source-code fingerprints) are documented in a comment block at the
bottom of `iocs.txt` for use in monitoring, blockchain pivoting, and
yara-style scans of other code bases.

## When to add IOCs

Anytime the Cachy investigation, the briefed-agent's `cachy-investigation-report.md`,
or any future analysis surfaces a new domain or IP, add it to `iocs.txt`
with the appropriate confidence tag and re-run the script. No code changes
needed.

Format reminder:

```
example.com           # [CONFIRMED] hard-coded in decoded blob
198.51.100.42         # [CONFIRMED] netstat hit during commit
not-a-real-c2.org     # [HIGH] from VirusTotal pivot
```

## Verifying it worked

### Linux / macOS

```bash
dig +short api.trongrid.io        # should print 0.0.0.0 (or nothing)
getent hosts bsc-dataseed.binance.org
curl -v --max-time 3 https://api.trongrid.io 2>&1 | head    # should fail fast
```

### Windows

```powershell
Resolve-DnsName api.trongrid.io
nslookup bsc-dataseed.binance.org
Test-NetConnection api.trongrid.io -Port 443         # should fail
```

## What this does NOT do

- **Does not remove the malware itself.** The obfuscated payload is still
  sitting in `cocofintel/frontend/tailwind.config.js` and
  `SageChat/postcss.config.mjs` (and their git history). Block first, then
  do the cleanup commits.
- **Does not protect machines you haven't run it on.** If you have other
  developer machines / VMs / Codespaces / CI runners, run it there too.
- **Does not survive a fresh OS install.** Re-run after re-imaging.
- **Does not replace credential rotation.** You've already revoked the PATs
  and SSH keys; this is a separate, network-layer mitigation.
- **Does not catch DoH / DoT.** If your browser or any application is
  configured to use DNS-over-HTTPS (e.g. Firefox's NextDNS / Cloudflare DoH
  setting), it bypasses the system resolver and the hosts file entries
  won't apply to it. The firewall rules will still block by IP. Verify that
  your browser is using the system resolver if you want hosts-level
  protection there.

## Legitimate-use caveats

If you actively develop dApps against TRON or BSC, the default `iocs.txt`
will break that work. Before running, scan the file for `[HIGH]` entries
and comment out anything that's part of your legitimate stack. The script
will skip commented lines.

## Reverting

`--unblock` / `-Unblock` does a full clean reversal:

- Removes the hosts-file block delimited by the `# === BEGIN/END ===` markers.
- Removes nftables `polinrider` table / iptables `polinrider`-tagged rules /
  ufw `polinrider`-comment rules / pf anchor / Windows Firewall rules in the
  `polinrider` group.
- Flushes DNS cache.

The timestamped hosts backups (`hosts.bak.YYYYMMDD-HHMMSS`) are kept on
disk in case you want to compare or restore manually.

## Troubleshooting

- **"Permission denied" on `/etc/hosts`** — you forgot `sudo`.
- **PowerShell "execution of scripts is disabled"** — run
  `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force` in
  the same session.
- **Block doesn't seem to take effect** — flush your browser DNS cache
  separately (Chrome: `chrome://net-internals/#dns` → Clear host cache).
- **macOS pf rules vanish after reboot** — pf isn't enabled by default on
  macOS user systems. The script enables it for the current boot. To make
  it permanent, look at `launchd` or use only the hosts-file mode (`--hosts-only`).
- **Linux iptables rules vanish after reboot** — `iptables` rules are not
  persisted by default. Use `iptables-save > /etc/iptables/rules.v4` (with
  the `iptables-persistent` package) or run the script from a boot service.
  nftables rules also do not persist unless you `nft list ruleset > /etc/nftables.conf`.

## Threat-model notes

This is a **defense-in-depth** layer. The right order of operations:

1. ✅ Rotate all credentials (already done).
2. ✅ Revoke all SSH keys and OAuth tokens (already done).
3. ✅ Block C2 infrastructure (this toolkit).
4. ⏳ Identify and remove the local injector (Cachy investigation, in progress).
5. ⏳ Clean malicious code from infected repos in HEAD (after step 4 completes).
6. ⏳ Rotate any secrets that were live in those repos at infection time.

Step 3 buys you safety to do steps 4–6 calmly without worrying about
ongoing exfiltration during the cleanup.
