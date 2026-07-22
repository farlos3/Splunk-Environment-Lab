# Specialized Tracks (BOTS v2) — Threat Hunting · DFIR · Network Forensics · Detection Eng · Purple Team · Reporting · Threat-Intel

Intensive, methodology-driven tracks on `index=botsv2`, same rigour and
structure as [`../botsv1/`](../botsv1/) — but on a **multi-stage, multi-OS
APT** instead of a single ransomware. Every finding below is verified against
the loaded data.

> **Do the [v2 fundamentals pack](../../self-practice/botsv2/) (Stages 1–3) first.**
> ⚠️ v2 = 226M events — always scope your time window and prefer `tstats`, or you'll OOM the lab.

---

## The incident — Taedonggang APT vs. *froth.ly* (August 2017)

An advanced actor targets the **FROTHLY** brewery (`frothly.local`). Unlike
v1's smash-and-grab, this is a slow, multi-surface intrusion. Verified anchors:

| Element | Verified value |
|---|---|
| Domain / org | `FROTHLY` / `frothly.local` |
| **C2 server** | **`45.77.65.211:443`** (PowerShell **Empire**, URI `/admin/get.php`) — seen in `pan:traffic` (48k), `suricata` (38k), `stream:http`, `access_combined` |
| Endpoint compromise | **PowerShell Empire** `-enc` stager (AMSI bypass + WebClient to C2) on **3 hosts: `wrk-btun`, `venus`, `wrk-klagerf`** |
| Foothold → lateral | `wrk-btun` = **`billy.tun`** (foothold); then the **`service3`** service account spread to `venus` + `wrk-klagerf` via **WMI** (`WmiPrvSE.exe`, T1047) |
| Persistence | `schtasks /Create /TN Updater /RU system` running an Empire payload stored in a **registry** key (`HKLM:\Software\Microsoft\Network debug`) |
| Tooling dropped | `msiexec /i c:\temp\download\python.msi /qn` |
| Workstation | `wrk-btun` = user **`FROTHLY\billy.tun`** (heavy `iexplore.exe` — browser activity) |
| Linux | SSH **brute force** on **`eridanus` (67k) + `gacrux` (40k)** from China IPs (`58.242.83.20` 26k → `eridanus`, `218.65.30.126` → `gacrux`, `116.31.116.17` → both); the only **successful** login is `Accepted password for klager from 71.39.18.125` on `gacrux` (5 events, unrelated IP) — `eridanus` yielded zero |
| macOS | **`ET TROJAN OSX Backdoor Quimitchin`** DNS lookup from `10.0.4.2` (the `kutekitten` Mac) → `10.0.1.100` |
| Other IDS | port-135 scanning, TOR relay traffic, vulnerable Java |

**Environment:** 23 hosts — servers `cassiopeia` (MySQL DB, ~61M events), `venus`, `jupiter`, `mercury`, `gacrux` + `eridanus` (Linux, both SSH-brute-forced); workstations `wrk-btun/ghoppy/aturing/klagerf/abungst/fmaltes/bgist`; Macs `maclory-air13` + `kutekitten` (`10.0.4.2`, the Quimitchin host).

---

## Tracks

| File | Track | Focus |
|---|---|---|
| [01-threat-hunting.md](01-threat-hunting.md) | **Threat Hunting** | Hypothesis-driven, ATT&CK — hunt the Empire chain, WMI lateral, multi-OS footholds |
| [02-dfir.md](02-dfir.md) | **DFIR** | Continuous IR case — scope, root-cause, timeline, blast radius across Windows/Linux/macOS |
| [03-network-forensics.md](03-network-forensics.md) | **Network Forensics** | PAN firewall + Suricata + Stream — C2 (TLS), scanning, SSH brute, macOS, exfil |
| [05-detection-engineering.md](05-detection-engineering.md) | **Detection Engineering** | Empire/`-enc` PowerShell, **WMI-spawn**, schtasks persistence, C2 beacon, SSH brute, macOS-via-IDS |
| [06-purple-team.md](06-purple-team.md) | **Purple Team** | ATT&CK coverage, detect-vs-prevent, the macOS blind spot |
| [07-reporting.md](07-reporting.md) | **Reporting** | IOC package, exec summary, ~9-day dwell metric |
| [08-threat-intel.md](08-threat-intel.md) | **Threat-Intel** | Taedonggang attribution, Empire infra, linkage, Diamond model |
| [04-capstone-full-incident.md](04-capstone-full-incident.md) | **Capstone** | "Operation Froth" — the whole APT, all disciplines |

> Status: **all 8 tracks + capstone complete**, verified against the data.
> Reference answers: [SOLUTIONS.md](SOLUTIONS.md).
