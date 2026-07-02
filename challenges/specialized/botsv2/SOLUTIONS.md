# Specialized Tracks (BOTS v2) — Reference Walkthroughs

Verified against the loaded `index=botsv2`. ✅ = confirmed value. Scope raw
searches to `08/23–08/25/2017` (the active days) or use `tstats` — v2 is 226M events.

---

# Track 1 — Threat Hunting (Taedonggang APT)

## Scenario A — The Empire Foothold (Windows)

### A1 ✅ Find the beacon
```spl
index=botsv2 "45.77.65.211" | stats count by sourcetype
```
One external IP dominates IDS + firewall + wire: **`45.77.65.211`** — `pan:traffic` (48,397), `suricata` (38,313), `stream:tcp/ip`, `stream:http` (9,712), `access_combined` (4,854). That's the C2.

### A2 ✅ Endpoint payload
```spl
index=botsv2 sourcetype=*ysmon* EventCode=1 (CommandLine="*-enc*" OR CommandLine="*FromBase64*" OR CommandLine="*DownloadString*")
| table _time host CommandLine
```
`powershell -noP -sta -w 1 -enc <base64>` — decoded, a **PowerShell Empire** stager (AMSI bypass, `System.Net.WebClient` → `https://45.77.65.211:443/admin/get.php`, RC4, `Cookie: session=MvCdddPqFQ54VL4OWU5ryRTUir8=`). ⚠️ **Verified — it's on THREE hosts, not just venus:** `stats count by host User` shows **`wrk-btun`** (user `FROTHLY\billy.tun`), **`venus`** and **`wrk-klagerf`** (both user `FROTHLY\service3`). So `wrk-btun`/billy.tun is the foothold, and the **`service3`** service account was used to spread to venus + wrk-klagerf. (T1059.001 / T1027.)

### A3 ✅ Execution vector
```spl
index=botsv2 sourcetype=*ysmon* EventCode=1 host=venus CommandLine="*-enc*"
| rex field=_raw "<Data Name='ParentImage'>(?<ParentImage>[^<]+)" | table _time ParentImage
```
Parent = **`C:\Windows\System32\wbem\WmiPrvSE.exe`** → launched via **WMI** (T1047). Verified: the WMI-spawned agent appears on **venus, wrk-btun, wrk-klagerf** — the `service3` account driving WMI lateral execution to venus + wrk-klagerf. Not a local click.

### A4 ✅ Persistence
```spl
index=botsv2 sourcetype=*ysmon* EventCode=1 (CommandLine="*schtasks*Create*" OR CommandLine="*/TN Updater*")
```
`schtasks /Create /F /RU system /SC DAILY /ST 10:51 /TN Updater /TR "powershell … -c IEX([Text.Encoding]::UNICODE.GetString([Convert]::FromBase64String((gp HKLM:\Software\Microsoft\Network debug).debug)))"` — scheduled task **"Updater"** as SYSTEM, running an Empire payload read from a **registry** value (T1053.005 + T1547/registry-blob).

### A5 ✅ Confirm & scope C2
```spl
index=botsv2 sourcetype=pan:traffic "45.77.65.211" | rex "TRAFFIC,\w+,\d+,[^,]+,(?<src_ip>[^,]+),(?<dest_ip>[^,]+)" | stats count by src_ip
```
C2 corroborated across PAN + Suricata + Stream + web (A1). Enumerate internal `src_ip`s reaching it = the blast-radius seed. **Report-grade:** one indicator, four independent sources.

### A6 ✅ Tooling drop
```spl
index=botsv2 sourcetype=*ysmon* EventCode=1 CommandLine="*msiexec*c:\\temp*"
```
`msiexec /i c:\temp\download\python.msi /qn /norestart` — Python staged to `c:\temp\download` (T1105). **Chain:** WMI push → Empire `-enc` stager → C2 `45.77.65.211` → schtasks+registry persistence → tooling staged.

## Scenario B — The Other Doors (Linux + macOS)

### B1 ✅ Linux SSH brute-force noise
```spl
index=botsv2 sourcetype=linux_secure "Failed password"
| rex "from (?<src_ip>\d+\.\d+\.\d+\.\d+)" | stats count by src_ip | sort - count
```
Top: `58.242.83.20` (26,174), `116.31.116.17` (19,755), `58.242.83.11` (19,329), `218.65.30.126`, `116.31.116.52` — internet brute force on `gacrux`. Loud background noise.

### B2 ✅ Successful login
```spl
index=botsv2 sourcetype=linux_secure "Accepted password"
| rex "Accepted password for (?<user>\S+) from (?<src_ip>\S+)" | stats count by src_ip user host
```
`Accepted password for klager from 71.39.18.125` on `gacrux` — a **different** source than the brute-forcers. Judgment call: likely the employee `klager` (verify source/timing) — the lesson is separating the real login from the brute-force noise, not assuming the loud IPs won.

### B3 ✅ macOS backdoor
```spl
index=botsv2 sourcetype=suricata "Quimitchin" | stats count by src_ip dest_ip
```
`ET TROJAN OSX Backdoor Quimitchin DNS Lookup` from **`10.0.4.2`** (the `maclory-air13` Mac) → `10.0.1.100`. Quimitchin/FruitFly = a macOS backdoor — a separate malware family from the Windows Empire agent.

### B4 — Campaign linkage
**Deliverable:** the Windows Empire foothold (**venus + wrk-btun + wrk-klagerf**, foothold `billy.tun`→lateral `service3`, C2 `45.77.65.211`) is the core Taedonggang intrusion; the macOS Quimitchin activity is a distinct foothold to assess on its own; the internet SSH brute force is **background noise** (not the APT). State which share infra/timing vs. which don't — don't fold noise into the campaign.

---

# Track 2 — DFIR

- **D0 ✅** `| metadata type=sourcetypes index=botsv2` → Windows (4688/Sysmon), Linux (syslog/auditd), PAN, Suricata, Stream, MySQL. Gaps: **macOS has no endpoint agent** (seen only via IDS/DNS); PAN/Linux need `rex`.
- **D1 ✅** internal hosts beaconing C2 `45.77.65.211` with first-seen:
  ```spl
  index=botsv2 sourcetype=pan:traffic "45.77.65.211" | rex ",(?<sip>10\.0\.\d+\.\d+),(?<dip>[^,]+)," | search dip="45.77.65.211"
  | stats count min(_time) as first by sip | eval first=strftime(first,"%m-%d %H:%M") | sort first
  ```
  `10.0.2.109` first at **08-15 23:36** (earliest foothold) → `10.0.2.107` (08-24 03:29), `10.0.1.100`/`10.0.1.101` (08-24 03:55). **`t0` = Aug 15**, not the Aug-24 spike.
- **D2 ✅** Empire `-enc` parented by **`WmiPrvSE.exe`** (T1047) on **venus, wrk-btun, wrk-klagerf**. Root cause: `wrk-btun`/`billy.tun` is the foothold; the **`service3`** account then spread via WMI to venus + wrk-klagerf.
- **D3 ✅** timeline: **08-15 23:36** first C2 contact (`10.0.2.109`) · **08-24 03:29** expansion · **08-24 03:55:14** Empire stager on `venus` · **08-24 04:12:36** `schtasks Updater` persistence.
- **D4 ✅** payload = PowerShell **Empire** stager (AMSI bypass, `WebClient`→`https://45.77.65.211:443/admin/get.php`, RC4, `session=MvCdddPqFQ54VL4OWU5ryRTUir8=`).
- **D5 ✅** eradication: remove task **`Updater`** + registry value `HKLM:\Software\Microsoft\Network debug`; sweep the pattern on all beaconing hosts.
- **D6 ✅** blast radius: **network view** = 4 internal IPs beaconing C2 (`10.0.2.107/109`, `10.0.1.100/101`); **confirmed-compromised (Empire agent present)** = **`venus`, `wrk-btun`, `wrk-klagerf`** (3 hosts, verified via the `-enc` search).
- **D7 ✅** lateral = WMI (`WmiPrvSE.exe`, T1047); the account behind it is **`FROTHLY\service3`** (ran the Empire on venus + wrk-klagerf) — reset it.
- **D8 ✅** multi-OS: Linux `Accepted password for klager from 71.39.18.125` (vs. brute-force noise `58.242.83.20` etc.); macOS Quimitchin from `10.0.4.2` (IDS-only).
- **D9 ✅** accounts: `FROTHLY\billy.tun` (foothold, wrk-btun), **`FROTHLY\service3`** (lateral cred → venus + wrk-klagerf), `amber.turing` (PAN), `klager` (Linux), SYSTEM (the task).
- **D10 ✅ (qualitative)** exfil: traffic to C2 is **asymmetric — received > sent** (inbound tasking dominates; a naive positional `rex` on the PAN CSV byte columns is unreliable — it returned `sent=0`, so don't quote a byte number without the proper Palo Alto field parser). Evidence points to **C2 signalling/tasking, not bulk data theft** — state it that way, don't over-claim exfil.
- **D11** containment: isolate compromised hosts, block `45.77.65.211`, remove `Updater`+registry, reset abused creds, handle Linux/macOS separately.
- **D12** dwell = Aug 15 (first C2) → detection; ATT&CK: T1190/T1566?→T1059.001→T1047→T1053.005→T1071→(multi-OS T1078/T1110)→exfil. Exec summary + IOCs.

# Track 3 — Network Forensics

- **N1 ✅** PAN top talkers — `sourcetype=pan:traffic | rex ",(?<src_ip>10\.0\.\d+\.\d+),(?<dst_ip>\d+\.\d+\.\d+\.\d+)," | stats count by dst_ip`; `45.77.65.211` stands out beyond normal web.
- **N2 ✅** C2 = `45.77.65.211` on **443/TLS** (`/admin/get.php`) — PAN (48,397) + Suricata (38,313) + Stream; payload encrypted.
- **N3 ✅** internal beacon hosts: `10.0.2.107`, `10.0.2.109` (first, Aug 15), `10.0.1.100`, `10.0.1.101`.
- **N4 ✅** `stream:http dest_ip="45.77.65.211"` ≈ empty (TLS) → for HTTPS C2 rely on flow metadata + IDS + endpoint, not payload. (Only stray cleartext: one `/microsoftuserfeedbackservice` hit.)
- **N5 ✅** scanning — `suricata "Port 135"` → `10.0.1.1 → 10.0.1.100` (5,330, "ET SCAN Unusual Port 135"). Categories: `Misc activity` (5,344), `A Network Trojan was detected` (5 = Quimitchin), `Misc Attack` (7).
- **N6 ✅** SSH brute — `linux_secure "Failed password"` external China IPs (`58.242.83.20` 26k …) on `gacrux`; wire view `stream:tcp dest_port=22`.
- **N7 ✅** macOS — `suricata "Quimitchin"` (cat *A Network Trojan*) from `10.0.4.2`; pivot `stream:dns src_ip=10.0.4.2`.
- **N8 ✅** capstone — `(pan:traffic OR suricata OR stream:tcp) 45.77.65.211 | stats count by sourcetype`: one indicator across every network view = report-grade. Exfil = over TLS C2, **asymmetric (received > sent) → tasking/signalling, not bulk theft**; a naive positional `rex` on PAN byte columns is unreliable (returns `sent=0`) — don't quote byte numbers without the proper PAN field parser.

# Track 5 — Detection Engineering

### DE1 ✅ Empire / encoded PowerShell (T1059.001, T1027)
```spl
index=botsv2 sourcetype=*ysmon* EventCode=1 (CommandLine="*-enc*" OR CommandLine="*FromBase64*" OR CommandLine="*AmsiUtils*")
| stats count by host
```
**Verified fires on 3 hosts:** `wrk-btun` (5), `wrk-klagerf` (3), `venus` (2). **Why high-signal:** the AMSI-bypass + `-noP` + long base64 combination is an Empire fingerprint; admin scripts rarely stack all three. **Tune:** require ≥2 markers to cut the odd legit `-enc`.

### DE2 ✅ WMI-spawned shell (T1047)
```spl
index=botsv2 sourcetype=*ysmon* EventCode=1 (Image="*powershell*" OR Image="*cmd.exe")
| rex field=_raw "<Data Name='ParentImage'>(?<ParentImage>[^<]+)"
| search ParentImage="*WmiPrvSE.exe" | stats count by host
```
**Verified fires on `venus`, `wrk-btun`, `wrk-klagerf` (1 each)** — the exact WMI-lateral trail. **Why it's the star detection:** a script host parented by `WmiPrvSE.exe` = someone running code over WMI; almost nothing benign does this. Catches the lateral movement itself, not just the aftermath.

### DE3 ✅ schtasks persistence (T1053.005)
```spl
index=botsv2 sourcetype=*ysmon* EventCode=1 CommandLine="*schtasks*Create*"
  (CommandLine="*/RU system*" OR CommandLine="*FromBase64*" OR CommandLine="*powershell*")
| rex field=_raw "<Data Name='User'>(?<User>[^<]+)" | stats count by host User
```
**Verified:** the **`Updater`** task on all **3** hosts — `venus`/`service3` (ST 10:51), `wrk-btun`/`billy.tun` (10:26), `wrk-klagerf`/`service3` (10:39), all running the same registry-sourced Empire payload (`HKLM:\Software\Microsoft\Network debug`). **Tune:** alert only when the task action is *encoded/registry-sourced* PowerShell — that's the malicious tell, not "any task created."

### DE4 ✅ C2 beacon (multi-signal) (T1071)
**Build:** correlate a newly-seen external `dst_ip` in `pan:traffic` with a Suricata hit to the same IP in a window (don't alert on one source). Fires on `45.77.65.211` (PAN 48,397 + Suricata 38,313). **Why:** single-source rare-IP alerting floods a SOC; the join makes it precise.

### DE5 ✅ SSH brute force (T1110)
```spl
index=botsv2 sourcetype=linux_secure "Failed password"
| rex "from (?<src_ip>\d+\.\d+\.\d+\.\d+)" | bin _time span=5m
| stats count by _time src_ip | where count > 20
```
**Verified:** **1,487** 5-min windows across **31** source IPs exceed the threshold — a large brute-force campaign on `gacrux`. **Escalate:** join with `"Accepted password"` from the same source to promote *brute-force-then-success*; the `klager` success came from a **different** IP, so this rule correctly treats it separately.

### DE6 ✅ Network trojan / macOS (T1071)
```spl
index=botsv2 sourcetype=suricata alert.category="A Network Trojan was detected" | stats count by src_ip alert.signature
```
Fires on **Quimitchin** from `10.0.4.2`. **Why it matters:** the Mac has no endpoint agent, so the **IDS category is your only detector** — this is how you cover an agentless host.

### DE7 ✅ Tooling drop via msiexec (T1105)
```spl
index=botsv2 sourcetype=*ysmon* EventCode=1 CommandLine="*msiexec*" (CommandLine="*c:\\temp*" OR CommandLine="*\\download\\*")
| stats count by host CommandLine
```
**Verified:** `python.msi` from `c:\temp\download` on **`venus`** (1). Legit installs rarely run MSIs out of user-temp/download paths.

### DE8 — Tune, backtest, operationalize
Backtest each rule across August: they should light up on the Aug-24 activity (and Aug-15 for C2), quiet otherwise. Attach notable metadata (title / ATT&CK / severity / data source / response). **Prefer RBA:** an APT trips *many* low-confidence rules — risk-scoring `host`/`user` surfaces `venus`/`wrk-btun`/`wrk-klagerf` far better than any single alert firing in isolation.

---

# Track 6 — Purple Team

### PT1 ✅ ATT&CK layer (verified evidence per technique)
```
T1110       SSH brute (1,487 windows / 31 IPs)     linux_secure
T1078       valid-account SSH login (klager)       linux_secure
T1059.001   Empire -enc on 3 hosts                 Sysmon (DE1)
T1027       AMSI bypass / obfuscation              Sysmon
T1047       WMI lateral (WmiPrvSE parent, 3 hosts) Sysmon (DE2)
T1053.005   schtasks "Updater" (3 hosts)           Sysmon (DE3)
T1547(reg)  payload in HKLM\...\Network debug      task action
T1071       C2 45.77.65.211:443                    PAN/Suricata/Stream
T1105       python.msi drop (venus)                Sysmon (DE7)
T1071(mac)  Quimitchin backdoor (10.0.4.2)         Suricata (DE6)
```

### PT2 ✅ Detect coverage
Detected: T1059.001 (DE1), T1047 (DE2), T1053.005 (DE3), T1071 C2 (DE4), T1110 (DE5), macOS trojan (DE6), T1105 (DE7). **Partial/Blind:** the **registry-payload write** (T1547) — the task action references it but there's no rule on the reg `SetValue`; and **macOS host-level** activity (IDS-only, no agent).

### PT3 ✅ Prevention assessment
T1059.001 → Constrained Language Mode + AMSI + script-block logging; T1047 → restrict WMI/RPC + host firewall (the lateral vector); T1110 → key-only SSH + fail2ban; T1071 → **egress filtering / TLS inspection** (the C2 walked out on 443 unimpeded); T1053.005 → block non-admin task creation.

### PT4 ✅ Rank the gaps
Earliest-break-the-chain × effort: (1) **restrict WMI lateral** (T1047) — kills the spread to venus/wrk-klagerf; (2) **egress filtering** to unknown 443 dsts — cuts the C2; (3) AMSI/CLM — blunts the agent; backups/response come later. Detecting persistence is *after* the fact — prevention upstream beats it.

### PT5 ✅ The macOS / multi-OS blind spot
`maclory-air13` has **no endpoint agent** — Quimitchin was visible only via network IDS. Recommendation: deploy macOS EDR / extend **osquery** (already present on some hosts) to the Mac. This inconsistent per-OS coverage is *how* an APT slips through.

### PT6 — Coverage matrix (deliverable)
Technique × Detect? / Prevent? / Gap / Recommendation — the leadership artifact, emphasizing the WMI + egress gaps and the macOS blind spot.

---

# Track 7 — Reporting

### R1 ✅ IOC package
```
C2        45.77.65.211 (:443, /admin/get.php, cookie MvCdddPqFQ54VL4OWU5ryRTUir8=)
Hosts     Empire agent: venus, wrk-btun, wrk-klagerf ; beaconing IPs 10.0.2.107/109, 10.0.1.100/101
Accounts  FROTHLY\billy.tun (foothold), FROTHLY\service3 (lateral), klager (Linux)
Persist   scheduled task "Updater" (x3) ; reg HKLM\Software\Microsoft\Network debug
Tooling   c:\temp\download\python.msi
Lateral   WMI (WmiPrvSE.exe)
Linux     SSH brute (1,487 windows/31 IPs: 58.242.83.20 …) ; success klager from 71.39.18.125
macOS     Quimitchin backdoor from 10.0.4.2
```

### R2 ✅ Technical report
Narrative + master timeline: **Aug 15 23:36** first C2 (`10.0.2.109`) → **Aug 24 03:29** expansion → **03:55:14** Empire stager (venus) → **04:12:36** `Updater` persistence → spread to wrk-btun/wrk-klagerf. Evidence source per step.

### R3 ✅ Executive summary (5 sentences)
APT (PowerShell Empire) compromised **3 FROTHLY hosts** via WMI lateral movement using the `service3` account; established C2 to `45.77.65.211`; persisted via a scheduled task; separate macOS backdoor + noisy internet SSH brute force observed; **dwell ≈ 9 days** (Aug 15 → 24+); no confirmed bulk data exfil (C2 tasking). No jargon.

### R4 ✅ Metrics
**Dwell ≈ 9 days** (first C2 Aug 15 → Aug 24 activity) — the APT hallmark vs. v1's 16 min. Hosts: 3 confirmed compromised, 4 beaconing IPs. Techniques: 10.

### R5 — Recommendations (ranked)
Egress/TLS inspection · restrict WMI lateral · reset `service3` + review service-account rights · macOS EDR · PowerShell logging + CLM · SSH hardening. Impact × effort.

### R6 — Intel-sharing product
STIX/MISP-style: indicators + context + confidence + recommended blocks — same facts as R3/R2, packaged for peer teams.

---

# Track 8 — Threat-Intel

### TI1 ✅ Enrichment
`| iplocation` the C2 `45.77.65.211`, the SSH brute IPs (`58.242.83.20`, …), and `71.39.18.125`. Mark data-derived vs. would-need-external (WHOIS/passive-DNS/VT on the C2 + the Empire cookie).

### TI2 ✅ Attribution (with confidence)
Framework = PowerShell **Empire** (verified from `/admin/get.php`, RC4 keying, AMSI bypass, the stager shape) — *high confidence on the framework*. Actor = **Taedonggang** (the froth.ly scenario adversary) — *scenario-level*. macOS = **Quimitchin/FruitFly**. **Framework ≠ actor** — state each confidence separately.

### TI3 ✅ Linkage analysis
Core intrusion = the Windows Empire cluster (venus/wrk-btun/wrk-klagerf, C2 `45.77.65.211`, `service3` lateral). macOS Quimitchin = a **separate** family — assess as possibly-related, don't assume. Internet SSH brute force = **background noise**, unrelated. Deliver the "core / possibly-related / noise" split without forcing links.

### TI4 — Diamond model
Adversary (Taedonggang) · Infrastructure (`45.77.65.211` Empire C2) · Capability (Empire stager, WMI lateral, schtasks+registry persistence) · Victim (FROTHLY — venus/wrk-btun/wrk-klagerf). Pivot any vertex to find more.

### TI5 ✅ Pivot
```spl
index=botsv2 45.77.65.211 | stats count by sourcetype
```
Confirms the C2 across sources; pivoting the beaconing IPs gives the blast radius + the Aug-15 first contact.

### TI6 — IOC durability (Pyramid of Pain)
C2 IP / cookie (trivial to change) → the **TTP** (Empire-over-WMI + schtasks/registry persistence) is *painful* to change. The Track-5 behaviour detections (DE2/DE3) outlast any IP blocklist — tell the manager who wants "just block the IP."

---

# Capstone — Operation Froth

Reuses the above; the value is the **handoffs** and the APT framing.
- **Phase 0 (triage):** C2 alert + SYSTEM-encoded-PowerShell persistence on a server = CRITICAL / APT-suspected, escalate.
- **Phase 1 (hunt):** Empire `-enc` on **3 hosts**, `WmiPrvSE` parent (WMI lateral, `service3`), `Updater` persistence, 4 beaconing IPs, + Linux/macOS footholds.
- **Phase 2 (network):** C2 confirmed PAN+Suricata+Stream, **443/TLS = metadata-only**; separate SSH brute noise.
- **Phase 3 (DFIR):** root cause `wrk-btun`/billy.tun → `service3` lateral; timeline Aug 15 → Aug 24.
- **Phase 4 (containment):** isolate 3 hosts, block `45.77.65.211`, remove `Updater`+registry (×3), reset `service3`.
- **Phase 5 (detection):** DE1–DE7 — **WMI-spawn (DE2) is the star**; prefer RBA.
- **Phase 6 (purple):** coverage matrix, gaps = WMI + egress + macOS blind spot.
- **Phase 7 (report):** ~9-day dwell, IOC package, exec summary.
- **Phase 8 (intel):** Taedonggang + Empire attribution; core-vs-noise linkage, no forced links.

**Lesson vs. v1:** APT response is about **patience, scope (multi-host/multi-OS), and long dwell** — not the 16-minute sprint of ransomware.

*All tracks + capstone complete — verified against the data.*
