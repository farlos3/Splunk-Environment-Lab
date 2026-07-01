# Specialized Tracks (BOTS v1) — Reference Walkthroughs

**Representative** methods and **confirmed** findings against `index=botsv1`.
Every track has two continuous scenarios; the steps below follow the same
order and dependencies as the exercises. If your path reached the same
finding differently, you did it right. ✅ = verified value · 🟡 = intentionally
thin, deliverable is a documented negative.

> SPL omits the time picker for brevity — set it per scenario
> (Web = `08/10/2016`, Ransomware = `08/24/2016`) or add `earliest=0`.

---

# Track 1 — Threat Hunting

## Scenario A — The Web Server Under Siege

### A1 ✅ Baseline & focus
```spl
index=botsv1 sourcetype=fgt_traffic action=deny dstport IN(22,23,3389) | stats count by srcip dstport | sort - count
index=botsv1 sourcetype=stream:http dest_ip="192.168.250.70" http_method=POST | stats count by src_ip
```
Perimeter noise (denied, distributed — e.g. `192.254.66.174` 9,641 SSH denies) is **not** the incident. The *accepted* traffic to `192.168.250.70` is dominated by **`40.80.148.42`** (~12.8k POSTs). That's your suspect.

### A2 ✅ Credential attack
```spl
index=botsv1 sourcetype=stream:http dest_ip="192.168.250.70" http_method=POST | stats count by src_ip http_user_agent
```
`40.80.148.42`, single fixed UA `Mozilla/5.0 (Windows NT 6.1; WOW64) … Chrome/41.0.2228.0 Safari/537.21`, thousands of POSTs (T1110). `| timechart span=1m count` shows machine-gun regularity → automation, not a human.

### A3 ✅ Exploitation attempts
```spl
index=botsv1 sourcetype=stream:http dest_ip="192.168.250.70" (uri="*union*" OR uri="*select*" OR uri="*'*" OR uri="*..%2f*")
| stats count by src_ip
```
Injection markers from **`40.80.148.42`** (~5,556) and **`23.22.63.114`** (~823) — same actors, so the web attack is multi-technique (T1190 + T1110), not a spray.

### A4 ✅ Upload / web shell
```spl
index=botsv1 sourcetype=stream:http dest_ip="192.168.250.70" http_method=POST part_filename=* | stats count by src_ip part_filename
```
`40.80.148.42` uploaded **`agent.php`** and **`joomla.json`** — the access→action boundary (T1505.003).

### A5 ✅ Second actor
Review post-access UAs: **`23.22.63.114`** with `Python-urllib/2.7` is the hands-on-keyboard operator, distinct from the brute-force automation.

### A6 ✅ Attribution & IOCs
Campaign = **Po1s0n1vy** APT (defacement theme). IOCs: attacker IPs `40.80.148.42`, `23.22.63.114`; UAs `Chrome/41.0.2228.0`, `Python-urllib/2.7`; uploads `agent.php`, `joomla.json`; target `192.168.250.70`. Connected story: recon → brute force → SQLi → upload → operator → attribution.

## Scenario B — Patient Zero: The Ransomware Outbreak

### B1 ✅ Initial access
```spl
index=botsv1 host=we8105desk USBSTOR | stats count by sourcetype
index=botsv1 host=we8105desk sourcetype=winregistry key_path="*USBSTOR*" key_path="*friendlyname*" | table _time key_path data
```
USB evidence is in **`winregistry`** (not Sysmon). Device `FriendlyName` = **`MIRANDA_PRI`** (`Ven_Generic&Prod_Flash_Disk`). The actual code execution arrives via a Word macro (B2).

### B2 ✅ Execution chain (LOLBin)
```spl
index=botsv1 host=we8105desk EventCode=1 User="*bob.smith*"
  (ParentImage="*WINWORD*" OR Image="*wscript.exe" OR CommandLine="*AppData*" OR CommandLine="*.vbs*" OR CommandLine="*.tmp*")
| table _time ParentImage Image CommandLine | sort _time
```
`WINWORD.EXE → cmd.exe → wscript.exe` running `…\AppData\Roaming\20429.vbs` (16:43:21) → `121214.tmp` (16:48:21). T1059.005 / T1204.002.

### B3 ✅ Triage the noise
The `cscript.exe` + `.vbs` from `C:\Windows\TEMP` as `NT AUTHORITY\SYSTEM` is **Acronis backup**; the `powershell "Get-AppxPackage…"` writing `nessus_*.TMP` is a **credentialed Nessus scan**. Both benign — confidently explaining them away is the hunt (scoping to `bob.smith` removes the Acronis bait).

### B4 ✅ Persistence
```spl
index=botsv1 sourcetype=winregistry key_path="*CurrentVersion\\Run*" | stats count by key_path data
```
Cerber hijacks **`…\CurrentVersion\Run\osk`** (T1547.001). No attacker scheduled task — Run key is the mechanism. (`internat.exe` Run entry = legit Windows.)

### B5 ✅ C2 channel
```spl
index=botsv1 sourcetype=suricata Cerber | stats count by alert.signature_id alert.signature | sort count
index=botsv1 sourcetype=stream:dns src_ip="192.168.250.100" "query{}"="*xmfir0*"
```
C2 = **`cerberhhyed5frqa.xmfir0.win`**; Suricata sigs **2816763** (`Checkin 2`, ×1 — the callback), **2816764** (×2), **2820156** (`Onion Domain Lookup`, ×2); firewall `accept`ed the egress (B8/N5).

### B6 ✅ Defense evasion
```spl
index=botsv1 host=we8105desk EventCode=1 (Image="*taskkill*" OR CommandLine="*del *") CommandLine="*.tmp*"
```
`cmd /d /c taskkill /t /f /im "121214.tmp" … & del "…\121214.tmp"` — self-deletion (T1070.004). The `ping -n 1 127.0.0.1` is a deliberate sleep so delete runs after exit.

### B7 ✅ Impact
```spl
index=botsv1 sourcetype=stream:smb src_ip="192.168.250.100" | stats count by dest_ip
index=botsv1 sourcetype=stream:smb dest_ip="192.168.250.20" filename="*.pdf" | stats dc(filename)
```
File server **`192.168.250.20`**; **22** PDFs encrypted (`filename="*.pdf"` — the loose `"*.pdf*"` wrongly reports 23 via `windows.data.pdf.dll`); **125** `.cerber` files; `# DECRYPT MY FILES #` notes per folder; first `.cerber` write **17:04:33** (T1486).

### B8 ✅ Exfil vs. impact
```spl
index=botsv1 sourcetype=fgt_traffic srcip="192.168.250.100" | stats count by action
```
Outbound was **`accept`ed** but no bulk transfer — this is **impact (T1486)**, not exfiltration (T1041). Full chain: USB/macro → LOLBin → persistence → C2 → self-delete → SMB encryption.

### Negative checks (score as ✅ if documented)
🟡 no log-clearing (`1102`); 🟡 no LSASS cred-dump (Sysmon EID 10 sparse); 🟡 it hit a *file share*, not `ADMIN$`/`C$`; ✅ TTP sweep across all hosts returns **only `we8105desk`** → contained.

---

# Track 2 — DFIR

## Case A — Web Server Intrusion
- **A1 ✅ Scope** — asset `192.168.250.70`; attacker `40.80.148.42` over HTTP; unknowns = access method + action.
- **A2 ✅ Root cause** — brute-forced CMS admin (one UA, ~12.8k POSTs) + SQLi probing; root cause = internet-exposed admin with a guessable password.
- **A3 ✅ Action-on-objective** — uploads `agent.php`/`joomla.json`; second actor `23.22.63.114` drives the operator stage / defacement.
- **A4 ✅ Attribution** — **Po1s0n1vy** APT, high confidence (defacement theme + attacker IP).
- **A5 — Report/control** — exec summary + earliest-breaking control = account lockout / rate-limit + WAF at the credential-attack stage.

## Case B — Cerber Ransomware
- **B0 ✅** — `| metadata type=sourcetypes index=botsv1`: ~25 sourcetypes (endpoint/wire/IDS/firewall/vuln). Gaps: no memory, no EDR, thin mail.
- **B1 ✅** — victim `we8105desk`; human user `bob.smith` (strip `NT AUTHORITY\*`); `t0` = 16:43:21 macro (not the 17:04 encryption alert).
- **B2 ✅** — tree `WINWORD→cmd→wscript(20429.vbs)→121214.tmp`; vector = malicious Word macro.
- **B3 ✅** — timeline: 16:43:21 execution · 16:48:12 DNS download · 16:48:21 payload · ~16:48 C2 · 17:04:33 encryption.
- **B4 ✅** — macro = env-var/`set` obfuscation + `WScript.Sleep` sandbox evasion + `MSXML2.XMLHTTP`/`ADODB.Stream` download. IOCs: `20429.vbs`, `solidaritedeproximite.org`.
- **B5 ✅** — `121214.tmp`: spawns cmd children, drives SMB encryption, self-deletes → T1204→T1486→T1070.004.
- **B6 ✅** — eradication list: Run-key `…\Run\osk`, delete `121214.tmp` + `20429.vbs`, purge `# DECRYPT MY FILES #`; re-image.
- **B7 ✅** — local profile + **22 PDFs** on `192.168.250.20`; **125** `.cerber`.
- **B8 ✅** — TTP sweep → only `we8105desk` → **contained**.
- **B9 ✅** — `bob.smith` active (`4624`); no privileged (`4672`) logon in window → limited lateral risk.
- **B10 🟡** — no `1102`/Sysmon-stop → "no anti-forensics observed" (smash-and-grab, not stealthy APT).
- **B11 ✅** — Acronis backups present; anything backed up before 17:04:33 is restorable; re-image + restore.
- **B12 ✅** — dwell ≈ **16.3 min** (16:48:12→17:04:33; ~21 min if `t0`=16:43 macro — state your choice). ATT&CK: T1566/T1204→T1059.005→T1547.001→T1070.004→T1071/T1568→T1021.002→**T1490 (vssadmin/bcdedit, 16:49)**→T1486.
```spl
index=botsv1 (sourcetype=stream:dns "query{}"="*solidarite*") OR (sourcetype=stream:smb ".cerber")
| eval m=if(sourcetype=="stream:dns","t0","t1") | stats min(_time) as ts by m
| stats min(eval(if(m=="t0",ts,null()))) as t0 min(eval(if(m=="t1",ts,null()))) as t1
| eval dwell_min=round((t1-t0)/60,1)
```

---

# Track 3 — Network Forensics

## Scenario A — Anatomy of the Web Attack
- **A1 ✅** — `fgt_traffic | stats sum(sentbyte) by srcip dstip` (fields `srcip`/`dstip`/`sentbyte`); top external talker to `192.168.250.70` = `40.80.148.42`.
- **A2 ✅** — HTTP brute force `40.80.148.42`, fixed UA `Chrome/41.0.2228.0`, machine-gun `timechart` cadence.
- **A3 ✅** — `stats count by status` shows error/probe spikes; injection markers in URIs (union/select/`'`/`..%2f`); a `200` after failures = success.
- **A4 ✅** — uploads `agent.php`, `joomla.json` via `part_filename`.
- **A5 🟡** — `iis` vs `stream:http` counts differ (server-side app log vs. raw wire) — explain the delta, don't "reconcile to equal."
- **A6 🟡** — `| iplocation` the actor IPs (`40.80.148.42` Azure/US, `23.22.63.114` AWS/US); set apart from denied SSH/Telnet perimeter scans.

## Scenario B — Tracking the Ransomware
- **B1 ✅ (method)** — `stream:dhcp` maps `192.168.250.100` ↔ `we8105desk` (+MAC) — attribution glue for dynamic IPs.
- **B2 ✅** — DNS via `query{}` + `regex "\."`, earliest-per-domain: **`solidaritedeproximite.org`** (16:48:12, download) + **`cerberhhyed5frqa.xmfir0.win`** (ransom portal).
- **B3 ✅** — `query_type{}` mix normal (A/PTR, no TXT tunneling); `*xmfir0* | timechart span=1m` → resolves only a couple of times = **one-shot, not a long beacon**.
- **B4 ✅** — Suricata sigs 2816763/2816764/2820156 confirm C2; firewall shows the flow.
- **B5 ✅** — `fgt_traffic … | stats count by action`: `accept` **29,112**, `ip-conn` 6,179, `deny` 169, `close` 19 → C2 egress **allowed** (the control gap).
- **B6 ✅** — SMB to `192.168.250.20`; `*.pdf` reads (recon) → `.cerber` writes (impact); first write **17:04:33**.
- **B7 🟡** — `stream:icmp`: normal size/volume, no tunneling → clean negative.
- **B8 ✅** — capstone: `(stream:dns OR suricata OR fgt_traffic) cerberhhyed5frqa.xmfir0.win | stats count by sourcetype` → three sources on one indicator = report-grade finding.

---

# Track 5 — Detection Engineering
- **DE1 ✅** Office→script-host (SPL in the capstone Phase 5 below). High-signal: Acronis/Nessus noise has non-Office parents. Map T1204.002→T1059.
- **DE2 ✅** mass-rename threshold: `stream:smb ".cerber" | bin _time span=1m | stats dc(filename) by _time src_ip | where files>10`. Behaviour-based → catches any encryptor; tune threshold vs. bulk-copy FPs.
- **DE3 ✅** brute force: POST rate to `192.168.250.70` with `dc(http_user_agent)=1` isolates automation (`40.80.148.42`).
- **DE4 ✅** C2: newly-seen `query{}` **joined** with a Suricata/firewall hit — single-signal rare-domain alone is too noisy for a SOC.
- **DE5 ✅** persistence: `winregistry …\Run` new `SetValue`; allow-list `internat.exe`, alert on `osk`.
- **DE6** operationalize: backtest each rule (fires only in the incident window), attach notable metadata (title/ATT&CK/severity), prefer RBA risk-scoring on `host`/`user` over raw alerts.
- **DE7 ✅** encoded PowerShell — allow-list the Nessus scanner (`Get-AppxPackage`/`nessus_*`) so the rule stays high-signal. T1059.001.
- **DE8 ✅** web upload — `part_filename IN (*.php,*.jsp,*.aspx)` to `192.168.250.70` fires on `agent.php`. T1505.003.
- **DE9** SQLi — URI injection markers; FP-prone on benign params → require source-IP corroboration. T1190.
- **DE10** exfil — z-score on `sum(sentbyte)` by host; near-negative in v1 → precision/baseline lesson.
- **DE11** detection-as-code — commit SPL + a must-fire test event + a must-not-fire exclusion + ATT&CK/severity + version note.
- **DE12** correlation — join rare DNS + Suricata + firewall on the C2 indicator within a window; multi-signal beats single-signal.
- **DE13 ✅** Inhibit System Recovery — `CommandLine=*vssadmin*delete*shadows*` / `*bcdedit*recoveryenabled no*`; fires at 16:49:23-24, ~15 min *before* encryption → high-fidelity **early-warning** (T1490).

# Track 6 — Purple Team
- **PT1 ✅** ATT&CK layer: T1566/T1204→T1059.005→T1547.001→T1070.004→T1071/T1568→T1021.002→**T1490**→T1486.
- **PT2 ✅** detect coverage: T1204 (DE1), T1486 (DE2), T1547.001 (DE5) = **Detected**; T1070.004 = **Partial** (logged, no rule); T1003 = **Blind**.
- **PT3 ✅** prevention: ASR "block Office child processes" kills T1204; egress filtering would block the C2 the firewall *accepted*; Acronis backups mitigate T1486.
- **PT4 ✅** gap ranking: ASR (breaks chain at Execution) > egress filtering (C2) > backups (Impact/recovery only).
- **PT5/PT6** emulation & validation (design): map to Atomic Red Team atomics (T1204.002, T1547.001); with ASR on, the child process never spawns → DE1 goes quiet (prevention > detection).
- **PT7** deliverable = Technique × Detect/Prevent/Gap/Recommendation matrix.
- **PT8 ✅** web-incident layer: T1595→T1110→T1190→T1505.003→T1491; network detections (IDS/HTTP) catch the web attack earlier than endpoint would.
- **PT9 ✅** layers: v1 is strong at perimeter+network+endpoint, **thin at identity** (no MFA/EDR telemetry).
- **PT10 ✅** assume-breach: network alone (DHCP→DNS→Suricata→SMB) reconstructs most of Incident B but loses the process tree + persistence.
- **PT11** metrics: % techniques Detected/Partial/Blind + kill-chain stages caught before impact.
- **PT12** regression: write the T1070.004 detection → flip its matrix cell Partial→Detected.

# Track 7 — Reporting
- **R1 ✅** IOC package: domains `solidaritedeproximite.org`, `cerberhhyed5frqa.xmfir0.win`; files `20429.vbs`, `121214.tmp`, `*.cerber`; Run-key `osk`; USB `MIRANDA_PRI`; server `192.168.250.20`; sigs 2816763/64/2820156.
- **R2 ✅** technical report = the master timeline (16:43:21→17:04:33) + narrative + evidence source per step.
- **R3 ✅** exec summary: Cerber on `we8105desk`/`bob.smith`, ~16 min dwell, email-macro vector, 22 PDFs + local files encrypted, recoverable from backup — 5 sentences, no jargon.
- **R4 ✅** metrics: dwell ≈16 min (state t0), blast radius 1 host / 1 share / 22 docs.
- **R5** recommendations: DE1 detection, ASR, egress filtering, backup verification — ranked impact×effort.
- **R6** intel-sharing brief: same facts, STIX/MISP-style structured indicators + context + actions (contrast tone vs. R3/R2).
- **R7 ✅** web-incident report (Incident A): IOCs `40.80.148.42`/`23.22.63.114`/`agent.php` + timeline + exec summary.
- **R8** timeline viz: Time·Stage·What·Evidence table; omit btool/service-account noise.
- **R9** evidence log: sourcetype · time range · what it proved · when pulled; note it's a live index, not a preserved image.
- **R10** in-incident update: 3 lines — confirmed / containing / unknown; honest about uncertainty.
- **R11** blameless retro: went-well / slow (16-min dwell, C2 allowed out) / 3 action items with owners.
- **R12** dashboard spec: dwell, MTTD/MTTR, incidents by severity, top techniques (+ feeding SPL).

# Track 8 — Threat-Intel Pivot
- **TI1 ✅** enrich via `iplocation` (`40.80.148.42` Azure/US, `23.22.63.114` AWS/US, C2); mark data-derived vs. would-need-external (WHOIS/VT).
- **TI2 ✅** attribution: A = **Po1s0n1vy** APT (high confidence, defacement + IP); B = **Cerber** family (family-level, from `.cerber`/`*.xmfir0.win`/sigs).
- **TI3 ✅** linkage verdict = **NOT linked** — no shared infra/TTP/timing; targeted APT vs. commodity ransomware. Discipline: don't force a connection.
- **TI4** Diamond model of Incident B (adversary/infra/capability/victim).
- **TI5 ✅** pivot: `(stream:dns OR fgt_traffic) <indicator> | stats count by src_ip` → only `we8105desk` touched the C2 → confirms scope.
- **TI6** intel product = actor/family + contextualized IOCs + confidence + linkage + recommended blocks.
- **TI7 ✅** Po1s0n1vy actor card: IPs `40.80.148.42`/`23.22.63.114`, UAs `Chrome/41.0.2228.0`+`Python-urllib`, `agent.php`, defacement theme.
- **TI8** Pyramid of Pain: hash/filename (trivial) → IP/domain (easy) → tools/UA (annoying) → TTP (painful); Track-5 behaviour rules outlast IP blocklists.
- **TI9** intel→detection: turn "Cerber uses `*.xmfir0.win`/`.cerber`/macro-VBS" into a hunt + a rule for your data.
- **TI10** family tracking: watch durable indicators (infra pattern, `.cerber`, ransom-note format) via lookups.
- **TI11** feed integration: indicators → lookup → auto-match on `stream:dns`/`fgt_traffic` → notable.
- **TI12** confidence/sourcing: label attribution high/moderate/low + Admiralty grade; state what evidence moves it.

---

# Capstone — Full-Spectrum Incident

Phases 0–4 and 6–8 reuse findings already confirmed above — pull them from the
relevant track section (Phase 1 = Track 1 §B, Phase 2 = Track 3 §B, Phase 3 =
Track 2 Case B, Phase 8 = Track 2 Case A / Track 1 §A). Only the genuinely new
deliverable — the **Phase 5 detection** — is detailed here.

### Phase 0 — Triage
`.cerber` writes to `192.168.250.20` starting ~17:04 from client `192.168.250.100`; **CRITICAL, escalate**. The source client IP is your pivot into Phase 1.

### Phase 5 — Detection engineering (the reusable rule)
```spl
index=botsv1 EventCode=1
  (ParentImage IN ("*WINWORD.EXE","*EXCEL.EXE","*POWERPNT.EXE","*OUTLOOK.EXE"))
  (Image IN ("*wscript.exe","*cscript.exe","*powershell.exe","*cmd.exe","*mshta.exe"))
| stats count min(_time) as first values(CommandLine) as cmd by host User ParentImage Image
```
**Why it works:** the root cause was Word spawning a shell/script host — legitimate Office use never does this, so it's a high-signal behaviour (T1566/T1204 → T1059). Fires on `we8105desk`/`bob.smith` at the macro time; the Acronis (`cscript`←`mms_mini.exe`) and Nessus (`powershell`←scanner) noise from Phase 1 has **non-Office** parents, so it does *not* trip this rule — that's the tuning check.
**Detection metadata to record:** name `Office Application Spawning Script Host / Shell`; ATT&CK T1204.002/T1059; severity High; data source Sysmon EID 1; response = isolate host + triage parent document. Save as a scheduled search / correlation search.
**Control tie-in (Phase 6):** the same behaviour is blocked outright by the Microsoft ASR rule *"Block Office applications from creating child processes"* — detection + prevention for one TTP.

### Phase 8 — Intel pivot (linkage call)
Web intrusion (Po1s0n1vy, `40.80.148.42`, defacement) and the Cerber ransomware share **no** infrastructure, tooling, or timing overlap — two independent incidents two weeks apart. Correct answer = **"not linked,"** with the discipline to not manufacture a connection the evidence doesn't support.

---

*Confirmed against the running lab. Numbers may shift slightly with a wider time window. 🟡 items are intentionally thin — a documented negative is a valid analyst result.*
