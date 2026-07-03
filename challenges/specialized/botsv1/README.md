# Specialized Tracks (BOTS v1) — Threat Hunting · DFIR · Network Forensics

> 📦 **Dataset: BOTS v1.** This folder holds the specialized tracks built on the
> `botsv1` index (loaded by `./setup.sh`). Tracks for other datasets live as
> siblings under [`../`](../) — e.g. a future `../botsv3/` for the AWS/O365
> cloud incident. Everything below assumes BOTS v1 is loaded.

Three **advanced, methodology-driven** tracks that go beyond the guided
Q&A packs in [`../../self-practice/`](../../self-practice/) and
[`../../2026 Splunk BOTS Training/`](../../2026%20Splunk%20BOTS%20Training/).

The difference matters:

| Guided Q&A packs | These specialized tracks |
|---|---|
| "Here's a question — find the one answer." | "Here's a **hypothesis / a case** — run the *process*." |
| Graded on the value you find | Graded on **how you hunt / investigate** |
| Single sourcetype per question | **Pivot across many sourcetypes** to build a picture |
| Answer is the goal | The **method** is the goal; the answer confirms it |

You should already be comfortable with SPL and the BOTS v1 sourcetypes
(finish `self-practice` Q1–Q30 first). These tracks assume you can write
`stats`, `rex`, `eval`, and pivot between indexes without hand-holding.

---

## The three tracks

| File | Track | What you practice |
|---|---|---|
| [01-threat-hunting.md](01-threat-hunting.md) | **Threat Hunting** | 2 continuous scenarios (Web Siege · Ransomware), hypothesis-driven, MITRE ATT&CK — 14 chained hunts |
| [02-dfir.md](02-dfir.md) | **DFIR / Investigation** | 2 continuous IR cases (Web Intrusion · Cerber), full lifecycle scope→report — 18 chained steps |
| [03-network-forensics.md](03-network-forensics.md) | **Network Forensics** | 2 continuous scenarios (Web on the wire · Ransomware), flows→protocol→payload — 14 chained steps |
| [05-detection-engineering.md](05-detection-engineering.md) | **Detection Engineering** | Turn findings into tuned, operational detections — behaviour rules, FP tuning, notable/RBA metadata |
| [06-purple-team.md](06-purple-team.md) | **Purple Team** | Attack↔defense validation — ATT&CK coverage, detect-vs-prevent matrix, ranked control gaps, emulation plan |
| [07-reporting.md](07-reporting.md) | **Reporting & Communication** | The IR deliverables package — IOCs, technical report, exec summary, metrics, intel-sharing product |
| [08-threat-intel.md](08-threat-intel.md) | **Threat-Intel Pivot** | Enrichment, attribution with confidence, linkage analysis, Diamond model, indicator pivoting |
| [04-capstone-full-incident.md](04-capstone-full-incident.md) | **Capstone (all tracks)** | One big use case fusing every discipline — SOC triage → hunt → network → DFIR → detection engineering → purple-team → reporting → intel pivot |
| [SOLUTIONS.md](SOLUTIONS.md) | — | Reference walkthroughs — *representative* method + confirmed findings, not the only valid path |

---

## The two BOTS v1 incidents these tracks use

Everything below is real activity in `index=botsv1`. Both tracks reuse them.

**Incident A — Web server intrusion & defacement (2016-08-10)**
- Target: `imreallynotbatman.com` web server at **`192.168.250.70`**
- Attacker (Po1s0n1vy APT), two tools: Acunetix scan + SQLi + the web-shell upload and successful `batman` login from **`40.80.148.42`** (Chrome/41 UA); the credential **brute force** from **`23.22.63.114`** (`Python-urllib`, 412 password POSTs)
- Time window: `08/10/2016:00:00:00` → `08/11/2016:00:00:00`

**Incident B — Cerber ransomware (2016-08-24)**
- Victim: **`we8105desk`** (`192.168.250.100`, user `WAYNECORPINC\bob.smith`)
- Chain: Word macro → `cmd.exe` → `wscript.exe` (`20429.vbs`) → `solidaritedeproximite.org` → `121214.tmp` → SMB encryption on file server **`192.168.250.20`**
- Time window: `08/24/2016:00:00:00` → `08/25/2016:00:00:00`

> ⏱️ **Always set the time picker to the right day** (or inline `earliest`/`latest`). A "no results" almost always means the wrong window, not wrong SPL.

---

## Available data sources (from `| tstats count where index=botsv1 by sourcetype`)

```
Endpoint      : XmlWinEventLog:...Sysmon/Operational, WinEventLog:Security/System/Application, winregistry
Network (wire): stream:tcp, stream:ip, stream:dns, stream:smb, stream:http, stream:ldap, stream:icmp, stream:mapi, stream:dhcp
Network (IDS) : suricata
Firewall      : fgt_traffic, fgt_utm, fgt_event   (Fortigate)
Web server    : iis, stream:http
Vuln scan     : nessus:scan
```

> ⚠️ **Sysmon field extraction note:** this lab has no `Splunk_TA_windows`, so Sysmon fields
> (`EventCode`, `Image`, `CommandLine`, …) are supplied by the local add-on
> `docker/apps/bots_sysmon_extractions/`. If those fields ever come back empty, that add-on
> isn't loading — not "no data."

---

## How to work a hunt / case

1. **State your hypothesis or objective out loud** before touching SPL. ("An attacker abused a script host to run code" → I expect `wscript`/`cscript` spawning from Office or writing to a user profile.)
2. **Pick the data source that would carry that evidence.** Guess wrong? `| stats count by sourcetype` tells you where the artifact really lives.
3. **Cast wide, then funnel.** Start broad, cut noise a layer at a time (scope to a host/user, drop service accounts, filter on "should-never-happen" behaviour). Never scroll hundreds of rows by hand.
4. **Corroborate across sources.** One event is a lead, not a conclusion. A DNS lookup + a firewall allow + a Suricata alert for the same domain is a finding.
5. **Record every IOC and timestamp** as you go — they become the timeline and the report.

The SOLUTIONS file shows one defensible path per exercise. If your method reaches the same finding differently, you did it right.
