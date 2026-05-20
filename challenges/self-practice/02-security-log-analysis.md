# Section 2 — Security Log Analysis (Q16–Q30)

🟡 **Level:** Beginner–Intermediate
🎯 **Goal:** Read logs from the key security sourcetypes — Windows event logs, Sysmon, Suricata IDS, DNS, and web.

> **Time picker (split by question to keep searches fast):**
>
> | Questions | Time picker | Why |
> |---|---|---|
> | **Q16–Q26** | `8/10/2016 00:00:00` → `8/11/2016 00:00:00` | Web attack day — has 4625/4624 spike, Suricata alerts, HTTP traffic |
> | **Q27–Q30** | `8/24/2016 00:00:00` → `8/25/2016 00:00:00` | Ransomware day — Sysmon-rich activity (process / registry / network) |
>
> Common sourcetypes you will see in BOTS v1: `WinEventLog`, `XmlWinEventLog`,
> `wineventlog`, `suricata`, `stream:dns`, `stream:http`, `iis`, `fgt_utm`.

---

## Q16 — Windows failed logons

How many Windows failed-logon events (`EventCode=4625`) are in the dataset?

**Hint:** `index=botsv1 EventCode=4625 | stats count`
**SOC angle:** Event 4625 = failed logon. Spikes indicate brute force or credential stuffing.

---

## Q17 — Successful logons

How many Windows successful-logon events (`EventCode=4624`) are present?

**Hint:** Same as Q16 with a different EventCode.
**SOC angle:** Compare the 4624 vs 4625 ratio — a 4625 spike alongside a small 4624 spike is the classic brute-force pattern.

---

## Q18 — Most-targeted accounts

Which 5 user accounts have the most failed logons?

**Hint:**
```spl
index=botsv1 EventCode=4625
| top limit=5 user
```
**SOC angle:** One account being hammered repeatedly = a targeted credential attack.

---

## Q19 — Sysmon process creation

How many Sysmon **process-creation** events (`EventCode=1`) are recorded?

**Hint:**
```spl
index=botsv1 sourcetype=XmlWinEventLog EventCode=1
| stats count
```
If you get zero, try `sourcetype=*sysmon*` or
`sourcetype=WinEventLog:Microsoft-Windows-Sysmon/Operational`.
**SOC angle:** Sysmon EID 1 logs every process spawn — a primary signal for malware execution.

---

## Q20 — Parent / child process pairs

Find the 10 most frequent `(ParentImage, Image)` pairs.

**Hint:**
```spl
index=botsv1 EventCode=1
| stats count by ParentImage Image
| sort - count | head 10
```
**SOC angle:** Anomalous parents (e.g. `winword.exe → powershell.exe`, `outlook.exe → cmd.exe`) are high-fidelity indicators of payload execution.

---

## Q21 — Suricata alert overview

How many Suricata IDS alerts are present? Show the top 10 `alert.signature` values.

**Hint:**
```spl
index=botsv1 sourcetype=suricata
| top limit=10 alert.signature
```
**SOC angle:** Signatures describe the attack technique — they are the natural starting point for any IDS-driven investigation.

---

## Q22 — High-severity IDS alerts

How many Suricata alerts have `alert.severity=1` (Suricata severity 1 = critical)?

**Hint:** `index=botsv1 sourcetype=suricata "alert.severity"=1 | stats count`
**SOC angle:** Severity-1 alerts go to the top of the Tier 1 queue.

---

## Q23 — Top outbound transfers

Find the 5 source IPs that sent the most data (`bytes_out`) across all
sourcetypes that have a `bytes_out` field.

**Hint:**
```spl
index=botsv1 bytes_out=*
| stats sum(bytes_out) as total_out by src_ip
| sort - total_out | head 5
```
**SOC angle:** Large unexplained outbound transfers are a primary signal of data exfiltration.

---

## Q24 — HTTP POST destinations

Show the top 10 `uri_path` values for `http_method=POST`.

**Hint:**
```spl
sourcetype=stream:http http_method=POST
| top limit=10 uri_path
```
**SOC angle:** POST endpoints are how attackers submit credentials, upload payloads, and exfiltrate.

---

## Q25 — SQL injection indicators

Find HTTP requests where `form_data` or `uri_query` contains classic SQLi
fragments: `union`, `select`, `' or '1'='1`.

**Hint:**
```spl
sourcetype=stream:http
  (form_data="*union*" OR form_data="*select*"
   OR uri_query="*union*" OR uri_query="*select*"
   OR form_data="*' or *" OR uri_query="*' or *")
| table _time src_ip uri_path form_data uri_query
```
**SOC angle:** SQLi remains in the OWASP Top 10 — every Tier 1 should recognize the patterns on sight.

---

## Q26 — Rare DNS queries

Find the 10 least-queried domains in DNS — these are often the most interesting.

**Hint:**
```spl
sourcetype=stream:dns
| rare limit=10 query
```
**SOC angle:** C2 beacons and DGA-generated domains tend to appear infrequently and stand out in the rare list.

---

---

> **Switch time picker now:** `8/24/2016 00:00:00` → `8/25/2016 00:00:00`
> (ransomware day — Q27–Q30 need Sysmon-rich data)

---

## Q27 — PowerShell execution

Find all process-creation events where `Image` ends with `powershell.exe`.
Group by `ParentImage` and `User`.

**Hint:**
```spl
index=botsv1 EventCode=1 Image="*powershell.exe"
| stats count by ParentImage User
| sort - count
```
**SOC angle:** PowerShell is the universal LOLBin — `cmd.exe → powershell.exe` or `winword.exe → powershell.exe` should both raise eyebrows.

---

## Q28 — Scheduled task creation

Are there any scheduled-task creation events (`EventCode=4698`)?
If so, list them.

**Hint:** `index=botsv1 EventCode=4698 | table _time user TaskName`
**SOC angle:** Scheduled tasks are a primary persistence technique (MITRE ATT&CK T1053).

---

## Q29 — Sysmon registry modifications

How many Sysmon registry events (`EventCode` 12, 13, or 14) are recorded?
Show the 10 most-modified registry paths.

**Hint:**
```spl
index=botsv1 EventCode IN (12,13,14)
| top limit=10 TargetObject
```
**SOC angle:** Registry Run keys are the textbook persistence mechanism (T1547.001).

---

## Q30 — Sysmon network connections

How many Sysmon network-connection events (`EventCode=3`) are recorded?
Show the 10 processes that initiated the most connections.

**Hint:**
```spl
index=botsv1 EventCode=3
| top limit=10 Image
```
**SOC angle:** Sysmon EID 3 captures every outbound connection — invaluable for finding malware C2 callbacks.

---

✅ Finished all 15? Continue to → [03-soc-tier1-investigations.md](03-soc-tier1-investigations.md)
