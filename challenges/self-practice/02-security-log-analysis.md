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

**Hint:** Windows Security event IDs are exposed on the `EventCode` field. Filter and count.
**SOC angle:** Event 4625 = failed logon. Spikes indicate brute force or credential stuffing.

---

## Q17 — Successful logons

How many Windows successful-logon events (`EventCode=4624`) are present?

**Hint:** Same shape as Q16. The two counts together let you compute the success rate.
**SOC angle:** Compare the 4624 vs 4625 ratio — a 4625 spike alongside a small 4624 spike is the classic brute-force pattern.

---

## Q18 — Most-targeted accounts

Which 5 user accounts have the most failed logons?

**Hint:** Take the failed-logon search from Q16 and rank by the account field (try `user`, `Account_Name`, or use the field picker to see what's populated).
**SOC angle:** One account being hammered repeatedly = a targeted credential attack.

---

## Q19 — Sysmon process creation

How many Sysmon **process-creation** events (`EventCode=1`) are recorded?

**Hint:** Sysmon sourcetype names vary by collector config. If a naive `EventCode=1` returns zero, run `| stats count by sourcetype` (or look at the sourcetype list from Q1) and try the candidates that contain `sysmon` or `XmlWinEventLog`.
**SOC angle:** Sysmon EID 1 logs every process spawn — a primary signal for malware execution.

---

## Q20 — Parent / child process pairs

Find the 10 most frequent `(ParentImage, Image)` pairs.

**Hint:** Group process-creation events by *two* fields at once — `stats count by` accepts a list. Then rank.
**SOC angle:** Anomalous parents (e.g. `winword.exe → powershell.exe`, `outlook.exe → cmd.exe`) are high-fidelity indicators of payload execution.

---

## Q21 — Suricata alert overview

How many Suricata IDS alerts are present? Show the top 10 `alert.signature` values.

**Hint:** Suricata events live under `sourcetype=suricata` and expose `alert.signature` / `alert.signature_id` fields. Note the dot in the field name.
**SOC angle:** Signatures describe the attack technique — they are the natural starting point for any IDS-driven investigation.

---

## Q22 — High-severity IDS alerts

How many Suricata alerts have `alert.severity=1` (Suricata severity 1 = critical)?

**Hint:** Field names that contain a dot need to be quoted in the search bar so Splunk doesn't try to parse them as expressions.
**SOC angle:** Severity-1 alerts go to the top of the Tier 1 queue.

---

## Q23 — Top outbound transfers

Find the 5 source IPs that sent the most data (`bytes_out`) across all
sourcetypes that have a `bytes_out` field.

**Hint:** Don't pin a sourcetype — instead, filter to events where `bytes_out` is actually populated (`bytes_out=*`). Then sum and rank per source.
**SOC angle:** Large unexplained outbound transfers are a primary signal of data exfiltration.

---

## Q24 — HTTP POST destinations

Show the top 10 `uri_path` values for `http_method=POST`.

**Hint:** Filter on POST, rank the path.
**SOC angle:** POST endpoints are how attackers submit credentials, upload payloads, and exfiltrate.

---

## Q25 — SQL injection indicators

Find HTTP requests where `form_data` or `uri_query` contains classic SQLi
fragments: `union`, `select`, `' or '1'='1`.

**Hint:** Payloads can ride in either the query string or the POST body. Build a parenthesised `OR` group covering both fields and each SQLi token, then table the interesting columns. Wildcards (`*...*`) handle the casing/spacing variations.
**SOC angle:** SQLi remains in the OWASP Top 10 — every Tier 1 should recognize the patterns on sight.

---

## Q26 — Rare DNS queries

Find the 10 least-queried domains in DNS — these are often the most interesting.

**Hint:** `top` has a counterpart that ranks from least to most frequent.
**SOC angle:** C2 beacons and DGA-generated domains tend to appear infrequently and stand out in the rare list.

---

---

> **Switch time picker now:** `8/24/2016 00:00:00` → `8/25/2016 00:00:00`
> (ransomware day — Q27–Q30 need Sysmon-rich data)

---

## Q27 — PowerShell execution

Find all process-creation events where `Image` ends with `powershell.exe`.
Group by `ParentImage` and `User`.

**Hint:** Process paths are stored as full paths — a trailing wildcard match (`Image="*powershell.exe"`) catches both 32- and 64-bit variants. Then aggregate over two fields like Q20.
**SOC angle:** PowerShell is the universal LOLBin — `cmd.exe → powershell.exe` or `winword.exe → powershell.exe` should both raise eyebrows.

---

## Q28 — Scheduled task creation

Are there any scheduled-task creation events (`EventCode=4698`)?
If so, list them.

**Hint:** Same pattern as Q16 — filter on the EventCode, then `table` the columns that matter (time, user, task name).
**SOC angle:** Scheduled tasks are a primary persistence technique (MITRE ATT&CK T1053).

---

## Q29 — Sysmon registry modifications

How many Sysmon registry events (`EventCode` 12, 13, or 14) are recorded?
Show the 10 most-modified registry paths.

**Hint:** `EventCode IN (...)` accepts a comma-separated list. The registry path being touched is on the `TargetObject` field.
**SOC angle:** Registry Run keys are the textbook persistence mechanism (T1547.001).

---

## Q30 — Sysmon network connections

How many Sysmon network-connection events (`EventCode=3`) are recorded?
Show the 10 processes that initiated the most connections.

**Hint:** EID 3 = outbound network. The process that initiated the connection is on `Image`.
**SOC angle:** Sysmon EID 3 captures every outbound connection — invaluable for finding malware C2 callbacks.

---

✅ Finished all 15? Continue to → [03-soc-tier1-investigations.md](03-soc-tier1-investigations.md)
