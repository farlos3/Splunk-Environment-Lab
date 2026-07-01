# Track 5 — Detection Engineering

Hunting finds the incident *once*; detection engineering makes sure it's
caught *automatically next time*. This track closes the loop: take findings
from Tracks 1–3 and turn each into a **tuned, documented, operational
detection**. It's one continuous build — hypothesis → rule → test on true
positives → tune out false positives → operationalize → measure coverage.

**The detection-engineering loop (apply to every exercise):**
1. **Behaviour, not IOC** — detect the *technique*, so it survives new variants.
2. **Test** it fires on the known true positive (our incident).
3. **Tune** against the benign baseline (Acronis, Nessus, admin tooling) until it's high-signal.
4. **Document** — name, ATT&CK, severity, data source, response.
5. **Operationalize** — schedule it / make it a notable / feed RBA.

> Reference detections + confirmed values: [SOLUTIONS.md](SOLUTIONS.md) (Track 5).
> The capstone's Phase 5 is a condensed version of this track.

---

### DE1 — Office spawning a script host (the root-cause detection)
**🔗 From:** Track 1 §B2 (the LOLBin chain) · **ATT&CK:** T1204.002 → T1059.005
**Build:** an Office product spawning `wscript`/`cscript`/`powershell`/`cmd`/`mshta` should never happen.
```spl
index=botsv1 EventCode=1
  (ParentImage IN ("*WINWORD.EXE","*EXCEL.EXE","*POWERPNT.EXE","*OUTLOOK.EXE"))
  (Image IN ("*wscript.exe","*cscript.exe","*powershell.exe","*cmd.exe","*mshta.exe"))
| stats count min(_time) as first values(CommandLine) as cmd by host User ParentImage Image
```
**Test:** fires on `we8105desk`/`bob.smith` at the macro time. **Tune:** the Acronis (`cscript`←`mms_mini.exe`) and Nessus (`powershell`←scanner) noise have **non-Office** parents → don't trip this rule. **Deliverable:** the rule + a note on why it's high-signal.

### DE2 — Mass file-rename to a ransomware extension
**🔗 From:** Track 1 §B7 / Track 3 §B6 (the `.cerber` writes) · **ATT&CK:** T1486
**Build:** many files gaining a new extension from one source in a short window.
```spl
index=botsv1 sourcetype=stream:smb ".cerber"
| bin _time span=1m | stats dc(filename) as files by _time src_ip
| where files > 10
```
**Design point:** this is **threshold/anomaly-based**, not signature — it would catch *any* mass-rename, not just `.cerber`. Discuss the threshold trade-off (too low = FPs on bulk copies; too high = miss slow encryptors). **Deliverable:** the rule + your chosen threshold + justification.

### DE3 — Web login brute force
**🔗 From:** Track 1 §A2 / Track 3 §A2 · **ATT&CK:** T1110
**Build:** a POST flood to the login from one source with one User-Agent.
```spl
index=botsv1 sourcetype=stream:http dest_ip="192.168.250.70" http_method=POST
| bin _time span=1m | stats count dc(http_user_agent) as uas by _time src_ip
| where count > 50 AND uas=1
```
**Tune:** `uas=1` (single automated UA) separates a tool from a busy human/proxy. **Deliverable:** the rule + how you'd set the per-minute threshold from the baseline.

### DE4 — Rare-domain / C2 callback
**🔗 From:** Track 1 §B5 / Track 3 §B2 · **ATT&CK:** T1071 / T1568
**Build:** a workstation resolving a first-seen, odd domain corroborated by IDS.
```spl
index=botsv1 sourcetype=stream:dns
| stats earliest(_time) as first count by query{} src_ip
| where first > relative_time(now(),"-1d")   /* newly-seen */
```
**Design point:** pure rarity is noisy — the real detection **joins** DNS rarity with a Suricata hit or a firewall allow (multi-signal). Sketch that correlation. **Deliverable:** the rule + why single-signal rare-domain alerts drown a SOC.

### DE5 — Run-key persistence
**🔗 From:** Track 1 §B4 · **ATT&CK:** T1547.001
**Build:** a new value written under `…\CurrentVersion\Run`.
```spl
index=botsv1 sourcetype=winregistry key_path="*CurrentVersion\\Run*" registry_type="SetValue"
| stats values(key_path) values(data) by host
```
**Tune:** allow-list known-good autostarts (`internat.exe`, vendor agents); alert on the unexpected (`osk`). **Deliverable:** the rule + a starter allow-list.

### DE6 — Tune, measure & operationalize
**🔗 Builds on DE1–DE5** · **Deliverable:** a detection you'd actually deploy.
- **Precision check:** for DE1, how many *total* hits vs. true-positive hits? Estimate precision; add exclusions if noisy.
- **Backtest:** run each rule across the whole dataset — does it fire only on the incident window, or also on benign days?
- **Operationalize:** pick each rule's schedule/cron, its **notable-event** fields (title, ATT&CK, severity), and whether it feeds **Risk-Based Alerting** (risk score on `host`/`user`) rather than a raw alert. Write the metadata block for one rule as you'd save it in Splunk ES.

---

---

## More detections (DE7–DE12)

### DE7 — Encoded / suspicious PowerShell (and taming the scanner)
**🔗 From:** Track 1 §B (PowerShell triage) · **ATT&CK:** T1059.001, T1027
**Build:** flag `-enc`/`-e`/`FromBase64`/`IEX`/`DownloadString`.
```spl
index=botsv1 EventCode=1 Image="*powershell*"
  (CommandLine="*-enc*" OR CommandLine="*FromBase64*" OR CommandLine="*IEX*" OR CommandLine="*DownloadString*")
| stats count values(CommandLine) by host User ParentImage
```
**Tune:** in v1 the PowerShell is the **Nessus** scanner (`Get-AppxPackage`, `nessus_*.TMP`) — allow-list the scanner host/parent so the rule stays high-signal. The lesson: a detection is only as good as its exclusions.

### DE8 — Web-shell / file upload to the server
**🔗 From:** Track 1 §A4 / Track 3 §A4 · **ATT&CK:** T1505.003
**Build:** content POSTed to the web root with executable/script extensions.
```spl
index=botsv1 sourcetype=stream:http dest_ip="192.168.250.70" http_method=POST part_filename=*
  (part_filename="*.php" OR part_filename="*.jsp" OR part_filename="*.aspx")
| stats count by src_ip part_filename
```
**Test:** fires on `agent.php`. **Deliverable:** rule + why upload-of-code to a web server is inherently high-signal.

### DE9 — SQL-injection in HTTP requests
**🔗 From:** Track 1 §A3 · **ATT&CK:** T1190
**Build:** injection markers in URI/body to the app. Discuss WAF-style signatures vs. anomaly (request-length, error-rate) approaches. **Deliverable:** the rule + a note on FP risk (benign strings like "select" in normal params) and how corroborating with the source IP tightens it.

### DE10 — Large outbound transfer / possible exfil
**🔗 From:** Track 1 §B8 · **ATT&CK:** T1041 / T1048
**Build:** per-host outbound byte volume far above baseline.
```spl
index=botsv1 sourcetype=fgt_traffic | stats sum(sentbyte) as out by srcip dstip
| eventstats avg(out) as a stdev(out) as s | where out > a + 3*s
```
**Design point:** statistical (z-score) detection — teaches baselining. In v1 this is a near-negative (no bulk theft), so it doubles as a **precision** lesson: does it stay quiet on a normal day?

### DE11 — Detection-as-code: version & unit-test
**🔗 Builds on DE1–DE10** · **Deliverable (design):** for one rule, define the artifacts you'd commit — the SPL, a *test event* that must fire it, an *exclusion event* that must not, the ATT&CK/severity metadata, and a version note. Mirrors ES 8.3 detection versioning: a detection is code, with tests and history.

### DE12 — Multi-signal correlation (the real C2 rule)
**🔗 From:** DE4 · **ATT&CK:** T1071
**Build:** don't alert on rare DNS alone — **correlate** it with an IDS hit or firewall allow to the same destination within a window. Sketch the `join`/`stats`-by-indicator logic across `stream:dns` + `suricata` + `fgt_traffic`. **Deliverable:** the correlation logic + why multi-signal beats single-signal for C2 (drowns fewer analysts).

### DE13 — Inhibit System Recovery (shadow-copy destruction)
**🔗 From:** the Q48 timeline (16:49:23–24) · **ATT&CK:** T1490
**Build:** ransomware destroys recovery options right before encrypting — detect it.
```spl
index=botsv1 EventCode=1
  (CommandLine="*vssadmin*delete*shadows*" OR CommandLine="*bcdedit*recoveryenabled no*"
   OR CommandLine="*wbadmin*delete*" OR CommandLine="*shadowcopy*delete*")
| table _time host User Image CommandLine
```
**Test:** fires on `we8105desk` at 16:49:23 (`vssadmin delete shadows /all /quiet`) and 16:49:24 (`bcdedit … recoveryenabled no`). **Why it's gold:** almost no legitimate software deletes *all* shadow copies — this is one of the **highest-fidelity, earliest** ransomware signals (it happens ~15 min *before* the first `.cerber` write, so it's a chance to respond before mass encryption). **Deliverable:** the rule + note that it's an *early-warning* detection, not a post-mortem one.

---

➡️ Reference detections & tuning notes: [SOLUTIONS.md](SOLUTIONS.md) (Track 5).
