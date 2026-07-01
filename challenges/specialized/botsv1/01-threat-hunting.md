# Track 1 — Threat Hunting (Hypothesis-Driven, MITRE ATT&CK)

Threat hunting is **proactive**: you assume the alert didn't fire and go
looking anyway. This track runs **two continuous scenarios** — each is a
*single connected hunt*, ordered along the kill chain, where every step
**builds on** the finding before it. Do a scenario top-to-bottom as one
investigation, not as isolated questions.

**Ground rules**
- Write the hypothesis and the expected evidence *before* you search.
- Baseline first ("what's normal here?") so the anomaly stands out.
- A hit is a *lead* — confirm with a second source before calling it a finding.
- Carry every IOC + timestamp forward; the later steps depend on them.

> Reference method + confirmed findings: [SOLUTIONS.md](SOLUTIONS.md)

---

# Scenario A — "The Web Server Under Siege" (2016-08-10)

*A public web server, `imreallynotbatman.com` (`192.168.250.70`), is behaving
oddly. Hunt the intrusion from first contact to attacker action.* Window:
`08/10/2016:00:00:00` → `08/11/2016:00:00:00`.

### A1 — Establish the baseline & spot the focus
**ATT&CK:** T1595 (Active Scanning) · **Data:** `fgt_traffic`, `stream:http`
**Hypothesis:** if the server is targeted, one external source stands out from the internet's background scanning.
**Method:** separate perimeter noise (`fgt_traffic action=deny dstport IN(22,23,3389)` — distributed, denied) from traffic *accepted* to `192.168.250.70`. Who is actually talking to the web app, and how much?
**Builds toward:** the top talker you find here is your prime suspect for A2.

### A2 — Hunt the credential attack
**🔗 Builds on A1** (the suspect IP + target) · **ATT&CK:** T1110
**Hypothesis:** the suspect is brute-forcing the CMS login — expect a POST flood with a single automated User-Agent.
**Method:** `sourcetype=stream:http dest_ip="192.168.250.70" http_method=POST | stats count by src_ip http_user_agent`. Confirm one source dominates; fingerprint its UA. `| timechart span=1m count` to see machine-gun cadence.
**Carry forward:** the attacker IP + UA (you'll separate this actor from a second one in A5).

### A3 — Hunt exploitation attempts
**🔗 Builds on A2** (same attacker) · **ATT&CK:** T1190
**Hypothesis:** password-guessing wasn't the only technique — look for injection.
**Method:** hunt SQLi/traversal markers to the server: `(uri="*union*" OR uri="*select*" OR uri="*'*" OR uri="*..%2f*")`. Does the same IP from A2 appear? Multi-technique = a determined actor, not a spray.

### A4 — Did they get in? Hunt the upload
**🔗 Builds on A2/A3** · **ATT&CK:** T1505.003 (Web Shell), T1105
**Hypothesis:** successful access shows up as *content being POSTed to the server* (not just login attempts).
**Method:** `dest_ip="192.168.250.70" http_method=POST part_filename=* | stats count by src_ip part_filename`. What filenames were uploaded? This is the access→action boundary.
**Carry forward:** the uploaded artifact names (IOCs for the report).

### A5 — Hunt the second actor
**🔗 Builds on A4** · **ATT&CK:** T1071
**Hypothesis:** the "hands-on-keyboard" stage often uses a *different* source/tool than the noisy brute-forcer.
**Method:** review the User-Agents and source IPs interacting post-access. A second IP with a scripting UA (e.g. `Python-urllib`) marks the operator stage — distinguish *automated access* from *human action-on-objective*.

### A6 — Attribution & IOC wrap-up
**🔗 Builds on A1–A5** · **ATT&CK:** T1591 (intel)
**Deliverable:** consolidate the campaign — both attacker IPs, the tool UAs, uploaded files, and the group behind the defacement theme. You now have one connected story: recon → brute force → exploitation → upload → operator → attribution.

---

# Scenario B — "Patient Zero: The Ransomware Outbreak" (2016-08-24)

*Files on `we8105desk` (`192.168.250.100`, user `bob.smith`) are being
encrypted. Hunt the full chain from initial access to impact.* Window:
`08/24/2016:00:00:00` → `08/25/2016:00:00:00`.

### B1 — Hunt the initial-access vector
**ATT&CK:** T1200 (Hardware Additions), T1566.001 · **Data:** `winregistry`, Sysmon
**Hypothesis:** something was introduced — a USB device and/or a malicious document.
**Method:** find where USB evidence lives (`host=we8105desk USBSTOR | stats count by sourcetype` → it's `winregistry`, not Sysmon), then pull the device `FriendlyName`. Separately, note whether an Office document is about to spawn processes (feeds B2).
**Carry forward:** the device name + the suspicion that a macro is the entry.

### B2 — Hunt the execution chain (LOLBin)
**🔗 Builds on B1** · **ATT&CK:** T1059.005, T1204.002
**Hypothesis:** malware ran through a trusted script host, launched by Office.
**Method:** scope to the user, then filter should-never-happen behaviour: `EventCode=1 User="*bob.smith*" (ParentImage="*WINWORD*" OR Image="*wscript*" OR CommandLine="*AppData*" OR CommandLine="*.vbs*" OR CommandLine="*.tmp*")`. Walk the parent→child tree.
**Carry forward:** the dropper script name + the payload name.

### B3 — Triage the noise (separate benign from malicious)
**🔗 Builds on B2** · **ATT&CK:** N/A (analyst skill)
**Hypothesis:** some "suspicious" activity is authorized tooling.
**Method:** explain away the `cscript.exe` + `.vbs` from `C:\Windows\TEMP` running as `NT AUTHORITY\SYSTEM` (Acronis backup) and the `Get-AppxPackage`/`nessus_*.TMP` PowerShell (credentialed Nessus scan). Confidently dismissing false positives *is* the hunt.

### B4 — Hunt persistence
**🔗 Builds on B2** · **ATT&CK:** T1547.001, T1053.005
**Hypothesis:** the malware set an auto-start to survive reboot.
**Method:** `sourcetype=winregistry key_path="*CurrentVersion\\Run*" | stats count by key_path data` (watch for a hijacked accessibility binary); also check scheduled tasks (`4698`) and confirm which the adversary actually used.
**Carry forward:** the persistence artifact (needed for eradication).

### B5 — Hunt the C2 channel
**🔗 Builds on B2** · **ATT&CK:** T1071, T1568
**Hypothesis:** the payload calls home to a rare domain.
**Method:** rare-domain hunt in DNS from the host, then corroborate across **three** sources — DNS resolution + Suricata signature + firewall allow. One indicator, three views = a finding.
**Carry forward:** the C2 domain + first-seen time.

### B6 — Hunt defense evasion
**🔗 Builds on B2** · **ATT&CK:** T1070.004
**Hypothesis:** the payload cleans up after itself.
**Method:** `EventCode=1 (Image="*taskkill*" OR CommandLine="*del *") CommandLine="*.tmp*"` — find the payload killing and deleting itself. (Note the `ping 127.0.0.1` sleep trick.)

### B7 — Hunt the impact
**🔗 Builds on B2** · **ATT&CK:** T1021.002, T1486
**Hypothesis:** the host reached a file server and encrypted files there.
**Method:** SMB sessions from the host → the server; count the **original** documents (careful: `filename="*.pdf"`, not `"*.pdf*"`); then the `.cerber` artifacts + `# DECRYPT MY FILES #` notes. Timestamp the first `.cerber` write.
**Carry forward:** file-server IP, impact counts, encryption start time.

### B8 — Characterize exfil vs. impact + close the loop
**🔗 Builds on B5/B7** · **ATT&CK:** T1041 vs T1486
**Deliverable:** was data *stolen* or just *encrypted*? Check outbound volume on the firewall — here the egress is C2 signalling, not bulk theft, so this is **impact (T1486)**, not exfiltration. Then assemble the connected chain: USB/macro → LOLBin → persistence → C2 → evasion → impact.

> **Negative checks along the way (score them too):** during Scenario B, also confirm what *didn't* happen — no event-log clearing (`1102`), no LSASS credential dumping (Sysmon EID 10), no `ADMIN$`/`C$` lateral movement (it hit a file share, not admin shares), no spread to other hosts. A documented negative is a real finding.

---

➡️ Method + confirmed findings: [SOLUTIONS.md](SOLUTIONS.md) (Track 1).
