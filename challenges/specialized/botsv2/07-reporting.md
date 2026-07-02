# Track 7 — Reporting & Communication (BOTS v2 / froth.ly APT)

Turn the investigation into the IR deliverables package — for responders,
management, and peer teams. An APT report must convey **dwell time** and
**multi-surface scope** clearly, since that's what makes it serious.

> Reference templates: [SOLUTIONS.md](SOLUTIONS.md) (Track 7).

---

### R1 — IOC package
**🔗 From:** all tracks. Typed indicator list:
```
C2        : 45.77.65.211 (:443, /admin/get.php), session cookie MvCdddPqFQ54VL4OWU5ryRTUir8=
Hosts     : venus (Empire agent); beaconing 10.0.2.107/109, 10.0.1.100/101
Persist   : schtasks "Updater"; reg HKLM\Software\Microsoft\Network debug
Tooling   : c:\temp\download\python.msi
Accounts  : FROTHLY\billy.tun, amber.turing, klager
Linux     : SSH brute 58.242.83.20 / 116.31.116.17 / …; success klager from 71.39.18.125
macOS     : Quimitchin backdoor from 10.0.4.2
```

### R2 — Technical incident report
**🔗 Builds on R1 + Track 2.** Narrative + master timeline (first C2 **Aug 15**, Empire on venus **Aug 24 03:55**, persistence **04:12**), evidence source per step, for a fellow analyst.

### R3 — Executive summary (5 sentences)
**🔗 Builds on R2.** What (APT / PowerShell Empire foothold + multi-OS activity), Where (FROTHLY, host venus + others), When + **dwell (~9 days: Aug 15→24+)**, How (WMI lateral → Empire → C2), Impact (compromise + C2 established; assess exfil). No jargon.

### R4 — Metrics & KPIs
**🔗 Builds on R2.** **Dwell time** (Aug 15 first C2 → detection) — far longer than v1's 16 min, the hallmark of an APT. Time-to-detect/contain, hosts affected (4 beaconing), techniques observed. State your `t0`.

### R5 — Lessons learned & recommendations
**🔗 Builds on Track 5/6.** Ranked: egress filtering / TLS inspection (C2 walked out on 443), restrict WMI lateral, macOS EDR (the blind spot), PowerShell script-block logging + CLM, SSH hardening. Impact × effort.

### R6 — Peer / intel-sharing product
**🔗 Builds on R1.** Structured brief (STIX/MISP-style) — indicators + context + confidence + recommended blocks — for sharing. Same facts, three audiences (R3 execs / R2 analysts / R6 peers).

---

➡️ Reference templates: [SOLUTIONS.md](SOLUTIONS.md) (Track 7).
