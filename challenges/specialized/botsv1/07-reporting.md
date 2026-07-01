# Track 7 — Reporting & Communication

Findings that aren't communicated well don't get acted on. This track turns
a completed investigation into the **deliverables package** a real IR
engagement produces — for three different audiences (responders, management,
peer teams). One continuous build, from raw evidence to a shareable product.

Base incident: **Cerber (Incident B)**; reuse everything from Tracks 1–3.

> Reference templates + confirmed values: [SOLUTIONS.md](SOLUTIONS.md) (Track 7).

---

### R1 — Assemble the IOC package
**🔗 From:** all tracks · **Deliverable:** a clean, typed indicator list for Tier 2 / tooling.
```
Domains   : solidaritedeproximite.org, cerberhhyed5frqa.xmfir0.win
Files     : 20429.vbs (dropper), 121214.tmp (payload), *.cerber (encrypted)
Host chain: WINWORD.EXE → cmd.exe → wscript.exe → 121214.tmp
Registry  : HKU\...\CurrentVersion\Run\osk (persistence)
Removable : USB FriendlyName "MIRANDA_PRI"
Network   : file server 192.168.250.20; Suricata sigs 2816763/2816764/2820156
```
Group by type; each indicator must be something a defender can block or hunt on.

### R2 — Technical incident report
**🔗 Builds on R1.** **Deliverable:** a narrative + the master timeline (16:43:21 → 17:04:33), written for a fellow analyst: what happened, in order, with the evidence source for each step. Enough detail to reproduce your investigation.

### R3 — Executive summary (5 sentences, no jargon)
**🔗 Builds on R2.** **Deliverable:** What (Cerber ransomware on a workstation), Where (`we8105desk`/`bob.smith`, file server), When + dwell (~16 min), How (email macro → script → payload), Impact (22 PDFs + local files encrypted; recoverable from backup). A manager must grasp it in 30 seconds — no IOCs, no SPL.

### R4 — Metrics & KPIs
**🔗 Builds on R2.** **Deliverable:** the numbers leadership tracks — **dwell time** (t0→t1 ≈16 min), time-to-detect vs. time-to-contain, blast radius (1 host, 1 share, 22 docs), and how they compare to targets. State your `t0` choice explicitly.

### R5 — Lessons learned & recommendations
**🔗 Builds on Track 5/6.** **Deliverable:** a prioritized recommendation list tied to evidence — deploy the DE1 detection, enable ASR Office-child-process blocking, add egress filtering (the firewall *allowed* C2), verify backup coverage. Rank by impact × effort.

### R6 — Peer / intel-sharing product
**🔗 Builds on R1.** **Deliverable:** the same incident packaged for *another team* — a short structured brief (indicators + context + recommended actions) in a shareable shape (think STIX/MISP fields, or a clean markdown block). Contrast the tone/detail vs. R3 (execs) and R2 (analysts): **same facts, three audiences.**

---

---

## More exercises (R7–R12)

### R7 — Web-incident report (Incident A)
**🔗 From:** Track 2 Case A · **Deliverable:** the same deliverable set for the 2016-08-10 web intrusion — IOCs (attacker IPs, `agent.php`), timeline, exec summary. Practice producing a report for a *different* incident type so the format is muscle memory, not a one-off.

### R8 — Presenting the timeline (visualization)
**🔗 Builds on R2.** **Deliverable:** turn the raw timeline into something a non-analyst reads at a glance — a clean stage-by-stage table (Time · Stage · What happened · Evidence). Discuss what to *omit* (btool noise, service accounts) so the story is legible.

### R9 — Evidence log / chain of custody
**🔗 From:** Track 2 B0 · **Deliverable:** a table of every data source you used — sourcetype, time range queried, what it proved, and when you pulled it. In real IR this is what makes findings defensible (and court-ready). Note integrity limits (you queried a live index, not a preserved image).

### R10 — In-incident status update
**🔗 Builds on R3.** **Deliverable:** a 3-line stakeholder update written *mid-incident* (before it's fully resolved) — what's confirmed, what's being contained, what's still unknown. Different from a post-incident report: honest about uncertainty, no over-claiming.

### R11 — Post-incident review (blameless)
**🔗 Builds on R5.** **Deliverable:** a short retro — what went well (detection at impact), what was slow (16-min dwell, C2 allowed out), and 3 concrete action items with owners. Focus on systems/controls, not blame.

### R12 — SOC metrics dashboard spec
**🔗 Builds on R4.** **Deliverable:** specify (in words + the SPL that would feed them) the KPI panels a SOC lead wants — dwell time, MTTD/MTTR, incidents by severity, top techniques. You're designing the recurring view, not a one-incident number.

---

➡️ Reference templates & confirmed values: [SOLUTIONS.md](SOLUTIONS.md) (Track 7).
