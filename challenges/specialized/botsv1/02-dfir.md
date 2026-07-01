# Track 2 — DFIR / Investigation Methodology

Digital Forensics & Incident Response is **reactive and disciplined**: the
incident is known; your job is a reproducible narrative of *what happened,
how far it spread, how it started, and what to hand off*.

This track is **two continuous investigations** — each runs the full IR
loop (Scope → Collect → Timeline → Analyze → Attribute → Report) as one
connected case, every step **building on** the last. Work a case end to
end; the later deliverables literally consume the earlier ones.

> Reference method + confirmed values: [SOLUTIONS.md](SOLUTIONS.md)

---

# Case A — Web Server Intrusion (2016-08-10)

*The `imreallynotbatman.com` server (`192.168.250.70`) was defaced. Run the
investigation.* Window: `08/10/2016:00:00:00` → `08/11/2016:00:00:00`.

### A1 — Scope the incident
**Deliverable:** the affected asset, the attacker source(s), and the earliest hostile contact. Identify who is hammering `192.168.250.70` and over which protocol. State what's unknown (how they got in, what they did).
**Feeds:** A2.

### A2 — Root cause: how was access gained?
**🔗 Builds on A1.** **Deliverable:** the initial-access mechanism. Distinguish brute force (thousands of login POSTs, one UA) from exploitation (SQLi/traversal), and determine whether a credential *succeeded*. Root cause here = an internet-exposed CMS admin with a guessable password.

### A3 — Action on objective
**🔗 Builds on A2.** **Deliverable:** what the attacker *did* after access — reconstruct the uploaded artifacts (file names) and the defacement. Separate the automated brute-forcer from the second, hands-on-keyboard actor.

### A4 — Attribution
**🔗 Builds on A1–A3.** **Deliverable:** a confidence-rated attribution note. Correlate the IOCs (attacker IPs, defacement theme, tooling) with known intel on the group. State the evidence behind the confidence level.

### A5 — Report & controls
**🔗 Builds on A1–A4.** **Deliverable:** a 5-sentence exec summary (What/When/Where/How/IOCs) plus one preventive control that would have broken the chain earliest (hint: at the credential-attack stage). No SPL, plain language.

---

# Case B — Cerber Ransomware (2016-08-24)

*`we8105desk` (`192.168.250.100`, `bob.smith`) is encrypting files. Full IR
case.* Window: `08/24/2016:00:00:00` → `08/25/2016:00:00:00`.

### B0 — Evidence acquisition & coverage
**Deliverable:** an inventory of available telemetry and its gaps. `| metadata type=sourcetypes index=botsv1` (and `type=hosts`). Name what you *can't* see (no memory image, no EDR, thin mail) — that scopes everything after.
**Feeds:** every later step.

### B1 — Scope & patient zero
**🔗 Builds on B0.** **Deliverable:** the victim host, its *human* owner (derive it — `stats count by User`, strip service accounts → `bob.smith`), and `t0` = the earliest malicious action (not the alert, which fires late at encryption).

### B2 — Root-cause process tree
**🔗 Builds on B1.** **Deliverable:** the parent→child chain from first execution to payload, and the initial-access vector. Scope to the user, filter should-never-happen behaviour, trace *backwards* to the user action (a Word macro).
**Carry forward:** dropper + payload names.

### B3 — Master timeline
**🔗 Builds on B2.** **Deliverable:** one chronological table unifying endpoint + DNS + IDS on `_time`, labelled by kill-chain stage. Read *real* timestamps off the data; mark "≈" only where a source lacks precision.
**Carry forward:** the anchor times (B12 needs them).

### B4 — Dropper artifact analysis
**🔗 Builds on B2.** **Deliverable:** IOCs and techniques from the dropper itself. Read the raw macro/VBS; name the technique families (obfuscation, sleep-based sandbox evasion, HTTP download) without full deobfuscation.

### B5 — Payload behavioural profile
**🔗 Builds on B4.** **Deliverable:** what the `.tmp` payload *did* — child processes, file writes, network, self-deletion, and **destruction of recovery options** (`vssadmin delete shadows /all /quiet` + `bcdedit … recoveryenabled no` at 16:49:23–24, **T1490** — a distinct pre-encryption stage; don't fold it into "encryption") — each mapped to an ATT&CK technique.

### B6 — Persistence enumeration (for eradication)
**🔗 Builds on B2.** **Deliverable:** every autostart the attacker created (Run keys, tasks, services) so responders can remove them. Output a concrete "remove these" list.

### B7 — Blast radius
**🔗 Builds on B2/B5.** **Deliverable:** exactly what was affected — local vs. the file server, which server, how many originals (beware loose wildcards), and how many `.cerber` artifacts.

### B8 — Prove containment
**🔗 Builds on B2.** **Deliverable:** evidence of (no) spread. Re-run the B2 TTP filter across *all* hosts in the window — one host matching = contained. Proving the negative matters.

### B9 — Account & credential impact
**🔗 Builds on B1.** **Deliverable:** which accounts were used/exposed on the victim (`4624/4625/4672`) and the lateral risk — did any privileged account log on during the incident?

### B10 — Anti-forensics check
**🔗 Builds on B3.** **Deliverable:** a yes/no on evidence tampering — log-clearing (`1102`), Sysmon stops, suspicious silent gaps. Likely a clean negative; document it (and what it says about adversary sophistication).

### B11 — Recovery scoping
**🔗 Builds on B5/B7.** **Deliverable:** what's restorable. ⚠️ Note the T1490 step from B5: **local Volume Shadow Copies were deleted** (`vssadmin`) and Windows recovery disabled (`bcdedit`), so in-place/VSS recovery is off the table — restoration depends on **off-host Acronis backups** taken *before* 16:49. Compare backup timing vs. the encryption start; recommend re-image + restore from off-host backup.

### B12 — Metrics, ATT&CK map & report
**🔗 Builds on B1–B11.** **Deliverable:** dwell time (`t1 − t0`, state which events you chose), the full ATT&CK technique list end-to-end, and a 5-sentence exec summary with the consolidated IOCs. Close the case.

---

➡️ Reference walkthroughs & confirmed values: [SOLUTIONS.md](SOLUTIONS.md) (Track 2).
