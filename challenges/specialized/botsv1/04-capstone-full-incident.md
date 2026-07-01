# Capstone — "Operation Wayne Manor": Full-Spectrum Incident

The single big use case that **fuses every track**. Tracks 01–03 taught each
discipline in isolation; here you run **one incident end-to-end**, switching
disciplines as a real responder does — SOC triage → threat hunting → network
forensics → endpoint DFIR → detection engineering → purple-team validation →
reporting → threat-intel pivot.

**How this differs from the per-track scenarios:** those give you the lens and
the answer. Here you get an *alert and a clock* — you decide which lens to
pick up next, carry evidence across all of them, and produce the full set of
IR deliverables. Nothing new to memorize; everything is the connective tissue
between what you already practiced.

> Do the per-track scenarios first (esp. Track 1 §B, Track 2 Case B, Track 3 §B).
> This capstone assumes you can already run each phase's queries. Reference
> values live in [SOLUTIONS.md](SOLUTIONS.md).

**Scenario window:** `08/24/2016:00:00:00` → `08/25/2016:00:00:00` (with an
Incident-A pivot to `08/10/2016` at the very end).

---

## The scene

> **17:05, Wayne Enterprises SOC.** A file-integrity alert fires: files on the
> corporate share `\\192.168.250.20` are being renamed with a `.cerber`
> extension. You are the on-call analyst. Work it to a closed case.

---

## Phase 0 — SOC Tier-1 triage (the first 10 minutes)
**Discipline:** SOC analysis · **Deliverable:** a triage note (5W1H) + severity call.
- Confirm the alert is real, not a false positive: `sourcetype=stream:smb ".cerber" | stats count min(_time) max(_time) by dest_ip`.
- Answer the fast 5W1H: *What* (ransomware extension appearing), *Where* (share `192.168.250.20`), *When* (first `.cerber` ~17:04), *Who* is writing them (which client IP), *How* (unknown yet — that's the investigation).
- **Decision point:** set severity and decide escalate-vs-close. `.cerber` on a file server = **CRITICAL, escalate to IR**. Note the source client IP to hunt next.
- 🔗 *Feeds Phase 1 (the source host).*

## Phase 1 — Threat hunting: scope the behaviour
**Discipline:** Track 1 §B · **Deliverable:** the compromised host + the execution chain.
- Pivot from the writing client IP → the workstation. Scope to its human user (strip service accounts) and filter should-never-happen behaviour to surface the LOLBin chain.
- Reach: `WINWORD→cmd→wscript(20429.vbs)→121214.tmp` on `we8105desk` / `bob.smith`.
- Triage out the Acronis `cscript`/SYSTEM and Nessus PowerShell noise as you go.
- 🔗 *Feeds Phase 2 (C2 domain) & Phase 3 (root cause).*

## Phase 2 — Network forensics: trace it on the wire
**Discipline:** Track 3 §B · **Deliverable:** C2 confirmation + impact quantification + firewall posture.
- Attribute the IP to the host via DHCP; DNS-hunt the download + ransom domains; confirm C2 across **DNS + Suricata + firewall**; read the firewall posture (was the egress allowed?).
- Quantify SMB impact: originals encrypted vs. `.cerber` artifacts; first-write timestamp.
- 🔗 *Feeds Phase 4 (blast radius) & Phase 7 (IOCs).*

## Phase 3 — Endpoint DFIR: root cause & malware triage
**Discipline:** Track 2 Case B · **Deliverable:** root-cause tree, master timeline, persistence, dropper IOCs.
- Trace *backwards* to the initial-access vector (Word macro); read the raw macro for technique families; profile the payload (`121214.tmp`) and its self-deletion; enumerate persistence (`Run\osk`).
- Build the unified timeline (endpoint + DNS + IDS) — this is the spine of the final report.
- 🔗 *Feeds Phase 4, 5, 7.*

## Phase 4 — Blast radius & containment decision
**Discipline:** DFIR + IR management · **Deliverable:** a containment recommendation with evidence.
- Prove scope: local profile + N docs on the share; and **prove the negative** — re-run the dropper TTP across *all* hosts to show it's contained to `we8105desk`.
- Account impact: any privileged logon? (limits lateral risk)
- **Decision:** isolate `we8105desk`, disable `bob.smith`, block the C2 domain, preserve evidence. Justify each with a query result.

## Phase 5 — Detection engineering: turn the hunt into a rule
**Discipline:** detection engineering (a *new* track woven in) · **Deliverable:** a tuned, reusable detection + its metadata.
- Generalize the root cause into a behaviour-based detection — an Office app spawning a script host/shell should *never* happen on a healthy endpoint:
  ```spl
  index=botsv1 EventCode=1
    (ParentImage IN ("*WINWORD.EXE","*EXCEL.EXE","*POWERPNT.EXE","*OUTLOOK.EXE"))
    (Image IN ("*wscript.exe","*cscript.exe","*powershell.exe","*cmd.exe","*mshta.exe"))
  | stats count min(_time) as first values(CommandLine) as cmd by host User ParentImage Image
  ```
- **Tune it:** would it fire on the Acronis/Nessus noise from Phase 1? Check the false-positive rate and add exclusions if needed. A good detection is *high-signal* — it should light up on `we8105desk` and stay quiet elsewhere.
- **Write the detection metadata:** name, ATT&CK mapping (T1566/T1204→T1059), severity, data source (`Sysmon EID 1`), and the response action. This is what you'd save as a correlation search / scheduled alert.
- 🔗 *This is the loop that turns a one-off finding into future coverage.*

## Phase 6 — Purple-team / control validation
**Discipline:** control assessment · **Deliverable:** ATT&CK coverage view + concrete control gaps.
- Map the whole incident to ATT&CK (T1566/T1204 → T1059.005 → T1547.001 → T1070.004 → T1071/T1568 → T1021.002 → T1486).
- For each stage, ask "what control would have broken it, and did we have it?" — e.g. Office child-process blocking (ASR) kills the chain at step 1; egress filtering would have blocked the C2 the firewall *accepted* (Phase 2 showed it didn't).
- Deliver a short gap list ranked by where it stops the attack earliest.

## Phase 7 — Reporting: the deliverables package
**Discipline:** IR reporting · **Deliverable:** exec summary + technical report + IOC package + metrics.
- **Exec summary** (5 sentences, no jargon): what/when/where/how/impact.
- **Dwell time**: `t1 − t0` with your chosen anchors stated (≈16 min).
- **IOC package** for Tier 2 / intel sharing: domains, dropper + payload names, C2 URL, `.cerber` extension, USB `FriendlyName`, ATT&CK IDs.
- **Lessons learned**: the detection from Phase 5 + the control gaps from Phase 6.

## Phase 8 — Threat-intel pivot (stretch): is this connected to anything?
**Discipline:** threat intel + cross-incident correlation · **Deliverable:** a linkage assessment.
- Two weeks earlier (`08/10/2016`) the org's web server was defaced (Track 1 §A / Track 2 Case A). Pivot: are the ransomware and the web intrusion the *same* actor, or unrelated?
- Compare infrastructure, tooling, and TTPs of **Po1s0n1vy** (web) vs. **Cerber** (ransomware). Deliver a confidence-rated "linked / not linked" call — and practice *not* forcing a connection that the evidence doesn't support.

---

## What "done" looks like

You've produced, from a single alert: a triage note, a scoped root-cause with
timeline, network + endpoint corroboration, a containment decision, **a new
detection**, an ATT&CK-mapped control-gap list, a full report with IOCs and
dwell time, and a defensible cross-incident intel call. That is the full arc
of a security professional — not one skill, but the *handoffs between them*.

➡️ Reference values per phase: [SOLUTIONS.md](SOLUTIONS.md).
