# Track 6 — Purple Team (Attack ↔ Defense Validation)

Purple teaming closes the gap between "we got hit" and "we'd catch it now."
You take the *attacker's* view of an incident (the ATT&CK techniques) and
grade the *defender's* view against it (do we detect? do we prevent?), then
drive concrete control improvements — and re-test them.

This is one continuous assessment of **Incident B (Cerber)**, ending in a
detect-vs-prevent coverage matrix and a ranked gap list.

> Reference matrix + confirmed values: [SOLUTIONS.md](SOLUTIONS.md) (Track 6).
> Uses the detections built in [Track 5](05-detection-engineering.md).

---

### PT1 — Build the ATT&CK layer of the incident
**🔗 From:** Tracks 1–3 (all findings) · **Deliverable:** the technique list, in kill-chain order, each with the evidence that proves it.
```
T1566/T1204  Word macro / user execution        (Sysmon: WINWORD→cmd)
T1059.005    VBScript (20429.vbs)                (Sysmon: wscript)
T1547.001    Run-key osk persistence            (winregistry)
T1070.004    self-deletion of 121214.tmp        (Sysmon)
T1071/T1568  C2 to cerberhhyed5frqa.xmfir0.win  (dns+suricata+fgt)
T1021.002    SMB to file server                 (stream:smb)
T1486        encryption (.cerber)               (stream:smb)
```

### PT2 — Coverage assessment (do we DETECT each?)
**🔗 Builds on PT1.** **Deliverable:** for every technique, mark Detected / Partial / Blind, citing the data source or the Track-5 rule that covers it.
- e.g. T1204 → **Detected** (DE1); T1486 → **Detected** (DE2); T1547.001 → **Detected** (DE5); T1070.004 → **Partial** (Sysmon has it but no rule yet); T1003 cred-dumping → **Blind** (EID 10 sparse).

### PT3 — Prevention assessment (could we have BLOCKED it?)
**🔗 Builds on PT1.** **Deliverable:** for each technique, what *preventive* control applies and did we have it?
- T1204 → Microsoft **ASR "block Office child processes"** would kill the chain at step 1.
- T1071 C2 → **egress filtering / DNS sinkhole** — but the firewall *accepted* it (Track 3 §B5), so we didn't.
- T1486 → **backups** (Acronis present) turn impact into recoverable.

### PT4 — Rank the gaps (earliest-break-the-chain)
**🔗 Builds on PT2/PT3.** **Deliverable:** a prioritized list. A control that breaks the chain at **Execution** (ASR) beats one that only helps at **Impact** (backups). Rank by *how early* it stops the attack × *effort to deploy*.

### PT5 — Emulation plan (safely re-test)
**🔗 Builds on PT1.** **Deliverable:** a mapping of each technique to a safe re-test (e.g. **Atomic Red Team** atomics: T1204.002, T1547.001, T1059.005). State how you'd run it against a lab host and *what your Track-5 detection should show* if it works. (Design exercise — you're specifying the test, not running it here.)

### PT6 — Validate one control end-to-end
**🔗 Builds on PT3/PT5.** **Deliverable:** pick the ASR Office-child-process control. Describe the before/after: without it, DE1 *detects*; with it enabled, the child process never spawns so the chain *dies* and DE1 goes quiet (prevention beats detection). Note how you'd confirm the control is actually on.

### PT7 — Deliver the coverage matrix
**🔗 Builds on PT1–PT6.** **Deliverable:** a single table — Technique × (Detect? / Prevent? / Gap / Recommendation) — the artifact a purple-team engagement hands to leadership.

---

---

## More exercises (PT8–PT12)

### PT8 — Purple-team the *web* incident (Incident A)
**🔗 From:** Track 1 §A / Track 2 Case A · **Deliverable:** a second ATT&CK layer + coverage matrix for the web intrusion (T1595 recon → T1110 brute force → T1190 exploit → T1505.003 web shell → T1491 defacement). Which stages do network detections catch that endpoint ones miss? Contrast the *detectability profile* of an external web attack vs. the endpoint ransomware.

### PT9 — Defense-in-depth / layer assessment
**🔗 Builds on PT2/PT8.** **Deliverable:** map coverage by *layer* — perimeter (firewall/IDS), network (stream), endpoint (Sysmon), identity (WinEventLog). Where is the org strong, where blind? (v1 is endpoint- and network-rich but identity-thin — no MFA/EDR telemetry.)

### PT10 — Assumption-of-breach drill
**🔗 Builds on PT2.** **Deliverable:** if endpoint logging were unavailable, could **network data alone** reconstruct Incident B? Walk it (DHCP→DNS→Suricata→SMB) and state what you'd lose (the process tree, persistence). Teaches resilience of detection across data-source outages.

### PT11 — Purple-team metrics
**🔗 Builds on PT7.** **Deliverable:** quantify the engagement — % of the incident's techniques Detected vs. Partial vs. Blind, and "detection depth" (how many kill-chain stages you'd catch before impact). These are the numbers a purple-team report trends over time.

### PT12 — Regression: prove the gap closed
**🔗 Builds on PT4/PT6 + Track 5.** **Deliverable:** pick one gap (e.g. T1070.004 self-delete = Partial). Write the missing detection (Track-5 style), then re-score the matrix to show the cell flip Partial→Detected. Purple teaming is a *loop*, not a one-shot audit.

---

➡️ Reference coverage matrix: [SOLUTIONS.md](SOLUTIONS.md) (Track 6).
