# Track 6 — Purple Team (BOTS v2 / froth.ly APT)

Grade the defense against the attacker's view. One continuous assessment of
the Taedonggang intrusion → a detect-vs-prevent coverage matrix and ranked
gaps. The APT + multi-OS angle makes coverage gaps (esp. macOS) the story.

> Reference matrix: [SOLUTIONS.md](SOLUTIONS.md) (Track 6). Uses Track 5 detections.

---

### PT1 — Build the ATT&CK layer
**🔗 From:** Tracks 1–3 · **Deliverable:** techniques in kill-chain order, each with evidence.
```
T1110        SSH brute force (external)              linux_secure
T1078        valid-account SSH login (klager)        linux_secure
T1047        WMI remote execution                    Sysmon (WmiPrvSE parent)
T1059.001    PowerShell Empire (-enc) on venus       Sysmon
T1027        AMSI bypass / obfuscation               Sysmon CommandLine
T1053.005    schtasks "Updater" persistence          Sysmon
T1547 (reg)  payload in HKLM\...\Network debug       (task action)
T1071        C2 45.77.65.211:443                     PAN / Suricata / Stream
T1105        python.msi tooling drop                 Sysmon
T1071 (macOS) Quimitchin backdoor                    Suricata (10.0.4.2)
```

### PT2 — Detect coverage
**🔗 Builds on PT1.** For each, mark Detected / Partial / Blind + the Track-5 rule. e.g. T1059.001→Detected (DE1); T1047→Detected (DE2); T1053.005→Detected (DE3); T1071 C2→Detected (DE4); T1110→Detected (DE5); Quimitchin→Partial (IDS alert + osquery confirmation, no real-time EDR; DE6); registry payload→Partial (no rule on the reg write).

### PT3 — Prevention assessment
**🔗 Builds on PT1.** Per technique, the preventive control: T1059.001 → Constrained Language Mode / AMSI + PowerShell logging; T1047 → restrict WMI/RPC + host firewall; T1110 → key-only SSH + fail2ban; T1071 → egress filtering / TLS inspection (the C2 was on 443 and *allowed out*).

### PT4 — Rank the gaps
**🔗 Builds on PT2/PT3.** Rank by earliest-break-the-chain × effort. Blocking WMI lateral (T1047) or egress to unknown 443 destinations stops the campaign earlier than detecting persistence after the fact.

### PT5 — The macOS / multi-OS blind spot
**🔗 Builds on PT2.** Key APT lesson: the Mac (`kutekitten`) runs **osquery but no real-time EDR** — IDS *alerted* on Quimitchin and osquery *confirms* the malware file/hash on-host, but nothing did behavioural detection in between. Deliverable: a coverage-gap statement + recommendation (add macOS behavioural EDR, or turn the existing osquery into scheduled detections).

### PT6 — Coverage matrix (deliverable)
**🔗 Builds on all.** Technique × Detect? / Prevent? / Gap / Recommendation — the artifact for leadership. Emphasize where an APT slips through *because* controls are per-OS and inconsistent.

---

➡️ Reference matrix: [SOLUTIONS.md](SOLUTIONS.md) (Track 6).
