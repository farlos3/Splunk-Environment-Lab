# Track 2 — DFIR / Investigation (BOTS v2 / froth.ly APT)

One **continuous investigation** of the Taedonggang intrusion, run through the
full IR lifecycle (Scope → Collect → Timeline → Analyze → Attribute → Report).
Unlike v1's single-host ransomware, this is a **multi-host, multi-day, multi-OS
APT** — the scoping and timeline work is the hard part.

Every step **builds on** the last. Scope raw searches to the active window
(`08/15–08/26/2017`) and prefer `tstats` — 226M events.

> Reference method + confirmed values: [SOLUTIONS.md](SOLUTIONS.md) (Track 2).
> Assumes Track 1 findings (the C2, the Empire agent).

---

### D0 — Evidence acquisition & coverage
**Deliverable:** the telemetry inventory + gaps. `| metadata type=sourcetypes index=botsv2`. Note the breadth (Windows 4688/Sysmon, Linux syslog/auditd, macOS osquery, PAN firewall, Suricata, Stream, MySQL) and the gaps (the Mac has **osquery but no real-time EDR** — IDS surfaces the backdoor and osquery confirms it on-host; PAN/Linux need `rex`).

### D1 — Scope & patient zero
**🔗 Builds on D0.** **Deliverable:** which hosts are involved and the *earliest* malicious action. Enumerate internal hosts beaconing to the C2 and their first-seen times. The earliest C2 contact (not the noisiest host) is your `t0` — beware assuming the day everything "blew up" was the start.

### D2 — Root cause & execution vector
**🔗 Builds on D1.** **Deliverable:** how code ran. On the compromised Windows host, trace the Empire `-enc` PowerShell to its **parent** (`WmiPrvSE.exe` → WMI execution, T1047). This means the agent was *pushed* remotely — so patient zero is elsewhere; follow the WMI/credential trail back.

### D3 — Master timeline
**🔗 Builds on D1/D2.** **Deliverable:** one chronological table across sources. Anchor the verified events: first C2 contact (Aug 15), the Aug 24 expansion, the Empire stager, the persistence task. Label each by ATT&CK tactic. Read real timestamps — don't invent.

### D4 — Payload / malware analysis
**🔗 Builds on D2.** **Deliverable:** what the agent is. Decode the `-enc` base64 (PowerShell **Empire** stager: AMSI bypass, `WebClient` → `https://45.77.65.211:443/admin/get.php`, RC4, session cookie). Name techniques from readable strings — you don't need to fully reverse it.

### D5 — Persistence enumeration (eradication list)
**🔗 Builds on D2.** **Deliverable:** every autostart to remove. The scheduled task **`Updater`** (SYSTEM, daily) runs a payload stored in registry `HKLM:\Software\Microsoft\Network debug`. Output: delete task `Updater` + the registry value; hunt the same pattern on the other beaconing hosts.

### D6 — Blast radius
**🔗 Builds on D1.** **Deliverable:** the full set of affected hosts. Enumerate all internal IPs that reached the C2 (map IP→host via DHCP/asset data). Distinguish *confirmed compromised* (Empire agent present) from *beaconing/suspect*.

### D7 — Lateral movement analysis
**🔗 Builds on D2.** **Deliverable:** how the actor moved host-to-host. The `WmiPrvSE.exe` parent (D2) = WMI lateral execution (T1047). Look for the credential source (which account ran the WMI) and other WMI-spawned processes across hosts.

### D8 — Multi-OS scope
**🔗 Builds on D1.** **Deliverable:** the non-Windows footholds. Linux: separate the SSH brute-force noise (two hosts — `eridanus` 67k, `gacrux` 40k) from the *successful* `klager` login (`gacrux` only; `eridanus` had none). macOS: the Quimitchin backdoor on **`kutekitten`** (`10.0.4.2`) — IDS/DNS flag it on the wire and `osquery_results` on that host confirms the malware file/hash. State confidence on whether each belongs to the campaign.

### D9 — Account & credential impact
**🔗 Builds on D7.** **Deliverable:** which accounts were used/abused (`FROTHLY\billy.tun`, `amber.turing`, `klager`, SYSTEM via the task). Any privileged accounts? What's the credential-exposure blast radius?

### D10 — Exfiltration assessment
**🔗 Builds on D6.** **Deliverable:** did data leave? Check outbound volume to the C2 and any large transfers (PAN `sentbyte`, stream). Characterize as C2 signalling vs. bulk exfil — and say which, with evidence (don't over-claim theft).

### D11 — Containment & eradication plan
**🔗 Builds on D5/D6/D8.** **Deliverable:** an action list — isolate the compromised hosts, block C2 `45.77.65.211`, remove the `Updater` task + registry blob, reset abused creds, and address the Linux + macOS footholds separately.

### D12 — Metrics, ATT&CK map & report
**🔗 Builds on all.** **Deliverable:** dwell time (first C2 Aug 15 → detection/containment), the end-to-end ATT&CK list, and a 5-sentence exec summary + IOC package. Close the case.

---

➡️ Reference walkthroughs & confirmed values: [SOLUTIONS.md](SOLUTIONS.md) (Track 2).
