# Track 1 — Threat Hunting (BOTS v2 / Taedonggang APT)

Two continuous hunts against the froth.ly intrusion. Each is one connected
investigation along the kill chain; every step **builds on** the last. This
is an *APT* — slower and stealthier than v1's ransomware, spread across
Windows, Linux, and macOS.

**Ground rules:** hypothesis before search · baseline first · one hit is a
lead, corroborate across sources · carry IOCs forward · **scope time / use
`tstats`** (226M events).

> Reference method + confirmed findings: [SOLUTIONS.md](SOLUTIONS.md) (Track 1).

---

# Scenario A — "The Empire Foothold" (Windows)

*Something on the FROTHLY network is beaconing out. Hunt the Windows
compromise from the C2 signal back to how it got in.* Suggested window:
`08/23/2017` → `08/25/2017` (the active days).

### A1 — Find the beacon (start from egress)
**ATT&CK:** T1071 · **Data:** `suricata`, `pan:traffic`
**Hypothesis:** a compromised host is talking to external C2 on a repeating channel.
**Method:** look for a single external IP that shows up heavily across IDS + firewall + wire. `sourcetype=suricata | stats count by dest_ip` and `sourcetype=pan:traffic` (rex the dst). One external IP will dominate suspiciously.
**Carry forward:** the C2 IP.

### A2 — Hunt the endpoint payload
**🔗 Builds on A1** · **ATT&CK:** T1059.001, T1027 · **Data:** Sysmon EID 1
**Hypothesis:** the beacon is a PowerShell agent (encoded, downloading from the C2).
**Method:** `sourcetype=*ysmon* EventCode=1 (CommandLine="*-enc*" OR CommandLine="*FromBase64*" OR CommandLine="*DownloadString*") | table _time host CommandLine`. Decode the `-enc` base64 (it's a PowerShell **Empire** stager — AMSI bypass + `WebClient` to the C2). Which host?
**Carry forward:** the compromised host + the decoded C2 URL.

### A3 — How was it launched? (execution vector)
**🔗 Builds on A2** · **ATT&CK:** T1047 (WMI)
**Hypothesis:** the agent didn't start from a click — something spawned it remotely.
**Method:** find the **ParentImage** of the `-enc` PowerShell. `… host=<compromised> CommandLine="*-enc*" | rex field=_raw "<Data Name='ParentImage'>(?<ParentImage>[^<]+)"`. A parent of `WmiPrvSE.exe` = **WMI-based lateral movement/execution** — the actor pushed the agent over WMI, not phishing-on-this-host.

### A4 — Hunt persistence
**🔗 Builds on A2** · **ATT&CK:** T1053.005, T1547 (registry)
**Hypothesis:** the agent set up to survive reboot.
**Method:** `sourcetype=*ysmon* EventCode=1 (CommandLine="*schtasks*Create*" OR CommandLine="*/TN*")`. Find the scheduled task (`/TN Updater /RU system`) whose action runs `powershell … IEX(… FromBase64String((gp HKLM:\Software\… ).debug))` — payload stored in a **registry** value, launched daily as SYSTEM. Note the dual technique: task + registry blob.

### A5 — Confirm & scope the C2
**🔗 Builds on A1/A2** · **ATT&CK:** T1071
**Method:** corroborate the C2 IP across **three+** sources and find *every* host that talked to it: `index=botsv2 45.77.65.211 | stats count by sourcetype` and `… sourcetype=pan:traffic 45.77.65.211 | rex … | stats count by src_ip`. C2 confirmed in PAN + Suricata + Stream + web = report-grade.
**Carry forward:** all internal hosts that reached the C2 (blast radius seed).

### A6 — Trace the tooling drop
**🔗 Builds on A2** · **ATT&CK:** T1105
**Method:** the actor staged tooling — hunt `msiexec` installs from odd paths: `sourcetype=*ysmon* EventCode=1 CommandLine="*msiexec*c:\\temp*"`. You'll find `python.msi` dropped to `c:\temp\download`. Assemble Scenario A: WMI push → Empire `-enc` stager → C2 `45.77.65.211` → schtasks+registry persistence → tooling staged.

---

# Scenario B — "The Other Doors" (Linux + macOS)

*The APT didn't only touch Windows. Hunt the non-Windows footholds — and
practice separating internet background noise from the real intrusion.*

### B1 — Triage the Linux SSH noise
**ATT&CK:** T1110 · **Data:** `linux_secure`
**Hypothesis:** the Linux hosts are being brute-forced from the internet.
**Method:** `sourcetype=linux_secure "Failed password" | rex "from (?<src_ip>\d+\.\d+\.\d+\.\d+)" | stats count by src_ip | sort - count`. Huge counts from a handful of (Chinese) IPs hitting `gacrux`. This is *background radiation* — loud, distributed, denied. Note it, don't over-focus.
**Carry forward:** the brute-force IPs (to *exclude* in B2).

### B2 — Find the actual successful login
**🔗 Builds on B1** · **ATT&CK:** T1078
**Hypothesis:** amid the noise, did anyone actually get **in**?
**Method:** `sourcetype=linux_secure "Accepted password" | rex "Accepted password for (?<user>\S+) from (?<src_ip>\S+)" | stats count by src_ip user host`. You'll find `klager` logging into `gacrux` from `71.39.18.125` — a *different* IP than the brute-forcers. Decide: is this the employee or the attacker? (Corroborate the source IP / timing before concluding — this is the judgment the hunt teaches.)

### B3 — Hunt the macOS backdoor
**🔗 parallel foothold** · **ATT&CK:** T1071 · **Data:** `suricata`, `stream:dns`
**Hypothesis:** the Mac (`kutekitten`, `10.0.4.2`) is compromised too.
**Method:** `sourcetype=suricata "Quimitchin"` (aka FruitFly, a macOS backdoor) — a DNS-lookup signature from `10.0.4.2` → `10.0.1.100`. Pivot: `sourcetype=stream:dns src_ip=10.0.4.2` for the domains it resolved. This is a *separate* malware family from the Windows Empire agent.

### B4 — Tie the campaign together
**🔗 Builds on A + B** · **Deliverable:** one adversary or several?
**Method:** compare infrastructure and timing across the Windows Empire C2 (`45.77.65.211`), the SSH activity, and the macOS backdoor. Which footholds share infra/timing (same campaign) vs. which are unrelated noise (the internet SSH brute force)? Deliver a reasoned "these belong to the froth.ly intrusion; that is background noise" split — the core APT-hunting skill.

---

➡️ Method + confirmed findings: [SOLUTIONS.md](SOLUTIONS.md) (Track 1).
