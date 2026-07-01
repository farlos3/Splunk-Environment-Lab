# Track 3 — Network Forensics

Network forensics reconstructs an incident from **wire and perimeter data** —
who talked to whom, how much, over what protocol, and what payloads reveal.
BOTS v1 is rich here: full Stream capture (`stream:*`), a Fortigate firewall
(`fgt_traffic`), Suricata IDS, and IIS logs.

This track is **two continuous investigations**, each following one incident
across the network stack — flows → protocol → payload → corroboration —
with every step **building on** the last.

**Mindset:** flows first (who↔who, how much), then protocol detail, then
payload. Three views of one conversation (wire + firewall + IDS) is a finding.

> Reference method + confirmed values: [SOLUTIONS.md](SOLUTIONS.md)

---

# Scenario A — Anatomy of the Web Attack on the Wire (2016-08-10)

*Reconstruct the intrusion of `192.168.250.70` using only network data.*
Window: `08/10/2016:00:00:00` → `08/11/2016:00:00:00`.

### A1 — Conversation map & top talkers
**Data:** `fgt_traffic`, `stream:ip`
**Objective:** big picture before drill-down. `sourcetype=fgt_traffic | stats sum(sentbyte) as sent sum(rcvdbyte) as rcvd by srcip dstip | sort - sent` (fields are `srcip`/`dstip`/`sentbyte`, not CIM `src`/`dest`). Which external IPs converse most with the web server, and in which direction does data flow?
**Feeds:** A2 (your suspect source).

### A2 — Brute force on the wire
**🔗 Builds on A1.** **Objective:** characterize the credential attack from HTTP. `sourcetype=stream:http dest_ip="192.168.250.70" http_method=POST | stats count by src_ip http_user_agent`, then `| timechart span=1m count by src_ip`. A single fixed, slightly-odd UA across thousands of POSTs at machine-gun cadence = automation.
**Carry forward:** attacker IP + UA.

### A3 — HTTP status & injection forensics
**🔗 Builds on A2.** **Objective:** read the attack in the requests. `| stats count by status` (error spikes vs. a telltale `200`), and hunt injection markers in the URI (`*union*`, `*'*`, `*..%2f*`). Separate recon 404s from successful access.

### A4 — Reconstruct what was uploaded
**🔗 Builds on A3.** **Objective:** recover the delivered artifacts. `dest_ip="192.168.250.70" part_filename=* | stats count by src_ip part_filename` — the action-on-objective files.
**Carry forward:** uploaded file names.

### A5 — Reconcile the two web views (iis vs stream)
**🔗 Builds on A2–A4.** **Objective:** cross-check server-side vs. wire. Compare counts across `sourcetype=iis` and `sourcetype=stream:http` for the same window; explain any disagreement (TLS termination, proxying, sampling). Literacy in *why sources differ* is the point.

### A6 — Enrich & attribute
**🔗 Builds on A1–A5.** **Objective:** add context — `| iplocation src_ip` on the attacker IPs (hosting/geo), and set the targeted attack apart from the perimeter SSH/Telnet scan noise (`fgt_traffic action=deny dstport IN(22,23,3389)`). Deliver the network IOC set.

---

# Scenario B — Tracking the Ransomware Across the Network (2016-08-24)

*Follow the Cerber infection of `192.168.250.100` purely through network
telemetry.* Window: `08/24/2016:00:00:00` → `08/25/2016:00:00:00`.

### B1 — Attribute the host (who is 192.168.250.100?)
**Data:** `stream:dhcp`
**Objective:** tie the IP to a device before anything else. `sourcetype=stream:dhcp 192.168.250.100 | table _time *mac* *requested* *hostname*` → `we8105desk`. When IPs are dynamic, DHCP is the attribution glue.
**Feeds:** every later step is scoped to this host.

### B2 — DNS anomaly hunt
**🔗 Builds on B1.** **Objective:** surface the malicious domains among thousands of lookups. Group by **`query{}`** (always present), earliest-seen per domain, drop dot-less NetBIOS noise (`regex "query{}"="\."`). The payload-download domain and the ransom `.onion` gateway stand out by name + timing.
**Carry forward:** the C2/download domains + first-seen times.

### B3 — DNS record-type & beacon timing
**🔗 Builds on B2.** **Objective:** profile the C2 lookups. `stats count by query_type{}` (A/PTR/TXT — TXT-heavy would suggest tunneling) and `"query{}"="*xmfir0*" | timechart span=1m count` — is it a sustained beacon or one-shot?

### B4 — Confirm the C2 channel (multi-source)
**🔗 Builds on B2.** **Objective:** prove C2 with IDS + firewall. `sourcetype=suricata Cerber | stats count by alert.signature_id alert.signature | sort count` (rarest = the high-fidelity check-in), then `sourcetype=fgt_traffic srcip="192.168.250.100" dstip=<c2-ip>` — allowed or blocked?
**Carry forward:** the confirming signatures.

### B5 — Firewall posture
**🔗 Builds on B4.** **Objective:** the perimeter decision. `sourcetype=fgt_traffic (srcip="192.168.250.100" OR dstip="192.168.250.100") | stats count by action` (`accept`/`deny`/`close`/`ip-conn`). Was the C2 egress *allowed*? That's the control gap the report flags.

### B6 — SMB impact on the wire
**🔗 Builds on B1.** **Objective:** watch encryption happen. SMB session to the file server, then originals read (`filename="*.pdf"`, not `"*.pdf*"`) vs. `.cerber` writes + `# DECRYPT MY FILES #` notes. Timestamp the first `.cerber` write = encryption start.
**Carry forward:** server IP, counts, encryption time.

### B7 — Rule out covert channels
**🔗 Builds on B4.** **Objective:** don't assume — check ICMP tunneling: `sourcetype=stream:icmp | stats count avg(bytes) by src_ip dest_ip`. Normal-sized, low-volume = clean negative. Document it.

### B8 — Single-pane correlation (capstone)
**🔗 Builds on B2–B7.** **Objective:** take the C2 indicator and prove it across every view at once: `(sourcetype=stream:dns OR sourcetype=suricata OR sourcetype=fgt_traffic) cerberhhyed5frqa.xmfir0.win | stats count by sourcetype`. Three independent sources on one indicator = a report-grade finding, and the connected close of the scenario.

---

➡️ Reference walkthroughs & confirmed values: [SOLUTIONS.md](SOLUTIONS.md) (Track 3).
