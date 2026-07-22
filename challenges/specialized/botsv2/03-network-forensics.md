# Track 3 — Network Forensics (BOTS v2 / froth.ly APT)

Reconstruct the intrusion from **wire + perimeter** data alone. v2 is rich
here: **Palo Alto** firewall (`pan:traffic`), Suricata IDS, and full Splunk
Stream (`stream:*`). One continuous investigation, flows → protocol →
payload → corroboration.

**Reminders:** `pan:traffic` is **CSV — no auto-fields**, so `rex` it. C2 is
on **443 (TLS)**, so you see *metadata* (PAN/Suricata) not payload. Scope
time / use `tstats` — 226M events.

> Reference method + confirmed values: [SOLUTIONS.md](SOLUTIONS.md) (Track 3).

---

### N1 — Conversation map & top external talkers
**Data:** `pan:traffic`
**Objective:** big picture first. The PAN log is positional CSV — extract src/dst and rank external destinations by volume. Which internal hosts talk most to the internet, and to where?
**Method:** `sourcetype=pan:traffic | rex ",(?<src_ip>10\.0\.\d+\.\d+),(?<dst_ip>\d+\.\d+\.\d+\.\d+)," | stats count by dst_ip | sort - count`. One external IP will stand out beyond normal web.
**Carry forward:** the suspicious external IP.

### N2 — Identify the C2 channel
**🔗 Builds on N1** · **ATT&CK:** T1071
**Objective:** confirm the standout IP is C2, and note the protocol. `index=botsv2 45.77.65.211 | stats count by sourcetype` → heavy in PAN + Suricata + Stream. It's **443/TLS** (`/admin/get.php`), so payload is encrypted — you characterize it by *metadata + IDS*, not content.

### N3 — Corroborate C2 across sources & find every internal host
**🔗 Builds on N2** · **Objective:** report-grade confirmation + blast radius on the wire.
**Method:** `sourcetype=pan:traffic "45.77.65.211" | rex ",(?<src_ip>10\.0\.\d+\.\d+),(?<dst_ip>[^,]+)," | search dst_ip="45.77.65.211" | stats count min(_time) as first by src_ip`. Four internal IPs beacon to the C2; `10.0.2.109` is first (Aug 15). Three independent sources agree on one indicator.

### N4 — TLS reality check (what the wire can't give you)
**🔗 Builds on N2** · **Objective:** understand your blind spot. `sourcetype=stream:http dest_ip="45.77.65.211" | stats count` returns almost nothing — the C2 is HTTPS, so `stream:http` (cleartext) sees little. Lesson: for TLS C2 you rely on **flow metadata (PAN), IDS (Suricata), and endpoint** — not payload. State this limit in findings.

### N5 — Detect the scanning
**🔗 parallel** · **ATT&CK:** T1046 · **Data:** `suricata`
**Method:** `sourcetype=suricata "Port 135" | stats count by src_ip dest_ip` → `10.0.1.1 → 10.0.1.100` (5,330 hits, "ET SCAN … Port 135"). Also review `| stats count by alert.category` — `Misc activity` (scan), `A Network Trojan was detected` (the macOS backdoor), `Misc Attack`.

### N6 — SSH brute force on the wire
**🔗 parallel** · **ATT&CK:** T1110 · **Data:** `linux_secure`, `stream:tcp`
**Method:** the syslog view (`linux_secure "Failed password" | rex …`) shows the external brute-forcers — add `by host` and you'll find they hit **two** Linux servers (`eridanus`, `gacrux`), not one; the wire view (`stream:tcp dest_port=22`) shows the connection volume. Separate this internet noise from the real intrusion.

### N7 — The macOS backdoor on the wire
**🔗 parallel** · **ATT&CK:** T1071 · **Data:** `suricata`, `stream:dns`
**Method:** `sourcetype=suricata "Quimitchin"` (category *A Network Trojan was detected*) from `10.0.4.2`; pivot `stream:dns src_ip=10.0.4.2` for the domains it resolved. IDS/DNS surface it on the wire; `osquery_results` on `kutekitten` (`10.0.4.2`) is the on-host confirmation.

### N8 — Exfil assessment + single-pane correlation (capstone)
**🔗 Builds on N2/N3** · **ATT&CK:** T1041
**Objective:** did data leave, and tie the C2 together. Sum outbound bytes to the C2 from PAN (`rex` the byte fields) — characterize C2 signalling vs. bulk exfil with evidence. Then the capstone query: `index=botsv2 (sourcetype=pan:traffic OR sourcetype=suricata OR sourcetype=stream:tcp) 45.77.65.211 | stats count by sourcetype` — one indicator, every network view = the finding that closes the track.

---

➡️ Reference walkthroughs & confirmed values: [SOLUTIONS.md](SOLUTIONS.md) (Track 3).
