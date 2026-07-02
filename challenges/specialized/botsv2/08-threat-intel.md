# Track 8 — Threat-Intel Pivot & Attribution (BOTS v2 / froth.ly APT)

Enrich, attribute, and cluster the froth.ly intrusion. The APT angle makes
this richer than v1: multiple footholds and OSes force real linkage analysis.

> Reference findings: [SOLUTIONS.md](SOLUTIONS.md) (Track 8).

---

### TI1 — Enrich the indicators
**🔗 From:** Tracks 1–3. `| iplocation` the C2 `45.77.65.211` and the SSH brute IPs (`58.242.83.20`, …) and `71.39.18.125`. Note hosting/geo; mark data-derived vs. would-need-external (WHOIS/passive-DNS/VT on the C2 + the Empire session cookie).

### TI2 — Attribute the campaign
**🔗 Builds on TI1.** Toolmarks: **PowerShell Empire** (the `-enc` stager shape, `/admin/get.php`, RC4, AMSI bypass) = a common APT/red-team framework; the froth.ly scenario actor is **Taedonggang**. macOS **Quimitchin/FruitFly** = a known macOS espionage backdoor. State confidence + evidence per claim (framework ≠ actor — be precise).

### TI3 — Linkage analysis (one actor or several?)
**🔗 Builds on TI2.** Cluster the footholds: the **Windows Empire C2** (`45.77.65.211`) is the core intrusion; the **macOS Quimitchin** is a separate malware family — same campaign or opportunistic? The **internet SSH brute force** is almost certainly unrelated **background noise**. Deliver a reasoned "core / possibly-related / noise" split; don't force links.

### TI4 — Diamond model
**🔗 Builds on TI2/TI3.** Model the core intrusion — Adversary (Taedonggang), Infrastructure (`45.77.65.211`, Empire C2), Capability (Empire stager, WMI lateral, schtasks/registry persistence), Victim (FROTHLY / `venus` + workstations). Pivoting any vertex finds related activity.

### TI5 — Pivot to find more
**🔗 Builds on TI1.** Take the C2 IP and hunt every host/time touching it: `index=botsv2 45.77.65.211 | stats count by src_ip` (via the sourcetype-appropriate field). Confirms the 4-host blast radius and the Aug-15 first contact.

### TI6 — IOC durability & intel product
**🔗 Builds on all.** Pyramid of Pain: the C2 IP/cookie (easy to change) vs. the TTPs (Empire-over-WMI + schtasks/registry persistence — painful). The Track-5 behaviour detections outlast an IP blocklist. Package: actor/framework + indicators with context + confidence + linkage + recommended detections — an intel product other teams can action.

---

➡️ Reference findings: [SOLUTIONS.md](SOLUTIONS.md) (Track 8).
