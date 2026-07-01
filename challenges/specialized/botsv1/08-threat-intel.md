# Track 8 — Threat-Intel Pivot & Attribution

Intel work turns "here's what happened" into "here's who, and what it means."
You enrich indicators, attribute the activity, and decide whether the org's
two incidents are connected — practicing the discipline to attribute *with
confidence levels* and to **not force links the evidence doesn't support**.

This track spans **both** incidents (Web = Po1s0n1vy, Ransomware = Cerber)
and ends in an intel product + a linkage verdict.

> Reference findings + confirmed values: [SOLUTIONS.md](SOLUTIONS.md) (Track 8).

---

### TI1 — Enrich the indicators
**🔗 From:** Tracks 1–3 IOCs · **Deliverable:** each external IP/domain with what context you can derive.
- In-data enrichment: `| iplocation` the attacker IPs (`40.80.148.42`, `23.22.63.114`, C2) for geo/hosting; note timing and volume from the flows.
- External enrichment (state you'd do it, offline here): WHOIS/passive-DNS/VT on the domains and hashes. Mark which context is *from data* vs. *would-need-external*.

### TI2 — Attribute each incident
**🔗 Builds on TI1.** **Deliverable:** a confidence-rated attribution per incident.
- **Incident A** → **Po1s0n1vy** APT: the defacement theme + attacker IP `40.80.148.42` + tooling. State confidence + evidence.
- **Incident B** → **Cerber** ransomware family: `.cerber` extension, `*.xmfir0.win` infra, ETPRO Suricata sigs. Note this is *family* attribution, not a named actor.

### TI3 — Linkage analysis (are A and B the same actor?)
**🔗 Builds on TI2.** **Deliverable:** a "linked / not linked" call with reasoning.
- Compare infrastructure, tooling, victimology, and timing (2 weeks apart).
- **Answer: not linked** — no shared infra/TTPs; one is a targeted APT web intrusion, the other commodity ransomware. The skill: resisting the pull to invent a connection because two bad things hit the same org.

### TI4 — Model it (Diamond / kill chain)
**🔗 Builds on TI2/TI3.** **Deliverable:** a Diamond-model view of Incident B — Adversary (Cerber operators), Infrastructure (`*.xmfir0.win`, download domain), Capability (macro dropper + payload), Victim (`bob.smith`/Wayne Enterprises). Shows how pivoting on any vertex could find related activity.

### TI5 — Pivot to find related activity
**🔗 Builds on TI1.** **Deliverable:** take one indicator and hunt the dataset for anything else touching it — e.g. did any *other* host resolve the C2 domain or talk to the attacker IPs? `index=botsv1 (sourcetype=stream:dns OR sourcetype=fgt_traffic) <indicator> | stats count by src_ip`. Confirms scope (only `we8105desk`) and demonstrates indicator pivoting.

### TI6 — Produce the intel product
**🔗 Builds on TI1–TI5.** **Deliverable:** a short, structured intel report other teams can action — the actor/family, the indicators with context, the confidence levels, the linkage verdict, and recommended detections/blocks. Written to *inform decisions*, not just list data.

---

---

## More exercises (TI7–TI12)

### TI7 — Deep-dive attribution: Po1s0n1vy (Incident A)
**🔗 From:** Track 1 §A / Track 2 Case A · **Deliverable:** a TTP profile of the web-attack actor — attacker IPs, tooling UAs (`Chrome/41.0.2228.0`, `Python-urllib`), uploaded artifacts, the defacement theme — assembled into an actor card with confidence levels.

### TI8 — IOC durability (Pyramid of Pain)
**🔗 Builds on R1/TI1.** **Deliverable:** rank the incident's indicators by how much they *cost the adversary* to change — hash/filename (trivial) → IP/domain (easy) → tools/UAs (annoying) → TTPs (painful). Conclusion: the Track-5 behaviour detections (TTP-level) outlast IOC blocklists. Explain why to a manager who wants "just block the IPs."

### TI9 — Intel → detection (reverse of Track 5)
**🔗 To:** Track 5 · **Deliverable:** start from an *external* intel report ("Cerber uses `*.xmfir0.win`, drops `.cerber`, VBS via macro") and turn it into a hunt + a detection for *your* data. Practice consuming intel, not just producing it.

### TI10 — Campaign / family tracking
**🔗 Builds on TI2.** **Deliverable (design):** how would you track the Cerber family *over time* — which durable indicators to watch (infra patterns, extension, ransom-note format), and how you'd store them as Splunk lookups for recurring matching.

### TI11 — Feed & enrichment integration
**🔗 Builds on TI1.** **Deliverable (design):** sketch wiring a threat-intel feed into Splunk — indicators as a lookup, an automatic `lookup`/`tstats` match against `stream:dns`/`fgt_traffic`, and how a hit becomes a notable. The pipeline from "feed" to "alert."

### TI12 — Confidence & sourcing discipline
**🔗 Builds on TI2/TI3.** **Deliverable:** re-express your attribution and linkage calls with explicit **analytic confidence** (high/moderate/low) and source reliability (e.g. Admiralty grading). State what evidence would *raise* or *lower* each — the habit that separates intel from guessing.

---

➡️ Reference findings & confirmed values: [SOLUTIONS.md](SOLUTIONS.md) (Track 8).
