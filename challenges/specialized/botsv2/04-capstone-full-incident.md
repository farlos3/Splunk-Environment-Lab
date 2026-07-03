# Capstone — "Operation Froth" : Full-Spectrum APT Response

The big use case that **fuses every track** on the Taedonggang intrusion.
Tracks 01–08 taught each discipline; here you run the whole APT end-to-end
from a single alert, switching disciplines as a real responder does. Unlike
v1's fast ransomware, this is a **slow, multi-OS, multi-host APT** — scoping
and patience are the test.

> Do the per-track scenarios first. Reference values: [SOLUTIONS.md](SOLUTIONS.md).
> Scope time / use `tstats` — 226M events.

**Window:** `08/15/2017` (first C2) → `08/26/2017`.

---

## The scene
> **A Suricata alert flags outbound traffic to a known-bad IP, and an
> analyst notices a scheduled task named "Updater" running SYSTEM PowerShell
> on a server.** You're on call. Work the whole thing.

## Phase 0 — SOC triage
**Discipline:** SOC. Confirm the alert, do 5W1H, set severity. An external C2 + SYSTEM-level encoded PowerShell persistence on a *server* = **CRITICAL / APT-suspected, escalate to IR**. Note the host + C2 IP to pivot.

## Phase 1 — Threat hunting (Track 1)
Pivot from the C2 to the endpoint: find the Empire `-enc` stager, its `WmiPrvSE.exe` parent (WMI lateral), the `Updater` persistence, and every host beaconing to `45.77.65.211`. Then the multi-OS footholds (Linux SSH, macOS Quimitchin).

## Phase 2 — Network forensics (Track 3)
Confirm C2 across PAN + Suricata + Stream; note it's **443/TLS** (metadata-only); map the 4 beaconing internal hosts; separate the SSH brute-force noise; find the macOS backdoor on the wire.

## Phase 3 — Endpoint DFIR (Track 2)
Root cause + master timeline: **first C2 Aug 15**, Empire on venus **Aug 24 03:55**, persistence **04:12**. Decode the payload, enumerate persistence (task + registry), trace the WMI lateral path and abused accounts.

## Phase 4 — Blast radius & containment
4 beaconing hosts + macOS + Linux footholds. **Decision:** isolate compromised hosts, block `45.77.65.211` at egress, remove `Updater`+registry blob, reset abused creds, handle each OS. Justify with evidence; prove which hosts are *confirmed* vs. *suspect*.

## Phase 5 — Detection engineering (Track 5)
Generalize the findings into rules: Empire `-enc` PowerShell, **PowerShell-parented-by-WMI** (the highest-value lateral detection), schtasks-SYSTEM-encoded persistence, multi-signal C2 beacon, SSH brute, IDS trojan category. Tune + write metadata; prefer **RBA** (an APT trips many low-confidence rules — risk-score the host).

## Phase 6 — Purple team (Track 6)
ATT&CK-map the incident; build the detect-vs-prevent matrix; rank control gaps (WMI lateral + egress filtering break the chain earliest); flag the **macOS gap** (osquery present but no real-time EDR — detection was IDS-first).

## Phase 7 — Reporting (Track 7)
Exec summary + **dwell time (~9 days — the APT hallmark)** + IOC package + lessons. Contrast with v1: here the value isn't a 16-minute timeline, it's explaining a *long, quiet* dwell across surfaces.

## Phase 8 — Threat-intel pivot (Track 8)
Attribute (Taedonggang + Empire framework + Quimitchin), cluster the footprints (core Windows intrusion vs. macOS vs. SSH noise), Diamond-model it, and produce an intel product — **without forcing links the evidence doesn't support**.

---

## What "done" looks like
From one alert: a triage note, a hunted + scoped multi-OS APT, network + endpoint corroboration, a containment decision, new detections, an ATT&CK-mapped gap list, a full report with a **9-day dwell**, and a confidence-rated attribution. That's APT-grade IR — the handoffs between disciplines, on a hard target.

➡️ Reference values per phase: [SOLUTIONS.md](SOLUTIONS.md).
