# Specialized Tracks — Threat Hunting · DFIR · Network Forensics

Advanced, **methodology-driven** tracks that go beyond the guided Q&A packs
in [`../self-practice/`](../self-practice/) and
[`../Bots Training/`](../Bots%20Training/).
Instead of "find the one answer," each exercise hands you a **hypothesis or
a case** and grades the *process*: pivot across sourcetypes, corroborate,
and document — including confident **negative** results.

## Organized by dataset

Each dataset gets its own subfolder (mirroring [`../splunk-bots/`](../splunk-bots/)),
because the incidents — and therefore the hunts — are completely different.

| Folder | Dataset | Incidents it covers | Status |
|---|---|---|---|
| [**botsv1/**](botsv1/) | BOTS v1 (`index=botsv1`, loaded by `./setup.sh`) | Web intrusion & defacement (2016-08-10) + Cerber ransomware (2016-08-24) | ✅ available |
| [**botsv2/**](botsv2/) | BOTS v2 (`./setup.sh --v2`) | Taedonggang APT vs *froth.ly* (PowerShell Empire, WMI lateral, multi-OS) | ✅ available — 8 tracks + capstone (do the [v2 fundamentals pack](../self-practice/botsv2/) first) |
| _botsv3/_ | BOTS v3 (`./setup.sh --v3`) | AWS + O365 cloud / identity incident | ⬜ not built yet |

> **Why per-dataset matters for expertise:** BOTS v1 is a single on-prem,
> 2016-era environment. Real specialization needs *variety* — different
> attack types, cloud/identity telemetry, newer TTPs. Adding v2/v3 tracks
> is the highest-value way to broaden this beyond one static incident.

## Start here

➡️ [**botsv1/README.md**](botsv1/README.md) — **8 tracks**: Threat Hunting · DFIR · Network Forensics (2 continuous scenarios each) + Detection Engineering · Purple Team · Reporting · Threat-Intel, all tied together by a full-incident [capstone](botsv1/04-capstone-full-incident.md). Reference answers in [SOLUTIONS](botsv1/SOLUTIONS.md).
