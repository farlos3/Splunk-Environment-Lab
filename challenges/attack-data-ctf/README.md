# Attack Data micro-CTF — Malware & Log Analysis

34 deep-dive questions, one per malware family, built from real endpoint
telemetry in [splunk/attack_data](https://github.com/splunk/attack_data) —
the same dataset Splunk uses to test its own detection content (ESCU).
Unlike `challenges/splunk-bots/`, none of these questions come from an
existing answer key: each was written by actually searching the raw
Sysmon/Windows Event Log/PowerShell-Operational data for a distinctive,
verifiable artifact (a dropped file, a C2 domain, a hijacked registry key,
a disabled service, an injected process...) and confirming the answer with
real SPL against the ingested index — the reverse of the BOTS pack, where
the walkthroughs already existed and got imported as-is.

Standalone from the CTF scoreboard (`SA-ctf_scoreboard`) — no scored UI,
just this file pair plus the `attack_data` Splunk index. Nothing stops you
from also hand-loading these into the scoreboard's KV store later if you
want scoring, but that's not wired up here.

## Setup

```bash
./setup.sh --v1 --attackdata   # or any --vN; --attackdata is independent of BOTS version
```

Ingests 34 small per-family log samples (~330 MB total, one scenario per
family — the smallest available where attack_data ships several) into a
new `attack_data` Splunk index. See the root README's "Attack data
micro-CTF" section for flags, requirements, and troubleshooting.

## How to use this pack

1. Open [questions.md](questions.md) — try each question yourself first.
   Every question names the `host` value (the malware family) to scope
   your search to, e.g. `index=attack_data host=qakbot`.
2. Hints in questions.md are prose nudges — a field name or command
   fragment, never full SPL.
3. Check your answer against [SOLUTIONS.md](SOLUTIONS.md), which has the
   full investigation + SPL + verified answer for each.

## Field reference

- `host` = malware family (matches the folder name under
  `attack-data/`, e.g. `host=lockbit_ransomware`)
- `source` = the original Windows Event Log channel (e.g.
  `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`)
- `sourcetype` = `XmlWinEventLog` for every Windows channel (Sysmon,
  Security, PowerShell-Operational, System — they're distinguished by
  `source`, not `sourcetype`), or `sysmon:linux` for the 3 Linux hosts
  (`acidrain`, `awfulshred`, `cyclopsblink`)
- `EventCode` = lifted from `<EventID>`, same convention as classic
  WinEventLog (EventCode=1 → process create, =11 → file create, =3 →
  network connect, ...)
- `Image`/`CommandLine`/`ParentImage`/`TargetFilename`/etc. — extracted
  generically from every `<Data Name='...'>` element, so field
  availability depends on which EventCode you're looking at (a
  CreateRemoteThread event has `SourceImage`/`TargetImage`, not `Image`)

## A note on noise

Several of these captures are dominated by the Splunk Universal
Forwarder's own housekeeping processes (`splunk-admon.exe`,
`splunk-powershell.exe`, `splunk-winevtlog.exe`, ...) rather than the
actual malware activity — the same noise-filtering skill the BOTS
challenges teach. A few questions below deliberately ask you to identify
*that* rather than pretend every event is malicious.

## Credits

Log data: [splunk/attack_data](https://github.com/splunk/attack_data)
(Apache-2.0). Full per-scenario metadata (author, date, environment) is
in each family's `.yml` under `attack-data/<family>/`; by dataset count,
scenario authorship breaks down as:

- **Teoderick Contreras** (Splunk) — the large majority of families
  (acidrain, agent_tesla, amadey, awfulshred, azorult, brute_ratel,
  chaos_ransomware, clop, conti, cyclopsblink, dcrat, doublezero_wiper,
  fin7, hermetic_wiper, icedid, industroyer2, lockbit_ransomware,
  olympic_destroyer, prestige_ransomware, qakbot, redline, remcos,
  swift_slicer, vilsel, warzone_rat, winpeas, winter-vivern)
- **Steven Dick** — gootloader
- **Raven Tait** (Splunk) — notdoor
- **Patrick Bareiss** — ryuk
- **Michael Haag** — snakemalware
- Auto-generated (`dataset_analyzer.py`, no named author) — ransomware_ttp, revil, trickbot

A few families' metadata also links further threat-intel reading, kept
here rather than only in the `.yml`:

- **amadey** — [Malpedia: win.amadey](https://malpedia.caad.fkie.fraunhofer.de/details/win.amadey)
- **brute_ratel** — [Unit 42: Brute Ratel C4 Tool](https://unit42.paloaltonetworks.com/brute-ratel-c4-tool/)
- **warzone_rat** — [Malpedia: win.ave_maria](https://malpedia.caad.fkie.fraunhofer.de/details/win.ave_maria) (Warzone RAT is also tracked as "Ave Maria")

Questions and answers in this pack (`questions.md`, `SOLUTIONS.md`) are
original, written for this lab by searching the raw data — not derived
from any existing answer key.
