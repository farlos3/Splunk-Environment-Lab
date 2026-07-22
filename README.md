# Splunk Environment Lab

[![GitHub Repo](https://img.shields.io/badge/GitHub-Repo-181717?logo=github&logoColor=white)](https://github.com/farlos3/Splunk-Environment-Lab)
[![Docker Compose](https://img.shields.io/badge/Docker-Compose-2496ED?logo=docker&logoColor=white)](https://docs.docker.com/compose/)
[![Splunk Docs](https://img.shields.io/badge/Splunk-Docs-FFB000?logo=splunk&logoColor=black)](https://docs.splunk.com/Documentation/Splunk)
[![SOC](https://img.shields.io/badge/SOC-Operations-0B7285)](https://github.com/icdfa/soc-training-program)
[![BOTS v1](https://img.shields.io/badge/BOTS-v1-000000)](https://github.com/splunk/botsv1)

Local Splunk Enterprise running in Docker, pre-wired to load Splunk's
**BOTS** (Boss of the SOC) datasets — real attack telemetry from
Splunk's SOC training competitions. Pick any combination of **v1**,
**v2**, **v3** at setup time. Use them to practice SPL, build
detections, and validate dashboards against data that looks like a
real incident.

Container/volume layout and why BOTS data goes through a staging copy
instead of a bind mount: **[docker/ARCHITECTURE.md](docker/ARCHITECTURE.md)**.

## Quick start

```bash
./setup.sh                   # interactive: prompts for v1 / v2 / v3 / all
./setup.sh --v1 --v2         # BOTSv1 + BOTSv2 (flags skip the prompt)
./setup.sh --all             # v1 + v2 + v3
```

For each selected dataset the script will:
1. Download `<vN>` `.tgz` into `bots-data/bots<vN>/` — resumes if interrupted
2. Validate + extract into `bots-data/bots<vN>/`
3. Copy it into the `splunk-bots<vN>` Docker volume (one-time)

Then it brings the container up, waits for healthy, and verifies each
loaded `bots<vN>` index has events.

Approximate sizes:

| Dataset | Compressed | First-run time |
| --- | --- | --- |
| BOTSv1 | ~6 GB | ~30-60 min |
| BOTSv2 | ~28 GB | hours |
| BOTSv3 | ~3.5 GB | ~20-40 min |

When it finishes, open <http://localhost:8000> (`admin` / `p@ssw0rd`),
set the time picker to **All time**, and run any of:

```spl
index=botsv1 earliest=0 | stats count by sourcetype
index=botsv2 earliest=0 | stats count by sourcetype
index=botsv3 earliest=0 | stats count by sourcetype
```

For BOTSv1 you should see ~33 million events across
`WinEventLog:Security`, `fgt_traffic`,
`XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`, `iis`,
`nessus:scan`, and more.

### Setup script options

```bash
./setup.sh --v2 --url-v2 https://custom.example/botsv2.tgz
./setup.sh --v1 --skip-download
./setup.sh --v1 --force
```

### If auto-download fails

Splunk has moved the BOTS download URLs several times. If the script
reports a URL is dead:

1. Open <https://github.com/splunk/botsv1> (or `botsv2` / `botsv3`)
2. Follow the current Download section
3. Drop the `.tgz` into `bots-data/bots<vN>/`
4. Re-run `./setup.sh --<vN> --skip-download`

## Resetting

Splunk Enterprise's free trial lasts 60 days from first boot. After that
it converts to Splunk Free (500 MB/day, no auth, fewer features). BOTS
data is pre-indexed so it keeps working under Free, but to refresh the
trial:

```bash
./docker/reset.sh             # fast — wipes container + state, keeps BOTS volumes
./docker/reset.sh --full      # nuke everything; next setup re-populates
```

Fast reset (default) wipes `splunk-var` (trial state, _internal logs)
and `splunk-etc-users` (user dashboards) but keeps the
`splunk-botsv1` / `splunk-botsv2` / `splunk-botsv3` volumes intact —
so the BOTS data is immediately available after the next boot, no
re-copy needed.

## Practice — BOTSv1 challenges

`challenges/splunk-bots/` is bundled in this repo as the **primary
practice resource**. It has completed walkthrough solutions for all
three BOTS versions (`botsv1/`, `botsv2/`, `botsv3/`) with SPL queries
and investigation steps.

> **Source / credit:** the contents of `challenges/splunk-bots/` are
> vendored from <https://github.com/chan2git/splunk-bots>. Check that
> upstream for the latest revisions or to file issues against the
> walkthroughs.

> Tip: try answering each official question yourself first using the
> sample searches below, then check `challenges/splunk-bots/botsv1/` to
> compare your SPL with the walkthrough's.

### Reference write-ups (when you get stuck)

These are independent BOTSv1 write-ups by other practitioners — useful
for a different angle or for the ransomware-specific questions:

- [Sabina Aliyeva — BOTSv1 Writeup](https://medium.com/@sabinaaliy3va/splunk-botsv1-writeup-47b73a2eadac) — clean step-by-step through the main scenario
- [Micah S0day — Splunk BOTSv1 Walkthrough](https://micahs0day.github.io/Splunk_BOTSv1(Boss-of-the-SOC)/) — detailed write-up with screenshots
- [JBXSec — BOTS Ransomware Challenge](https://medium.com/@JBXSec/splunk-bots-ransomware-challenge-992ea6a62fc9) — focuses on the ransomware track
- [HackerHermanos — BOTSv1 Ransomware](https://hackerhermanos.com/posts/splunk-bots-v1-ransomware/) — ransomware deep-dive with IoCs

## Sample searches to try

```spl
# 1. What sourcetypes exist and how big are they?
index=botsv1 earliest=0 | stats count by sourcetype | sort -count

# 2. Brute force — Windows failed logons by source IP
index=botsv1 sourcetype=WinEventLog:Security EventCode=4625 earliest=0
| stats count by src_ip, user | sort -count | head 20

# 3. Top processes seen by Sysmon
index=botsv1 sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=1 earliest=0
| stats count by Image | sort -count | head 20
```

For full walkthroughs of the BOTSv1 scenario (60 official questions +
answer keys), search "BOTSv1 walkthrough" — the community has many
write-ups on Medium and GitHub.

## CTF scoreboard (optional)

A real jeopardy-style scoreboard UI — question list, answer submission,
scoring, hints — on top of the BOTS data, using Splunk's own
[`SA-ctf_scoreboard`](https://github.com/splunk/SA-ctf_scoreboard)
(original author: Dave Herrald) +
[`SA-ctf_scoreboard_admin`](https://github.com/splunk/SA-ctf_scoreboard_admin)
apps — the same apps Splunk used internally to run early BOTS
competitions (deprecated by Splunk as of January 2022, still functional
here). Installed automatically by `setup.sh` — running it interactively
also asks which question set to load:

```bash
./setup.sh --v1                              # BOTSv1 data + v1 writeup questions (default)
./setup.sh --v2 --ctf-questions v2            # explicit
./setup.sh --v1 --ctf-questions v1-official   # load your own official set instead
```

Then open <http://localhost:8000/en-US/app/SA-ctf_scoreboard/welcome>
(`admin` / `p@ssw0rd`). By default questions come from
`docker/ctf_seed_data/<vN>_writeups/`, derived from the
`challenges/splunk-bots/` walkthroughs below — only one question set can
be "live" at a time (see why, plus full setup/config detail,
troubleshooting, and the compatibility patch this lab needed, in
**[docker/CTF_SCOREBOARD.md](docker/CTF_SCOREBOARD.md)**). Want the real
Splunk-authored questions instead of the write-up-derived set? See
**"Requesting the official question set"** in
[docker/CTF_SCOREBOARD.md](docker/CTF_SCOREBOARD.md) for how to email
Splunk and get them.

## Attack data micro-CTF (optional, opt-in)

A second, independent practice pack — 34 original deep-dive questions
covering Malware Analysis + Log Analysis, one per malware family, built
from real endpoint telemetry in
[splunk/attack_data](https://github.com/splunk/attack_data) (the same
dataset Splunk uses to test its own ESCU detections). Unlike the CTF
scoreboard above or the BOTS challenges, there's no existing answer key
to import here — every question was written by actually searching the
raw Sysmon/Windows Event Log data for a verifiable artifact and
confirming the answer with real SPL. Standalone from `SA-ctf_scoreboard`
— no scored UI, just a markdown Q&A pack (same convention as
`challenges/splunk-bots/`) plus a dedicated Splunk index.

```bash
./setup.sh --v1 --attackdata   # any --vN works; --attackdata is independent of BOTS version
```

Downloads ~330 MB of per-family log samples (one small scenario per
family) and ingests them into a new `attack_data` index via
`splunk add oneshot`. See
**[challenges/attack-data-ctf/README.md](challenges/attack-data-ctf/README.md)**
for how to use the pack, and
**[docker/apps/attack_data_ingest/](docker/apps/attack_data_ingest/)**
for the index/field-extraction config. Requires python3 (same as the CTF
scoreboard's KV import, for downloading + parsing the file manifest).

## Folder layout

```
Splunk-Environment-Lab/
├── setup.sh                    ← one-shot bootstrap (download + extract + copy + up)
├── docker/
│   ├── docker-compose.yml      ← splunk service + named volumes + ports
│   ├── reset.sh                ← nuke + restart; --full also wipes BOTS volumes
│   ├── CTF_SCOREBOARD.md       ← CTF scoreboard setup/config detail, troubleshooting
│   ├── apps/                   ← bind-mounted Splunk apps (sysmon extractions, CTF scoreboard, attack_data_ingest)
│   ├── ctf_seed_data/          ← question/answer/hint CSVs, per BOTS version
│   └── download_attack_data.py ← fetches attack-data/*/*.log from splunk/attack_data (Git LFS via CDN)
├── bots-data/                  ← staging area (gitignored — per-version dirs tracked)
│   ├── botsv1/                 ← BOTSv1 archive + extracted app
│   ├── botsv2/                 ← BOTSv2 archive + extracted app
│   └── botsv3/                 ← BOTSv3 archive + extracted app
├── attack-data/                ← staging area for the attack-data micro-CTF (gitignored *.log, manifest.json tracked)
├── challenges/                 ← bundled practice walkthroughs
│   ├── splunk-bots/            ← vendored from github.com/chan2git/splunk-bots
│   └── attack-data-ctf/        ← original Q&A pack for the attack-data micro-CTF
├── .gitignore                  ← blocks all huge files
└── README.md
```

After a successful first run, `bots-data/bots<vN>/` is a backup —
Splunk is reading from the named volumes, not from these folders. You
can delete their contents (or just the `.tgz` files) to reclaim disk,
at the cost of having to re-download/re-extract before the next
`./setup.sh --force` or `./docker/reset.sh --full`.

## Continue your training — get certified

This lab builds the SPL and blue-team investigation skills; a
certification is a way to get that validated externally. **Security
Blue Team** runs **Blue Team Level 1 (BTL1)**, a practical, hands-on
exam (not multiple-choice) covering SOC fundamentals, phishing/log
analysis, digital forensics, and incident response — a natural next
step after working through the BOTS challenges here.

- **[blueteamlabs.online](https://blueteamlabs.online/home)** —
  Security Blue Team's lab platform, with investigation-style
  challenges in the same format as the BTL1 exam. A good way to gauge
  readiness before sitting the exam.
- BTL1 is timed and hands-on, not memorization-based — the muscle
  memory built here (pivoting across sourcetypes, writing SPL from
  scratch, building a timeline across BOTSv1/v2/v3) transfers directly.