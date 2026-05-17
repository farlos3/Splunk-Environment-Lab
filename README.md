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

```
┌────────────────────────────────────────────────────────────────────┐
│                    Splunk container (splunk-lab)                   │
│                                                                    │
│   /opt/splunk/etc/apps/botsv1_data_set/  ← splunklab_splunk-botsv1 │
│   /opt/splunk/etc/apps/botsv2_data_set/  ← splunklab_splunk-botsv2 │
│   /opt/splunk/etc/apps/botsv3_data_set/  ← splunklab_splunk-botsv3 │
│                                                                    │
│   /opt/splunk/var                        ← splunklab_splunk-var    │
│   /opt/splunk/etc/users                  ← splunklab_splunk-etc-…  │
└────────────────────────────────────────────────────────────────────┘
       Web UI :8000   HEC :8088   Mgmt :8089   Fwd :9997   Syslog :1514

   bots-data/botsv1/ (host staging) ─one-time copy─▶ splunk-botsv1 volume
   bots-data/botsv2/                                 splunk-botsv2 volume
   bots-data/botsv3/                                 splunk-botsv3 volume
```

> **Why a volume, not a bind mount?**  Docker Desktop on Windows exposes
> host files via gRPC-FUSE, which lacks the file-locking and mmap
> semantics Splunk's `validatedb` requires. Splunk refuses to use such
> paths as an index home ("unusable filesystem"). So we stage each
> dataset in `bots-data/bots<vN>/` on the host, then copy it into a
> named volume that lives on Docker's native ext4 — Splunk is happy
> with that.

## Quick start

```powershell
# Windows
.\setup.ps1                  # default: BOTSv1 only
.\setup.ps1 -V1 -V2          # BOTSv1 + BOTSv2
.\setup.ps1 -All             # v1 + v2 + v3
```

```bash
# Linux / macOS
./setup.sh                   # default: BOTSv1 only
./setup.sh --v1 --v2         # BOTSv1 + BOTSv2
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

```powershell
.\setup.ps1 -V2 -UrlV2 https://custom.example/botsv2.tgz   # override URL
.\setup.ps1 -V1 -SkipDownload                              # fail if .tgz not local
.\setup.ps1 -V1 -Force                                     # re-extract AND re-populate volume
```

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
4. Re-run `setup` with `--<vN> --skip-download` (bash) or
   `-<VN> -SkipDownload` (PowerShell)

## Resetting

Splunk Enterprise's free trial lasts 60 days from first boot. After that
it converts to Splunk Free (500 MB/day, no auth, fewer features). BOTS
data is pre-indexed so it keeps working under Free, but to refresh the
trial:

```powershell
.\docker\reset.ps1            # fast — wipes container + state, keeps BOTS volumes
.\docker\reset.ps1 -Full      # nuke everything; next setup re-populates
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

# 4. Firewall traffic — top external destinations by bytes out
index=botsv1 sourcetype=fgt_traffic earliest=0
| stats sum(sentbyte) AS bytes_out by dstip | sort -bytes_out | head 20

# 5. SQL injection probes in IIS logs
index=botsv1 sourcetype=iis ("UNION SELECT" OR "OR 1=1" OR "DROP TABLE") earliest=0
| table _time, c_ip, cs_uri_stem, cs_uri_query

# 6. PowerShell encoded commands (commonly malicious)
index=botsv1 sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
"powershell" CommandLine="*-enc*" earliest=0
| table _time, Computer, User, CommandLine
```

For full walkthroughs of the BOTSv1 scenario (60 official questions +
answer keys), search "BOTSv1 walkthrough" — the community has many
write-ups on Medium and GitHub.

## Folder layout

```
Splunk-Environment-Lab/
├── setup.ps1 / setup.sh        ← one-shot bootstrap (download + extract + copy + up)
├── docker/
│   ├── docker-compose.yml      ← splunk service + named volumes + ports
│   └── reset.ps1 / reset.sh    ← nuke + restart; -Full also wipes BOTS volumes
├── bots-data/                  ← staging area (gitignored — per-version dirs tracked)
│   ├── botsv1/                 ← BOTSv1 archive + extracted app
│   ├── botsv2/                 ← BOTSv2 archive + extracted app
│   └── botsv3/                 ← BOTSv3 archive + extracted app
├── challenges/                 ← bundled practice walkthroughs
│   └── splunk-bots/            ← vendored from github.com/chan2git/splunk-bots
├── .gitignore                  ← blocks all huge files
└── README.md
```

After a successful first run, `bots-data/bots<vN>/` is a backup —
Splunk is reading from the named volumes, not from these folders. You
can delete their contents (or just the `.tgz` files) to reclaim disk,
at the cost of having to re-download/re-extract before the next
`setup -Force` or `reset -Full`.

## Ports exposed

| Port | Service | Notes |
|---|---|---|
| 8000 | Splunk Web | http://localhost:8000 |
| 8088 | HTTP Event Collector | token env var: `SPLUNK_HEC_TOKEN` |
| 8089 | Splunk REST / Management | for CLI / API |
| 9997 | Forwarder receiver | for a future Universal Forwarder |
| 1514/tcp+udp | Syslog | non-privileged (container can't bind 514) |
