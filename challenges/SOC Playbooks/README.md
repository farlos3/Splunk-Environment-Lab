# SOC Playbooks — Practice Pack

Six real-world SOC investigation playbooks (Phishing, Malware Alert, Brute
Force Login, Privilege Escalation, Data Exfiltration, Web Application Attack),
each practiced against **real, verified events** in the BOTS v1/v2 datasets
already loaded in this lab. Every playbook step maps to an actual pivot you
can run right now — nothing here is a hypothetical.

> Playbooks adapted from *Ken Café — SOC Analyst Playbooks*. The generic
> workflow/tools/escalation criteria are the source material; the case data,
> SPL, and verified findings below are specific to this lab's `index=botsv1`
> and `index=botsv2`.

---

## Which playbook uses which dataset

| # | Playbook | Primary dataset | The real incident | Alternate dataset | Solutions |
|---|---|---|---|---|---|
| 1 | [Phishing Email Investigation](question/01-phishing-email-investigation.md) | **v2** | Taedonggang's password-protected `invoice.zip` lure to Frothly | — | [→](answer/01-phishing-email-investigation.md) |
| 2 | [Malware Alert Investigation](question/02-malware-alert-investigation.md) | **v1** | Cerber ransomware on `we8105desk` | v2: PowerShell Empire stager | [→](answer/02-malware-alert-investigation.md) |
| 3 | [Brute Force Login Detection](question/03-brute-force-login-detection.md) | **v1** | Joomla admin brute force (`23.22.63.114`) | v2: SSH brute force on `eridanus` + `gacrux` | [→](answer/03-brute-force-login-detection.md) |
| 4 | [Privilege Escalation Detection](question/04-privilege-escalation-detection.md) | **v2** | Backdoor account `svcvnc` added to local Administrators on 4 hosts, then an audit-log clear | — | [→](answer/04-privilege-escalation-detection.md) |
| 5 | [Data Exfiltration Detection](question/05-data-exfiltration-detection.md) | **v2** | Amber Turing emails a patent document to a competitor (insider threat) | — | [→](answer/05-data-exfiltration-detection.md) |
| 6 | [Web Application Attack Detection](question/06-web-application-attack-detection.md) | **v1** | SQLi + scanning against `imreallynotbatman.com` | v2: SQLi + XSS against `brewertalk.com` | [→](answer/06-web-application-attack-detection.md) |

> **Playbook 4 note:** the `svcvnc` backdoor-account chain isn't documented
> anywhere else in this lab's packs — it was discovered verifying this pack
> against the live data. It's a genuine, previously-unsurfaced angle on the
> v2 Taedonggang/Empire incident.

## Prerequisites

1. Lab running — `http://localhost:8000` (admin / `p@ssw0rd`)
2. Load whichever dataset(s) the playbook you're doing needs:
   - v1: `./setup.sh` (default) — Playbooks 2, 3, 6 (primary paths)
   - v2: `./setup.sh --v2` — Playbooks 1, 4, 5, and the alternate paths for 2/3/6
   - Both datasets loaded together is memory-heavy — if the container gets
     OOM-killed, load one dataset at a time.
3. You've done (or are comfortable with) the [self-practice](../self-practice/)
   fundamentals — this pack assumes SPL fluency, not "what is `stats`."

## How to use this pack

Each playbook file mirrors the source poster's **numbered workflow**, but
every step is a **task against real data** instead of a generic checklist
item. For each step you get:
- The **task** — what an analyst would actually be asked to produce
- A **prose hint** — sourcetype, fields, and approach; not the finished SPL
- Space to fill in your own findings (IPs, hashes, users, timestamps) as you go

Try each step yourself before checking the matching file in [`answer/`](answer/) — each
playbook has its own solutions file (same name as its question file) with the
full runnable SPL and the verified real values for every step. At the end of
each playbook you assemble a mini incident report using the same IOC
checklist / severity guide as the source poster.

## Time picker quick reference

| Dataset | Incident window |
|---|---|
| v1 — Cerber ransomware (Playbooks 2, 3-alt is n/a) | `08/24/2016 00:00:00` → `08/25/2016 00:00:00` |
| v1 — Web/Joomla attack (Playbooks 3, 6) | `08/10/2016 00:00:00` → `08/12/2016 00:00:00` |
| v2 — Phishing / privesc / exfil / Empire (Playbooks 1, 2-alt, 4, 5) | `08/15/2017 00:00:00` → `08/31/2017 00:00:00` |
| v2 — SSH brute force / brewertalk (Playbooks 3-alt, 6-alt) | **All time** (dataset-wide counts) |

Each playbook file repeats the exact window it needs — this table is just the overview.

## Severity guide (from the source poster)

| Level | Response time | Example from this pack |
|---|---|---|
| 🔴 Critical | 0–15 min | Cerber encryption in progress (Playbook 2) |
| 🟠 High | 15–60 min | Brute force success, privilege escalation (Playbooks 3, 4) |
| 🟡 Medium | 1–4 hours | Suspicious login, policy violation |
| 🔵 Low | 4–24 hours | Scan / recon-only activity |

---

*Reference answers: [`answer/`](answer/) (one file per playbook). Official BOTS walkthroughs live in [`../splunk-bots/`](../splunk-bots/).*
