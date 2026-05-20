# Section 3 — SOC Tier 1 Investigations (Q31–Q50)

🟠 **Level:** Intermediate
🎯 **Goal:** Practice the investigative mindset — form a hypothesis, gather evidence, build a timeline, and extract IOCs.

> Questions in this section often have **multiple valid approaches** — what matters is the reasoning, not memorizing one command.

---

## Scenario A: Web Server Attack (Q31–Q40)

> The website `imreallynotbatman.com` has been defaced. As the Tier 1 analyst on shift, you need to answer the following.
>
> **Time picker for this scenario:** `8/10/2016 00:00:00` → `8/12/2016 00:00:00`

### Q31 — Identify the victim

What is the IP address of the `imreallynotbatman.com` web server?

**Hint:** Asset identification before attacker attribution. A public web server is the most-contacted destination in inbound HTTP — rank `dest_ip` by event volume and the top row should be obvious.
**SOC angle:** Before chasing the attacker, identify the asset under attack.

---

### Q32 — Reconnaissance phase

Is anyone scanning the web server? Find the top external `src_ip` values by
both event count and distinct path count (`uri_path`).

**Hint:** Two metrics per source: raw event count and *path diversity*. A normal user hits a handful of distinct paths; a scanner hits hundreds. You need both `count` and `dc(uri_path)` in the same `stats` call.
**SOC angle:** Vulnerability scanners request many paths in a short time — high `unique_paths` per source is the giveaway.

---

### Q33 — Scanner identification

For the scanning IP from Q32, inspect `http_user_agent`. Which scanning tool was used?

**Hint:** Off-the-shelf scanners almost always leak their name in the User-Agent. Pivot on the source IP from Q32 and look at the top UA strings.
**SOC angle:** Scanners usually identify themselves in the User-Agent string (Nikto, Acunetix, sqlmap, OWASP ZAP, ...).

---

### Q34 — Brute force detection

Did a brute-force attack hit the login page? Count POST requests to the
login URL grouped by `src_ip`.

**Hint:** Brute force = many POSTs to a login URL from one source. Filter on method + path, group by source, and look at whether the count distribution has a clear outlier.
**SOC angle:** A single IP issuing hundreds of POSTs to a login endpoint in a short window is brute force.

---

### Q35 — Attack volume and duration

For the attacker IP from Q34, how many login attempts were made, and over
how long? Report the start time, end time, and duration in minutes.

**Hint:** Three numbers in one `stats`: total count, earliest event time, latest event time. The duration is just `(latest - earliest)` in epoch seconds — divide by 60 for minutes and use `strftime` for the readable start/end.
**SOC angle:** Always report the start and end of an attack window in any triage note.

---

### Q36 — Unique passwords tried

How many distinct passwords did the attacker try?

**Hint:** The submitted credentials ride in `form_data`, URL-encoded as something like `username=...&passwd=...`. Pull the password into its own field with `rex` (capture everything between `passwd=` and the next `&`), then distinct-count.
**SOC angle:** A wordlist tells you something about the attacker — dictionary attack vs. targeted, English vs. localized, hash-cracked vs. random.

---

### Q37 — Which password succeeded?

Which password resulted in a **successful** login? Spotting it requires
comparing response sizes — most attempts return a "failed" page of a
consistent size; the successful one will differ.

**Hint:** Reuse the `rex` extraction from Q36 to get `pwd`, then look at the response side-channel. `bytes_out` (or `status`) for the failed attempts will cluster around one value; the success is the single row that doesn't fit the cluster.
**SOC angle:** When you can't see content directly, look for response-size or status-code outliers.

---

### Q38 — Post-breach file upload

After successful login, was anything uploaded? Find the file upload request.

**Hint:** File uploads use `multipart/form-data`, which leaves `Content-Disposition` headers in the body. Constrain to POSTs from the attacker IP after the successful-login timestamp from Q37, and look for either an obvious upload path or that `Content-Disposition` marker in `form_data`.
**SOC angle:** Web-shell upload is the typical pivot from "logged in" to "owns the server".

---

### Q39 — Defacement file

What is the filename used for the defacement (image or HTML page)?

**Hint:** Multipart uploads embed a `filename="..."` token in the body. Same `rex` technique as Q36/Q37 — capture everything between the quotes — then filter to the rows where the field is non-null.
**SOC angle:** The chosen filename often hints at the threat actor or campaign.

---

### Q40 — IOC summary for Scenario A

Summarize the IOCs from this incident:
- Attacker IP(s)
- Scanner tool / User-Agent
- Targeted username
- Successful password
- Uploaded filename (with hash if available)

**SOC angle:** A clean IOC list is the deliverable Tier 1 hands to Tier 2 / Incident Response — completeness is what makes the handoff useful.

---

## Scenario B: Ransomware Outbreak (Q41–Q50)

> Workstation `we8105desk` (user `bob.smith`) was hit by **Cerber ransomware** on August 24, 2016.
>
> **Time picker for this scenario:** `8/24/2016 00:00:00` → `8/25/2016 00:00:00`

### Q41 — Patient zero

What is the IP address of `we8105desk`?

**Hint:** Free-text search the hostname across the index and see which IP addresses co-occur on those events. `stats values(src_ip) values(dest_ip) by host` collapses it into one row per host. DHCP and Windows logon events also bind host↔IP if you want a second source.
**SOC angle:** Identify the first infected host — the rest of the investigation hangs on this.

---

### Q42 — First suspicious domain

What is the first suspicious DNS query made by `we8105desk` on 8/24/2016?

**Hint:** Pivot on the host's IP from Q41 against `stream:dns`. Group queries by `earliest(_time)` so you get a chronological list, then eyeball the early rows for the one that doesn't fit — random-looking labels, weird TLDs, long names.
**SOC angle:** Drive-by and phishing landing pages routinely use throwaway domains.

---

### Q43 — Initial dropper

Was an executable or script run on `we8105desk` just before the ransomware
fired? Look at process-creation events around the infection time.

**Hint:** Walk the host's process-creation events (Sysmon EID 1) in chronological order. The CommandLine and Image fields tell the story. Red flags: scripting hosts (`cscript`/`wscript`/`powershell`), processes launched from `%TEMP%`, anything with `.tmp` or `.vbs` extensions.
**SOC angle:** Cerber's typical chain: VBScript dropper → `.tmp` payload → encryption binary.

---

### Q44 — Suricata Cerber signatures

How many Suricata alerts mention Cerber, and which signature fired the
fewest times?

**Hint:** Free-text "Cerber" against the Suricata sourcetype, then group by signature ID + signature name. Sorting *ascending* surfaces the rarest signature — the opposite of the usual top-N pattern.
**SOC angle:** The lowest-firing signature is often the one that confirms a single high-fidelity action (e.g., the C2 callback after encryption).

---

### Q45 — Ransom note destination

After encryption, Cerber points the user to a payment / decryption portal.
What domain (often a `.onion` mirror or TOR gateway) is involved?

**Hint:** TOR gateways usually carry `onion` somewhere in the hostname; Cerber's family name shows up in its own infrastructure too. Wildcard-search the host's DNS queries for those tokens.
**SOC angle:** The ransom-note URL itself is a high-value IOC for both detection and threat-intel sharing.

---

### Q46 — File-server impact

Which file server did `we8105desk` connect to during the outbreak, and how
many PDFs were encrypted there?

**Hint:** Two separate searches stitched together. (1) SMB share access — look for sourcetypes containing `smb` or Windows EventCodes 5140/5145, group by `dest_ip` + `ShareName` to find the server. (2) Cerber renames encrypted files with a `.cerber` extension — free-text search for that suffix and distinct-count the filenames.
**SOC angle:** Lateral encryption via SMB shares is the textbook ransomware blast-radius expansion.

---

### Q47 — USB device evidence

Was a USB device inserted into Bob Smith's workstation? If so, what was its name?

**Hint:** Windows leaves a trail under the `USBSTOR` registry subkey whenever a removable drive is connected. On a host with Sysmon, that shows up as registry events (EID 12/13) where `TargetObject` contains `USBSTOR`. The device name is embedded in the key path.
**SOC angle:** USB-drop is a classic initial-access technique — always check.

---

### Q48 — Build the attack timeline

Construct a timeline of attack stages ordered by time:
1. Initial recon (suspicious DNS / web visit)
2. Dropper execution
3. C2 callback
4. Encryption begins
5. Encryption complete + ransom note dropped

**Hint:** You already have the individual data points from Q42–Q46. The deliverable here is *synthesis*: pull host-scoped events from the three sourcetypes that matter (process creation, DNS, IDS), unify them on `_time`, and label each row with the stage it represents.
**SOC angle:** A clean timeline is what Tier 2 / Incident Response uses to plan containment.

---

### Q49 — Dwell time

Compute the **dwell time** — minutes between initial compromise and the
start of file encryption.

**Hint:** Two timestamps you already identified in earlier questions: `t0` = first compromise activity (the suspicious DNS/dropper from Q42–Q43), `t1` = first encryption event (the first `.cerber` write from Q46). The delta in epoch seconds divided by 60 is your answer.
**SOC angle:** Dwell time is a top SOC KPI — the lower, the better.

---

### Q50 — Incident report

Write a short incident report (3–5 sentences) covering:
- **What** happened (ransomware family + impact)
- **When** it was detected and when the attack started (dwell time)
- **Where** — host, IP, user
- **How** — initial vector and propagation method
- **IOCs** to hand to the IR team

**Example template:**
```
[Severity: HIGH] Cerber ransomware infection on host we8105desk
(10.x.x.x, user bob.smith) detected at 2016-08-24 HH:MM.
Initial vector: drive-by download from <domain>, followed by VBScript
dropper (<filename>) at HH:MM. Encryption phase started at HH:MM,
affecting N local files and M files on file server 10.x.x.x.
Dwell time: NN minutes. IOCs attached: <domains>, <hashes>, <filenames>.
```
**SOC angle:** A short, complete written summary is the final deliverable of a Tier 1 triage — concise and complete is the standard.

---

🎉 **You've completed all 50 exercises.**

Check your work in → [SOLUTIONS.md](SOLUTIONS.md)

## Next Steps

- Repeat the exercises in 3–7 days without looking at the solutions
- Work through the official BOTS v1 walkthrough in [../splunk-bots/botsv1/](../splunk-bots/botsv1/)
- If you have BOTS v2 / v3, load them with `./setup.sh --v2` or `--v3` for new scenarios
- Practice building dashboards, scheduled alerts, and saved searches from the queries you wrote here
