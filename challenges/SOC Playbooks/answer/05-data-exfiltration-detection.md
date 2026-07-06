# Playbook 5 — Data Exfiltration Detection — Solutions

Reference answers, verified against the loaded `index=botsv2`.
Questions: [../question/05-data-exfiltration-detection.md](../question/05-data-exfiltration-detection.md)

---

### Step 1–2 — Alert & destination
```spl
index=botsv2 sourcetype=stream:smtp "attach_filename{}"=* "berkbeer.com"
```
Or directly:
```spl
index=botsv2 sourcetype=stream:smtp "Saccharomyces_cerevisiae_patent.docx"
| rex field=_raw "From: (?<mail_from>[^\r\n]+)"
| rex field=_raw "To: \"(?<mail_to>[^\"]+)\""
```
`aturing@froth.ly` (**Amber Turing**, Frothly) → `hbernhard@berkbeer.com` (**Heinz Bernhard**, a named contact at competitor **Berk Beer**). Subject: `RE: Heinz Bernhard Contact Information` — a *reply*, meaning there's an earlier thread establishing contact. Timestamp: `2017-08-30 15:07:56`.

### Step 3 — Volume / thread
Attachment: `Saccharomyces_cerevisiae_patent.docx` — a patent-relevant research document, i.e. proprietary IP, not routine correspondence.

### Step 4 — Business justification (behavioral corroboration)
```spl
index=botsv2 tor amber
```
TOR-related artifacts present across `wineventlog:security`, `winregistry`, `xmlwineventlog:…sysmon…`, and `winhostmon` on **`wrk-aturing`** — a privacy/anonymity browser installed on this user's workstation (per the official BOTS v2 walkthrough, version `7.0.4`, explicitly to obfuscate her web browsing). Combined with a personal email account documented elsewhere in her mail traffic (`ambersthebest@yeastiebeastie.com`, per official walkthrough Q107 — recovered via base64-decoding a `content_body` field this lab's raw extraction doesn't expose cleanly), there's no innocent explanation left standing.

### A worthwhile pivot
```spl
index=botsv2 sourcetype=stream:smtp "Saccharomyces_cerevisiae_patent.docx"
| rex field=_raw "(?i)x-originating-ip: \[(?<orig_ip>[^\]]+)\]"
```
Originating IP: **`71.39.18.125`**. Cross-reference:
```spl
index=botsv2 sourcetype=linux_secure "Accepted password"
| rex "Accepted password for (?<user>\S+) from (?<src_ip>\S+)"
```
The **exact same IP** (`71.39.18.125`) is the source of the one successful SSH login — for a *different* user, **`klager`** — earlier in the month. Not proof of collusion (shared network/VPN/ISP are all plausible), but exactly the kind of lead that belongs in a handoff, not buried.

---

➡️ Next: [Playbook 6 — Web Application Attack Detection](06-web-application-attack-detection.md)
