# Playbook 6 — Web Application Attack Detection — Solutions

Reference answers, verified against the loaded `index=botsv1` / `index=botsv2`.
Questions: [../question/06-web-application-attack-detection.md](../question/06-web-application-attack-detection.md)

---

## Primary case (v1: Joomla)

### Steps 1–2 — Alert / request review
```spl
index=botsv1 sourcetype=stream:http dest_ip="192.168.250.70"
| stats count dc(uri_path) as unique_paths by src_ip | sort - unique_paths
```
**`40.80.148.42`** dominates by path diversity — the scanner.

### Step 3 — Attack type
```spl
index=botsv1 sourcetype=stream:http dest_ip="192.168.250.70" src_ip="40.80.148.42"
  (uri="*union*" OR uri="*select*" OR uri="*'*" OR uri="*..%2f*")
| stats count
```
~600 injection-marker hits. UA: `Mozilla/5.0 (Windows NT 6.1; WOW64) … Chrome/41.0.2228.0 Safari/537.21` (Acunetix Web Vulnerability Scanner signature).

### Step 4 — Uploads
```spl
index=botsv1 sourcetype=stream:http dest_ip="192.168.250.70" src_ip="40.80.148.42" part_filename=*
```
`agent.php` and `joomla.json` uploaded — a scripting-language extension is an immediate red flag.

### Step 5 — Impact validation
```spl
index=botsv1 sourcetype=stream:http src_ip="192.168.250.70" http_method=GET
| search "*.jpeg" OR "*.jpg" OR "*.png"
```
The server serves **`poisonivy-is-coming-for-you-batman.jpeg`** — confirmed defacement, not just an attempted upload.

---

## Alternate case (v2: SQLi + XSS against brewertalk.com)

**SQLi:**
```spl
index=botsv2 sourcetype=stream:http src_ip="45.77.65.211" uri_path="/member.php"
| eval sqli=if(match(form_data,"(?i)updatexml"),1,0) | stats sum(sqli) as hits count
```
**136** hits — the `updatexml()` error-based SQL injection technique against `/member.php`.

**XSS → session hijacking (freshly verified, not previously documented in this lab):**
```spl
index=botsv2 sourcetype=stream:http "1502408189"
| table _time src_ip dest_ip uri_path cookie
```
The **same admin session cookie** (`sid=4a06e3f4a6eb6ba1501c4eb7f9b25228; adminsid=9267f9cec584473a8d151c25ddb691f1`) appears from **two different sources** within the same minute on `2017-08-16`:
- `71.39.18.125` → `172.31.4.249` at `15:19:17` (the legitimate user's real browsing)
- **`10.0.2.109`** → `52.42.208.228` (brewertalk.com's real public IP) at `15:18:38` — and `10.0.2.109` is the **same host that later becomes the first internal system beaconing the Empire C2**, per the specialized botsv2 DFIR track's timeline (first C2 contact ~Aug 15 23:36).

This is a genuine session-hijack: the admin cookie was stolen (consistent with an XSS-based theft, per the official BOTS v2 walkthrough's documented cookie-theft scenario) and replayed from an already-compromised internal host to interact with brewertalk.com's admin panel. The official walkthrough documents the outcome as a new forum account (`kIagerfield`) created via this stolen session — a spear-phishing enabler this lab's live data corroborates the mechanism for, even though this session didn't independently re-isolate the exact account-creation POST event.

---

*Official BOTS walkthroughs for details not independently re-extractable in this lab: [`../splunk-bots/`](../../splunk-bots/).*
