# Playbook 3 — Brute Force Login Detection

🎯 **Purpose:** Detect and respond to brute force login attempts targeting user accounts and prevent unauthorized access.

**Dataset:** BOTS v1 (`./setup.sh`) · **Case:** the Joomla admin login on `imreallynotbatman.com`.
**Alternate case (BOTS v2):** internet-wide SSH brute force against `gacrux` — see the callouts at the end of each step.

⏱ **Time picker:** `08/10/2016 00:00:00` → `08/12/2016 00:00:00` (v1). For the v2 SSH alternate: **All time** — it's dataset-wide background noise, not a single-day spike.

> **Hints are nudges, not answers.** Full SPL + verified findings are in [Solutions](../answer/03-brute-force-login-detection.md) (Playbook 3).

---

## Playbook workflow

1. Review alert details and timestamp
2. Check failed-logon events
3. Count number of failed attempts
4. Identify the username targeted
5. Identify the source IP address
6. Perform geo-location & IP reputation check
7. Verify if a successful logon followed
8. Block the malicious IP
9. Reset password if account is compromised

---

## Step 1–2 — Alert & Failed Attempts

**Task:** This is a **web application** login, not a Windows domain logon, so the "Event ID 4625" from the quick-reference guide doesn't apply directly — find the web-log equivalent.
**Hint:** Brute force on a web login shows up as repeated `POST` requests to the same login URL. Scope to the web server's `dest_ip` and the login page's path, and filter to `POST`.

## Step 3 — Count Failed Attempts

**Task:** How many login attempts were made, and over what duration?
**Hint:** One `stats` can give you the count *and* the earliest/latest timestamp in a single pass — subtract for the duration.

## Step 4 — Identify the Targeted Username

**Task:** Which account was the attacker trying to log into?
**Hint:** The submitted username lives inside the POST body, not a clean field — you'll need to pull it out with `rex`.

## Step 5 — Identify the Source IP

**Task:** Confirm the single source driving this — is it really one attacker, or several?
**Hint:** Group by source IP alongside the count from Step 3. One IP should dominate overwhelmingly — that's your brute-force source. (This is a *different* IP from any scanner activity you might see against the same server — a scanner and a brute-forcer are different attack phases, often different tools.)

## Step 6 — Geo-location & IP Reputation

**Task:** Where does the attacking IP come from, and does that fit the target's expected user base?
**Hint:** `iplocation` on the source IP gives you country/city for free — no external lookup needed for this step.

## Step 7 — Verify Successful Logon

**Task:** Did the brute force *work*? Find the one password (if any) that got a different response than all the others.
**Hint:** Pull the submitted password out of the POST body the same way you did the username in Step 4, then group by password and look at the response size or status — the successful login's response looks different from hundreds of identical failure responses. A password used only *once* but with a distinctive response is your signal.

## Step 8–9 — Block IP / Reset Password

**Task:** Write the two response actions as if you were actually taking them.
**Hint:** You already have everything you need for both: the IP from Step 5 to block, and — since Step 7 showed the brute force *succeeded* — the account from Step 4 needs a forced password reset, not just a block.

---

## Report

**IOC checklist:**
- [ ] Source IP
- [ ] Targeted username
- [ ] Number of attempts / duration
- [ ] Password that succeeded (if any)
- [ ] Geo-location of source

---

## Escalate when

- **Success after multiple failed attempts** ✅ — this case escalates; the brute force *worked*
- Same source IP targeting multiple users
- Login attempts from unfamiliar location
- Password spraying pattern (many users, few passwords each — contrast with this case, which is few users, many passwords)

**This case escalates.** The compromised login is the entry point for a much larger incident — pivot to **[Playbook 6 — Web Application Attack Detection](06-web-application-attack-detection.md)** to see what the attacker did once they were in.

**Alternate case (v2):** SSH brute force against `gacrux` is **pure noise, not a success** — tens of thousands of failures from dozens of source IPs, but the one *successful* login on that host came from a completely different source IP than any of the brute-forcers. That's the opposite lesson from the v1 case: don't assume the loudest IP is the one that got in — always check Step 7 independently of Step 5.

➡️ [Solutions](../answer/03-brute-force-login-detection.md)
