# Playbook 6 — Web Application Attack Detection

🎯 **Purpose:** Detect attacks targeting web applications that exploit vulnerabilities to steal data, execute code, or disrupt services.

**Dataset:** BOTS v1 (`./setup.sh`) · **Case:** scanning + SQL injection against the Joomla site `imreallynotbatman.com`, ending in a web-shell upload and defacement.
**Alternate case (BOTS v2):** SQLi *and* XSS against `brewertalk.com` — see the callouts at the end.

⏱ **Time picker:** `08/10/2016 00:00:00` → `08/12/2016 00:00:00` (v1). For the v2 alternate: **All time**.

> **Hints are nudges, not answers.** Full SPL + verified findings are in [Solutions](../answer/06-web-application-attack-detection.md) (Playbook 6).

> 🔗 **This continues Playbook 3.** The brute-forced login you found there and the attack you'll trace here hit the *same* server, from *different* source IPs, as *different phases* of the same campaign — recon/exploitation vs. credential attack.

---

## Playbook workflow

1. WAF alert triggered (this lab has no WAF product — you'll build the equivalent from raw web logs)
2. Review request (source IP, URL, method)
3. Identify attack type (payload analysis)
4. Analyze logs (web server / app logs)
5. Validate impact (success or blocked)
6. Block attack & document incident

---

## Step 1–2 — Alert & Request Review

**Task:** Something is hitting this server far more than any normal visitor would. Find it.
**Hint:** Group web traffic to the server by source IP, and look at *both* raw event count and how many distinct paths each source requested. A normal visitor touches a handful of pages; a scanner touches hundreds.

## Step 3 — Identify Attack Type

**Task:** What's actually in the malicious requests — is this SQLi, path traversal, something else?
**Hint:** Filter the scanner's requests for classic injection markers in the URI (`union`, `select`, a literal `'`, or `..%2f`/directory-traversal). Also check the User-Agent string — off-the-shelf scanners frequently identify themselves there without even trying to hide it.

## Step 4 — Analyze Logs

**Task:** Beyond scanning, did this actor *upload* anything to the server?
**Hint:** POST requests carrying a file upload will show a `part_filename`-style field. Anything uploaded here that isn't an image is worth immediate attention — especially a scripting-language file extension.

## Step 5 — Validate Impact

**Task:** Did the attack succeed? Look for the defaced content itself.
**Hint:** If the server serves back a file that doesn't belong in the site's normal image inventory — via a plain `GET` from the server itself — that's the attacker's payload being served to visitors. That's confirmed, not just attempted, impact.

## Step 6 — Block & Document

Fill in the IOC checklist.

**IOC checklist:**
- [ ] Scanner/attacker source IP + tool identified
- [ ] Injection technique observed
- [ ] Uploaded file name(s)
- [ ] Defacement artifact
- [ ] Any second actor involved (cross-reference Playbook 3)

---

## Escalate when

- **Database access or data dump detected**
- **Web shell or RCE suspected** ✅ — a scripting-extension upload qualifies
- **Application is defaced or unavailable** ✅ — confirmed here
- Multiple attack attempts from same IP

**This is Critical.** Successful upload + confirmed defacement means full compromise of the web tier — escalate to the DFIR/hunting workflow (see the [specialized botsv1](../../specialized/botsv1/) tracks for the full-depth version of this exact incident).

**Alternate case (v2):** `brewertalk.com` shows the SQLi side of this playbook (an error-based technique abusing a specific SQL function against a login/registration endpoint) **and** the poster's other common attack type this lab doesn't otherwise cover: **Cross-Site Scripting**. A victim's session cookie gets exfiltrated to an attacker-controlled URL via injected script, and that stolen cookie is then used to create a new account on the victim site — a textbook "XSS → session theft → account takeover" chain, distinct from the credential-based takeover in the v1 case. See [Solutions](../answer/06-web-application-attack-detection.md) for both.

➡️ [Solutions](../answer/06-web-application-attack-detection.md)
