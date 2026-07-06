# Playbook 1 — Phishing Email Investigation — Solutions

Reference answers, verified against the loaded `index=botsv2`.
Questions: [../question/01-phishing-email-investigation.md](../question/01-phishing-email-investigation.md)

---

### Step 1 — Find the attachment
```spl
index=botsv2 sourcetype=stream:smtp "attach_filename{}"="invoice.zip"
```
**4 events**, all `2017-08-24` between `03:27:14` and `03:27:33`. `attach_size{}` = 22,578 bytes on every copy.

### Step 2 — Header analysis
```spl
index=botsv2 sourcetype=stream:smtp "attach_filename{}"="invoice.zip"
| rex field=_raw "From: (?<mail_from>[^\r\n<]*<[^\r\n>]+>)"
```
Sender: **`Jim Smith <jsmith@urinalysis.com>`** — a domain with no relationship to Frothly. The raw headers also show `X-YMLPcode:` and a `List-Unsubscribe:` link pointing at `smtp12.ymlpsvr.com` — YMLP is a legitimate bulk-mail/newsletter platform. The phishing email was relayed through mass-mail infrastructure rather than sent directly, which is itself a mismatch worth flagging.

### Step 3 — Attachment
`invoice.zip`, 22,578 bytes, delivered as a password-protected archive (per the official BOTS v2 walkthrough, the password is disclosed in the email body — this lab's `stream:smtp` extraction doesn't cleanly expose `content_body` for this event, so cross-reference [`../splunk-bots/botsv2/README.md`](../../splunk-bots/botsv2/README.md) Q401/Q402 for that detail). A password-protected zip can't be auto-detonated by a mail-gateway sandbox — the human has to type the password from the body, which is the entire point of the technique.

### Step 4 — Correlation (with an honest limit)
```spl
index=botsv2 sourcetype=*ysmon* EventCode=1 (CommandLine="*-enc*" OR CommandLine="*FromBase64*")
| sort _time | head 5
```
Earliest encoded-PowerShell execution in the environment: **`2017-08-24 03:29:08`** on `wrk-btun` — about 1.5–2 minutes after the phishing email's delivery window. That's a tight *timing* correlation, but `stream:smtp` in this lab doesn't expose which mailbox/host actually received and opened the attachment, so **this is a lead, not proof** that this specific email caused that specific execution. Say so explicitly in a real report.

### Step 5 — Verdict
**Malicious**, on the email's own merits (unrelated sender domain, mass-mail relay, password-protected archive) independent of the unproven host link.

---

➡️ This escalates to [Playbook 2 — Malware Alert Investigation](02-malware-alert-investigation.md).
