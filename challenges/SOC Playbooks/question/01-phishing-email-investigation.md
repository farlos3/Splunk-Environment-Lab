# Playbook 1 — Phishing Email Investigation

🎯 **Purpose:** Investigate phishing emails and identify malicious intent, URLs, domains, and attachments.

**Dataset:** BOTS v2 (`./setup.sh --v2`) · **Case:** a password-protected `invoice.zip` lure delivered to Frothly — the opening move of the Taedonggang intrusion you may already know from the [specialized botsv2](../../specialized/botsv2/) tracks.

⏱ **Time picker:** `08/24/2017 03:00:00` → `08/24/2017 04:00:00` (the delivery + first execution both land in this hour).

> **Hints are nudges, not answers.** Full SPL + verified findings are in [Solutions](../answer/01-phishing-email-investigation.md) (Playbook 1).

---

## Playbook workflow

1. Alert / email report
2. Analyze email header
3. Check URLs & attachments
4. Threat intelligence lookup
5. Determine malicious / safe
6. Report & close

---

## Step 1 — Alert / Email Report

A user (or an automated rule) flags a suspicious email with a `.zip` attachment. Your job: find it in `sourcetype=stream:smtp`.

**Task:** Find the email(s) carrying an attachment named `invoice.zip`.
**Hint:** `stream:smtp` carries attachment metadata in a multivalue field — the field name has a `{}` suffix, so quote it. Filter on that field equal to the exact filename.

## Step 2 — Analyze Email Header

**Task:** Pull the sender, and note anything about the delivery path that looks off.
**Hint:** The sender and routing info live in the raw MIME headers (`_raw`), not always in clean extracted fields for this sourcetype — `rex` the `From:` line. Also look at the `Received:`/mailer headers: this one didn't come directly from a normal corporate mail server — it was relayed through a **bulk-email platform**. A mismatch between the claimed sender and the actual delivery infrastructure is a phishing indicator on its own (see the poster's "Mismatched or spoofed domain" indicator).

## Step 3 — Check URLs & Attachments

**Task:** What's attached, how big is it, and what would make it hard for AV to inspect?
**Hint:** Pull `attach_filename{}` and `attach_size{}` for these events. A `.zip` that requires a password to open is a classic evasion technique — AV/sandboxes can't open it automatically, so the payload only detonates once a human types the password from the email body. (You won't find the password in a clean field here — read `_raw` around the body text, or cross-reference the [official BOTS walkthrough](../../splunk-bots/botsv2/README.md) Q401/Q402, which documents it.)

## Step 4 — Threat Intelligence Lookup

**Task:** Is the sender's domain or the mailer platform known-bad, and does the timing tell you anything?
**Hint:** This lab has no live TI feed, so "lookup" here means **internal correlation**: pivot the timestamp of this email forward a few minutes and look for the *first* suspicious process execution anywhere in the environment (Sysmon `EventCode=1`, encoded PowerShell). ⚠️ **Be honest about what this proves:** `stream:smtp` in this lab doesn't cleanly expose the recipient's mailbox or the delivering IP, so a nearby-in-time execution is a **lead to pivot on, not proof of causation** — you'd need mail-gateway delivery logs (which this lab doesn't have) to say for certain *this* email is why *that* host got popped. State the correlation, and state the gap honestly.

## Step 5 — Determine Malicious / Safe

**Task:** Make the call, and justify it with what you found in Steps 1–4.
**Hint:** Weight the evidence: odd sender domain unrelated to Frothly's business, relayed through a mass-mailer, and a password-protected archive (classic AV-evasion — sandboxes can't auto-detonate it). That's already enough to call this **malicious** on the email's own merits, independent of whatever you found in Step 4. The precise link to a specific victim host is a *lead*, not a *verdict* — don't let an unproven pivot inflate your confidence on the parts you haven't confirmed.

## Step 6 — Report & Close

Fill in the IOC checklist and write a 3–4 sentence summary (sender, attachment, victim host, and what happened right after).

**IOC checklist:**
- [ ] Sender address / domain
- [ ] Attachment filename + size
- [ ] Delivery infrastructure (mailer platform)
- [ ] Victim host(s)
- [ ] Timestamp of delivery
- [ ] What fired immediately after (pivot to Playbook 2)

---

## Escalate when

- Credential submission detected (n/a here — attachment-based, not a credential-harvesting page)
- **Malicious attachment executed** ✅ — this is exactly what happened
- Multiple users/reports of the same email
- High-severity threat identified downstream

**This case escalates.** The natural next step is **[Playbook 2 — Malware Alert Investigation](02-malware-alert-investigation.md)**, picking up right where the attachment detonates.

➡️ [Solutions](../answer/01-phishing-email-investigation.md)
