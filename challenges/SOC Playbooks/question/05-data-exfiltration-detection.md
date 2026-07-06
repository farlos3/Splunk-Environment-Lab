# Playbook 5 — Data Exfiltration Detection

🎯 **Purpose:** Detect unauthorized transfer of sensitive or confidential data outside the organization.

**Dataset:** BOTS v2 (`./setup.sh --v2`) · **Case:** an **insider threat** — an employee emails a proprietary document to a named contact at a competitor.

⏱ **Time picker:** `08/30/2017 00:00:00` → `08/31/2017 00:00:00` for the exfil email itself; **All time** for the supporting insider-behavior evidence (TOR install, personal email use), since those build up over the month.

> **Hints are nudges, not answers.** Full SPL + verified findings are in [Solutions](../answer/05-data-exfiltration-detection.md) (Playbook 5).

---

## Playbook workflow

1. DLP / SIEM alert triggered
2. Identify user, data type & destination
3. Analyze transfer details & volume
4. Validate business justification
5. Contain & block the transfer
6. Document & escalate if required

---

## Step 1 — Alert Trigger

This lab has no DLP product, so the "alert" is a pivot you run yourself: **email flowing to a competitor's domain, carrying an attachment.**

**Task:** Find every email with an attachment sent from a Frothly address to an external recipient.
**Hint:** `stream:smtp` carries the attachment name in a multivalue field with a `{}` suffix — quote it. Filter to events with that field populated, then read the destination in the raw `To:` header (the clean extracted sender/receiver fields aren't always populated on this sourcetype in this lab — you'll need `rex` on `_raw`).

## Step 2 — User, Data Type & Destination

**Task:** Who sent it, what's the attachment, and who received it?
**Hint:** The attachment name itself tells you the data classification — a `.docx` named after a specific biological process/compound is a strong hint this is **intellectual property** (patent-relevant research), not routine business correspondence. The recipient's domain is a competitor in the same industry, not a customer or vendor.

## Step 3 — Transfer Details & Volume

**Task:** Note the size and how the message got there — was this a one-off, or part of a longer conversation?
**Hint:** Check the subject line — does it read like the *first* contact, or a reply (`RE:`)? A reply means there's a whole thread you haven't seen yet; go find the earlier messages in the same conversation.

## Step 4 — Validate Business Justification

**Task:** Is there *any* legitimate business reason an employee would send this document to this recipient?
**Hint:** Look at how the sender is behaving elsewhere in the same timeframe — is there evidence of tooling that exists specifically to *hide* activity (a privacy/anonymity browser installed on her workstation)? Also check whether she has a **personal** email account she's used in other messages — routing sensitive business communication through personal channels, or using anonymity tooling around the same period, undermines any "this was authorized business development" explanation.

## Step 5 — Contain & Block

**Task:** What would you actually do here, given this isn't malware — it's a person?
**Hint:** This isn't a technical containment problem (there's no C2 to block). The action is procedural: preserve the evidence (the email, the thread, the attachment), and escalate to HR/Legal — a DLP block on the *next* attempt is reasonable, but the investigation itself is a people process, not an incident-response one.

## Step 6 — Document & Escalate

Fill in the IOC checklist and write a short case summary.

**IOC checklist:**
- [ ] Sender (internal user)
- [ ] Recipient + external domain
- [ ] Attachment name (what data left)
- [ ] Timestamp
- [ ] Supporting behavioral evidence (privacy tooling, personal email)
- [ ] Any shared network/IP linking this user's activity to anyone else's

---

## A worthwhile pivot

The email's outbound connection carries an originating IP in its headers. Pivot that IP against every other sourcetype in the index — in this case, it ties back to **a completely different employee's successful login elsewhere in the environment**, on a completely different system. That doesn't necessarily mean collusion — shared home networks, VPN egress, or a family/office connection are all plausible — but it's exactly the kind of lead a DLP investigation should surface and hand to the next analyst, not silently drop.

## Escalate when

- **Data sent to untrusted or unknown destination** ✅ — a named competitor
- **User shows suspicious behavior or policy violation** ✅ — personal email + anonymity tooling
- Repeated attempts after initial warning
- Potential data breach impact

**This escalates to HR/Legal, not just IR.** Unlike the other playbooks in this pack, the remediation here isn't a technical control — document thoroughly and hand off.

➡️ [Solutions](../answer/05-data-exfiltration-detection.md)
