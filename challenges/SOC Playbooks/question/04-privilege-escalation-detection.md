# Playbook 4 — Privilege Escalation Detection

🎯 **Purpose:** Detect unauthorized attempts to gain elevated privileges or modify user roles and permissions.

**Dataset:** BOTS v2 (`./setup.sh --v2`) · **Case:** a backdoor local account (`svcvnc`) added to the local **Administrators** group on multiple hosts during the Taedonggang intrusion, followed by an audit-log clear.

> 🆕 **This case isn't documented anywhere else in this lab.** It surfaced while verifying this pack against the live data — Event IDs 4728/4732/1102 aren't covered by the existing [specialized/botsv2](../../specialized/botsv2/) tracks. You're investigating genuinely fresh ground here.

⏱ **Time picker:** `08/24/2017 03:30:00` → `08/24/2017 04:30:00` for the group-membership events; widen to `08/26/2017 00:00:00` → `08/27/2017 00:00:00` for the log-clear.

> **Hints are nudges, not answers.** Full SPL + verified findings are in [Solutions](../answer/04-privilege-escalation-detection.md) (Playbook 4).

---

## Playbook workflow

1. Alert triggered (permission change detected)
2. Review event details (user, action, time, source)
3. Check affected user & group changes
4. Validate if change is authorized
5. Contain & remove unauthorized access
6. Document & monitor the incident

---

## Step 1–2 — Alert & Event Details

**Task:** Pull every group-membership-change event in the window and read the story chronologically.
**Hint:** The quick-reference sheet's **4728** (user added to global group) and **4732** (member added to local group) are the two Event IDs you want. Sort by time — you should see the *same* account name being added on host after host, a few minutes apart.

## Step 3 — Affected User & Group Changes

**Task:** Which account is being added, to which group, and — critically — **who's doing the adding**?
**Hint:** Each event has both a `Subject` (who performed the action) and a `Member` (who was added). Track both across every event: does the *Subject* stay the same, or does it change partway through? A change in *who's* granting access partway through a chain is itself a finding — it suggests the first compromised account was used to authorize privilege for later stages.

## Step 4 — Validate if Authorized

**Task:** Is there any legitimate business reason a service/admin account would be creating this same local account on host after host in the space of an hour?
**Hint:** Look at the account name itself — does it look like a real user, or does it look like it's *impersonating* a legitimate-sounding service (the kind of name an admin might not think twice about in a process list)? Cross-reference the hosts involved against what you already know is compromised (if you've done Playbook 2/the specialized botsv2 tracks) — if the *Subject* accounts are ones you already flagged as attacker-controlled, this isn't authorized.
⚠️ **One of the hosts in this chain has no independent corroborating evidence** (no encoded PowerShell, no WMI-spawned process) in this lab's telemetry — for that one, the honest answer is "flagged by this event alone, needs further evidence," not "confirmed." Don't let one strong pattern make you overconfident about every data point in it.

## Step 5 — Contain & Remove

**Task:** What actions actually undo this privilege escalation?
**Hint:** Removing the backdoor account from Administrators everywhere it was added is the obvious one — but also check whether that same actor did anything *after* the group changes to cover their tracks. (Hint: check Event ID **1102** on the *last* host in the chain, a couple of days later.)

## Step 6 — Document & Monitor

Fill in the IOC checklist and write the sequence: who escalated what, where, and in what order.

**IOC checklist:**
- [ ] Backdoor account name
- [ ] Group(s) it was added to
- [ ] Every host affected, with timestamp
- [ ] Subject account(s) performing the escalation
- [ ] Any anti-forensics action afterward (log clearing)

---

## Escalate when

- **Domain admin or privileged group targeted** ✅
- Privilege escalation followed by suspicious activity
- **Multiple privilege changes in short time** ✅ — four hosts in under 40 minutes
- If the source is an untrusted or unknown host

**This is High severity, 15–60 min response.** The audit-log clear afterward pushes it further — that's deliberate anti-forensics, not routine administration. Pivot to **[Playbook 5 — Data Exfiltration Detection](05-data-exfiltration-detection.md)** to check whether the elevated access was used to move data out, or back to the specialized [DFIR track](../../specialized/botsv2/02-dfir.md) to fold this into the master timeline.

➡️ [Solutions](../answer/04-privilege-escalation-detection.md)
