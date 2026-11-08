# 04 — L2 Investigation Methodology

How I work an escalated incident from handoff to disposition. Each step lists the questions it answers and where the evidence comes from.

---

## 1. Accept and review the handoff

Before touching the SIEM, read what L1 sent and judge whether it is usable.

| Check | Why it matters |
|---|---|
| UTC times for key events | Without times, the timeline has to be rebuilt from zero |
| Affected users and hosts named | Scoping starts from these pivots |
| Indicators listed and defanged | Lets L2 block and hunt immediately |
| What L1 already checked | Avoids duplicate work |
| What L1 already contained | Avoids conflicting actions |
| A clear ask | Tells L2 what decision is needed |

A weak note gets written feedback, not silent rework. The checklist is in [`templates/l1-handoff-review.md`](../templates/l1-handoff-review.md).

---

## 2. Scope

Scoping answers four questions:

1. **How did they get in?** Initial access: phishing click, valid credentials, exploit.
2. **What did they touch?** Every user, host, mailbox and data set the attacker reached.
3. **How far did they get?** Execution, persistence, credential access, lateral movement, exfiltration.
4. **Are they still active?** Live sessions, beacons, scheduled tasks, forwarding rules.

### Pivot order

```text
alert entity ─▶ user      ─▶ sign-ins (IP, ASN, MFA) ─▶ mailbox rules, app consents, file access
             ─▶ host      ─▶ process tree (Sysmon 1) ─▶ network (Sysmon 3) ─▶ credential use (4648, 4624 type 3)
             ─▶ indicator ─▶ every other host or user that touched it
```

Every pivot that finds something new becomes a new pivot. Scoping stops when a pass finds no new entity.

### Evidence sources

| Question | Primary source | Event IDs / tables |
|---|---|---|
| Who signed in, from where | Entra ID, Windows Security | `SigninLogs`, 4624, 4625, 4771 |
| What ran on the host | Sysmon | 1 (process), 11 (file) |
| Where the host connected | Sysmon, firewall, proxy | 3, `DeviceNetworkEvents`, `CommonSecurityLog` |
| Credential misuse | Windows Security | 4648, 4768, 4769 |
| Mailbox manipulation | Exchange Online audit | `New-InboxRule`, `Set-InboxRule` |
| Web exploitation | WAF, IIS | allowed requests with injection signatures |

---

## 3. Contain

Containment is a business decision as much as a technical one. Isolating the wrong host is an outage.

| Situation | Action | Authority |
|---|---|---|
| Malicious infrastructure confirmed | Block IP or domain | L1 and above |
| Account used by an attacker | Revoke sessions, force password reset | L2 |
| Code executed on a workstation | Isolate the workstation | L2 |
| Code executed on a server | Isolate the server, collect forensics | L3 |
| Privileged, VIP or service account abused | Disable the account | SOC Manager |
| Domain controller involved | Disable the rogue account, not the DC | SOC Manager |

Anything above my tier goes through an emergency change with the evidence attached.

---

## 4. Report

The incident report serves three readers:

| Reader | Section | Standard |
|---|---|---|
| Management | Executive summary | Plain language, business impact, current status |
| Auditor | Timeline, actions taken | UTC times, who did what, who approved it |
| Client | Notification | What happened, what we did, what we need from them |

Template: [`templates/l2-incident-report.md`](../templates/l2-incident-report.md). Standards: [07 — QA Rubric and Report Standards](07-qa-rubric-and-report-standards.md).

---

## 5. Disposition

| Resolve at L2 when | Escalate to Tier 3 when |
|---|---|
| Fully contained | Ransomware or destructive malware |
| Root cause known | Web shell or compromise of an internet-facing server |
| No evidence of further spread | Privileged or service account credentials used |
| Recovery is routine client IT work | Forensics, malware analysis or a breach assessment is needed |

---

## 6. Improve

Every incident should leave the SOC better prepared for the next one:

- a **detection** for the behaviour (not just the indicator) in [`detections/`](../detections/)
- a **playbook** update in [`playbooks/`](../playbooks/)
- a **tuning request** for any rule that produced noise during the investigation
