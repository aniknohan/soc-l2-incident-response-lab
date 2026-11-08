# 03 — SOC Operating Procedures

SentriCore SOC-SOP-001. These are the standards the simulator's QA reviews grade against.

## L1 ticket lifecycle

1. **Pick up.** Take the highest-priority, oldest ticket from `SOC-L1-Triage`. Assigning it acknowledges it and stops the response SLA.
2. **Analyze.** Read the detection and raw event, pivot on every entity in the SIEM, check intel, CMDB and directory context, contact the user when only they can confirm, and attach the log lines that prove the verdict.
3. **Document.** Triage report: summary, affected users and assets, IOCs, analysis performed with UTC times, verdict and justification, recommendation.
4. **Disposition.** Resolve (true positive handled at L1, benign true positive, false positive) or escalate to `SOC-L2-Incident-Response`.

## L2 incident lifecycle

1. **Accept and review the handoff.** Rate the L1 note; vague notes get feedback.
2. **Scope.** Every affected user, host and data set. How did they get in, what did they touch, are they still active?
3. **Contain.** Only what the evidence supports. Unneeded isolation is a business outage.
4. **Report.** Executive summary, timeline, scope and impact, root cause, actions taken, recommendations, client notification.
5. **Disposition.** Resolve at L2, or escalate to `SOC-L3-IR-Forensics` for forensics, malware analysis, hunting or breach assessment.

## Escalate L1 → L2 when

- Confirmed or likely compromise of an account or host
- Any high or critical true positive
- Malware execution, C2, lateral movement, exfiltration, ransomware indicators
- VIP, privileged or service account involvement
- Containment beyond L1 authority

## Priority and SLA matrix

| Priority | Meaning | Response | Resolution |
|---|---|---|---|
| P1 | Critical business impact, active attack | 15 min | 30 min |
| P2 | High impact or likely compromise | 30 min | 1 h |
| P3 | Moderate, contained or single user | 1 h | 4 h |
| P4 | Low, informational, policy | 2 h | 8 h |

## Response authority

| Action | Runs directly from |
|---|---|
| Block IP or domain, purge email | L1 |
| Isolate workstation, disable standard user, revoke sessions, reset password | L2 |
| Isolate server, collect forensic package | L3 |
| Isolate a domain controller; disable VIP, privileged or service accounts | SOC Manager |

Requests above the requester's tier become emergency changes for approval.
