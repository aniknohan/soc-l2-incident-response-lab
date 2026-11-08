# INC-2033: Incident Report

> **Status:** Draft. Written by the investigating L2 analyst after working this case in the SentriCore simulator.
> Replace every _italic prompt_ with your own findings. Delete this note when done.

| Field | Value |
|---|---|
| Incident | INC-2033 |
| Client | Northbridge Financial Services (fictional) |
| Severity / Priority | high / P1 |
| Linked alerts | COR-1035, COR-1034 |
| Analyst | Anik Nohan, SOC L2 (lab) |
| Disposition | _Resolved at L2 / Escalated to Tier 3_ |

## 1. Executive summary

_Three to five plain-language sentences for Northbridge management: what happened, business impact, current status. No event IDs or tool names._

## 2. L1 handoff review

| Rating | Feedback to L1 |
|---|---|
| _Meets standard / Needs improvement_ | _What the note did well, or what was missing (times, IOCs, scope, ask)._ |

## 3. Scoping findings

| Question | Finding | Evidence (query / log line) |
|---|---|---|
| How many accounts successfully authenticated from 203.0.113.99? | _ | _ |
| Which accounts signed in successfully from the spraying IP? | _ | _ |
| Which Windows event ID records the failed Kerberos pre-authentication used in the spray? | _ | _ |
| Are there other affected users or hosts? | _ | _ |

## 4. Timeline (UTC, 2026-10-17)

| Time | Event | Source |
|---|---|---|
| _HH:MM_ | _Initial access_ | _ |
| _HH:MM_ | _…_ | _ |
| _HH:MM_ | _Containment complete_ | _ |

## 5. Scope and impact

_Every affected user, host and data set; what the attacker reached; what they did not reach._

## 6. Root cause

**Category:** _e.g. Phishing / credential theft_

_How the attacker got in and why it worked (control gap)._

## 7. Containment and actions taken

| Time | Action | Target | Approved by |
|---|---|---|---|
| _HH:MM_ | _Isolate host / revoke sessions / reset password / block_ | _ | _ |

## 8. Indicators of compromise

| Type | Indicator (defanged) | Context |
|---|---|---|
| _ip / domain / url / hash_ | _ | _ |

## 9. MITRE ATT&CK mapping

| Tactic | Technique | Observed as |
|---|---|---|
| Credential Access | T1110.003 Password Spraying | _ |

## 10. Recommendations

1. _Eradication step_
2. _Recovery step_
3. _Prevention or detection improvement (link to a rule in `detections/` if you wrote one)_

## 11. Disposition and justification

_Resolve at L2 or escalate to Tier 3, and why._
