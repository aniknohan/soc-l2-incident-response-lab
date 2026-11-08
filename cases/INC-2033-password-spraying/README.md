# INC-2033: Password Spraying with Three Successful Logons

| | |
|---|---|
| **Client** | Northbridge Financial Services (fictional) |
| **Severity / Priority** | high / P1 |
| **Tier** | L2 |
| **Kill chain** | Credential Access → Initial Access |
| **Escalated by** | R. Castillo (L1, day shift) |
| **ATT&CK** | `T1110.003` Password Spraying |

## Handoff

Day shift escalated this incident to L2 with the note in [`evidence/l1-escalation-note.txt`](evidence/l1-escalation-note.txt). Day-shift assessment: *3 compromised accounts; CS rep without MFA*. Impact: *Customer PII access risk*.

### Linked alerts

| Alert | Severity | Detection | Source |
|---|---|---|---|
| `COR-1035` Password spraying from 203.0.113.99 (45 attempts) | high | DR-007 Password spray threshold | Windows Security |
| `COR-1034` Account locked: p.nguyen@example.net | medium | DR-009 Lockout threshold | Windows Security |

Use the raw events, not the alert list, to build the timeline: alerts are grouped detections, and the events show when each step actually happened.

## Evidence

| File | Contents |
|---|---|
| [`evidence/events.csv`](evidence/events.csv) | 70 log events (Windows Security, Sysmon, Entra ID, email, network) touching any incident entity; URLs and domains defanged |
| [`evidence/alerts.json`](evidence/alerts.json) | The 2 linked SIEM alerts with detection, ATT&CK and business context |
| [`evidence/entities.json`](evidence/entities.json) | Directory, CMDB and threat-intel context for 4 entities |
| [`evidence/l1-escalation-note.txt`](evidence/l1-escalation-note.txt) | The L1 handoff as received |

## Hunting queries

Starting points I used to scope the incident, written for both Splunk and Microsoft Sentinel. Field names follow the lab's data model in [`docs/02-lab-environment.md`](../../docs/02-lab-environment.md).

### Failures and successes from the spraying IP

```spl
index=wineventlog src_ip=203.0.113.99 (EventCode=4771 OR EventCode=4624)
| stats count by user EventCode
```

```kql
SecurityEvent
| where IpAddress == "203.0.113.99" and EventID in (4771, 4624)
| summarize count() by TargetUserName, EventID
```

### Spray pattern: distinct users per source IP

```spl
index=wineventlog EventCode=4771
| bin _time span=30m
| stats dc(user) as users count by src_ip _time
| where users > 5
```

```kql
SecurityEvent
| where EventID == 4771
| summarize Users = dcount(TargetUserName), Attempts = count() by IpAddress, bin(TimeGenerated, 30m)
| where Users > 5
```

### Lockouts

```spl
index=wineventlog EventCode=4740
| table _time user
```

```kql
SecurityEvent
| where EventID == 4740
| project TimeGenerated, TargetUserName
```

### MFA status of accounts that signed in

```spl
| inputlookup identities.csv
| search user IN ("p.nguyen","b.garcia","c.dubois")
| table user title mfa
```

```kql
IdentityInfo
| where AccountName in ("p.nguyen", "b.garcia", "c.dubois")
| project AccountName, JobTitle, AssignedRoles
```

## Deliverables

| Deliverable | Status |
|---|---|
| [Incident report](report.md) | 📝 In progress |
| [Client notification](client-notification.md) | 📝 In progress |
| Containment actions logged | 📝 In progress |
| Simulator QA score | _ /100 |
