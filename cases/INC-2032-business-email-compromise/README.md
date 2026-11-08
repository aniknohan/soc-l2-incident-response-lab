# INC-2032: Business Email Compromise of the Treasury Director

| | |
|---|---|
| **Client** | Northbridge Financial Services (fictional) |
| **Severity / Priority** | critical / P1 |
| **Tier** | L2 |
| **Kill chain** | Credential Access → Persistence → Impact (fraud) |
| **Escalated by** | R. Castillo (L1, day shift) |
| **ATT&CK** | `T1098.002` Additional Email Delegate · `T1566` Phishing |

## Handoff

Day shift escalated this incident to L2 with the note in [`evidence/l1-escalation-note.txt`](evidence/l1-escalation-note.txt). Day-shift assessment: *Mailbox-only; no endpoint compromise*. Impact: *Potential fraudulent wire $480,000*.

### Linked alerts

| Alert | Severity | Detection | Source |
|---|---|---|---|
| `COR-1038` New inbox rule forwarding to external domain | high | DR-031 Suspicious inbox rule | Entra ID |
| `COR-1037` Outbound email with updated wire instructions to vendor | critical | DR-040 BEC wire-instruction pattern | Email Gateway |

Use the raw events, not the alert list, to build the timeline: alerts are grouped detections, and the events show when each step actually happened.

## Evidence

| File | Contents |
|---|---|
| [`evidence/events.csv`](evidence/events.csv) | 8 log events (Windows Security, Sysmon, Entra ID, email, network) touching any incident entity; URLs and domains defanged |
| [`evidence/alerts.json`](evidence/alerts.json) | The 2 linked SIEM alerts with detection, ATT&CK and business context |
| [`evidence/entities.json`](evidence/entities.json) | Directory, CMDB and threat-intel context for 3 entities |
| [`evidence/l1-escalation-note.txt`](evidence/l1-escalation-note.txt) | The L1 handoff as received |

## Hunting queries

Starting points I used to scope the incident, written for both Splunk and Microsoft Sentinel. Field names follow the lab's data model in [`docs/02-lab-environment.md`](../../docs/02-lab-environment.md).

### Session activity for k.larsen

```spl
index=azuread user="k.larsen@example.net"
| table _time operation src_ip user_agent result
```

```kql
SigninLogs
| where UserPrincipalName == "k.larsen@example.net"
| project TimeGenerated, IPAddress, AppDisplayName, TokenIssuerType, ResultType
```

### Inbox rule creation

```spl
index=o365 Operation IN ("New-InboxRule","Set-InboxRule") UserId="k.larsen@example.net"
| table _time Operation Parameters ClientIP
```

```kql
OfficeActivity
| where Operation in ("New-InboxRule", "Set-InboxRule") and UserId == "k.larsen@example.net"
| project TimeGenerated, Operation, Parameters, ClientIP
```

### Outbound mail to external domains

```spl
index=email direction=outbound sender="k.larsen@example.net"
| table _time recipient subject
```

```kql
EmailEvents
| where SenderFromAddress == "k.larsen@example.net" and EmailDirection == "Outbound"
| project Timestamp, RecipientEmailAddress, Subject
```

## Deliverables

| Deliverable | Status |
|---|---|
| [Incident report](report.md) | 📝 In progress |
| [Client notification](client-notification.md) | 📝 In progress |
| Containment actions logged | 📝 In progress |
| Simulator QA score | _ /100 |
