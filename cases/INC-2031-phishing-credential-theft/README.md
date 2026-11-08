# INC-2031: Phishing to Credential Theft and PowerShell Execution

| | |
|---|---|
| **Client** | Northbridge Financial Services (fictional) |
| **Severity / Priority** | critical / P1 |
| **Tier** | L2 |
| **Kill chain** | Initial Access → Execution → Credential Access |
| **Escalated by** | R. Castillo (L1, day shift) |
| **ATT&CK** | `T1566.002` Spearphishing Link · `T1059.001` PowerShell · `T1078` Valid Accounts |

## Handoff

Day shift escalated this incident to L2 with the note in [`evidence/l1-escalation-note.txt`](evidence/l1-escalation-note.txt). Day-shift assessment: *Single workstation + one user account; credential use confirmed*. Impact: *Finance analyst credentials compromised; potential access to financial shares*.

### Linked alerts

| Alert | Severity | Detection | Source |
|---|---|---|---|
| `COR-1041` Credential submission to suspicious login portal | critical | DR-022 Phishing URL click + form submit | Email Gateway |
| `COR-1042` Suspicious PowerShell execution on FIN-WS-117 | high | DR-014 Encoded PowerShell | Sysmon |
| `COR-1040` Sign-in from unfamiliar ASN (198.51.100.42) | high | DR-003 Impossible travel / new ASN | Entra ID |

Use the raw events, not the alert list, to build the timeline: alerts are grouped detections, and the events show when each step actually happened.

## Evidence

| File | Contents |
|---|---|
| [`evidence/events.csv`](evidence/events.csv) | 16 log events (Windows Security, Sysmon, Entra ID, email, network) touching any incident entity; URLs and domains defanged |
| [`evidence/alerts.json`](evidence/alerts.json) | The 3 linked SIEM alerts with detection, ATT&CK and business context |
| [`evidence/entities.json`](evidence/entities.json) | Directory, CMDB and threat-intel context for 5 entities |
| [`evidence/l1-escalation-note.txt`](evidence/l1-escalation-note.txt) | The L1 handoff as received |

## Hunting queries

Starting points I used to scope the incident, written for both Splunk and Microsoft Sentinel. Field names follow the lab's data model in [`docs/environment.md`](../../docs/environment.md).

### Phishing email and recipients

```spl
index=email sourcetype=email_gateway ("login-portal-example.net" OR subject="*Password Expiry*")
| table _time recipient sender spf dkim url
```

```kql
EmailEvents
| where Subject has "Password Expiry" or UrlDomain == "login-portal-example.net"
| project Timestamp, RecipientEmailAddress, SenderFromAddress, AuthenticationDetails, Url
```

### Sign-ins from the phishing infrastructure IP

```spl
index=azuread sourcetype=signinlogs src_ip=198.51.100.42
| table _time user src_ip mfa result risk
```

```kql
SigninLogs
| where IPAddress == "198.51.100.42"
| project TimeGenerated, UserPrincipalName, IPAddress, AuthenticationRequirement, ResultType, RiskLevelDuringSignIn
```

### Process and network activity on FIN-WS-117

```spl
index=sysmon host=FIN-WS-117 (EventCode=1 OR EventCode=3)
| table _time EventCode Image ParentImage CommandLine DestinationIp DestinationPort
```

```kql
DeviceProcessEvents
| where DeviceName == "FIN-WS-117"
| project Timestamp, FileName, InitiatingProcessFileName, ProcessCommandLine
| union (DeviceNetworkEvents | where DeviceName == "FIN-WS-117" | project Timestamp, RemoteIP, RemotePort, InitiatingProcessFileName)
```

### Explicit credential use (4648) from the compromised host

```spl
index=wineventlog EventCode=4648 host=FIN-WS-117
| table _time Account_Name Target_User_Name Target_Server_Name
```

```kql
SecurityEvent
| where EventID == 4648 and Computer == "FIN-WS-117"
| project TimeGenerated, SubjectUserName, TargetUserName, TargetServerName
```

## Deliverables

| Deliverable | Status |
|---|---|
| [Incident report](report.md) | 📝 In progress |
| [Client notification](client-notification.md) | 📝 In progress |
| Containment actions logged | 📝 In progress |
| Simulator QA score | _ /100 |
