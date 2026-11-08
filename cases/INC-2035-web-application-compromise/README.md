# INC-2035: SQL Injection to Web Shell on the Customer Portal

| | |
|---|---|
| **Client** | Northbridge Financial Services (fictional) |
| **Severity / Priority** | critical / P1 |
| **Tier** | L3 |
| **Kill chain** | Initial Access → Persistence → C2 |
| **Escalated by** | R. Castillo (L1, day shift) |
| **ATT&CK** | `T1190` Exploit Public-Facing App · `T1505.003` Web Shell · `T1053.005` Scheduled Task |

## Handoff

Day shift escalated this incident to L2 with the note in [`evidence/l1-escalation-note.txt`](evidence/l1-escalation-note.txt). Day-shift assessment: *Single web server; web shell uploaded*. Impact: *Public portal; PII exposure risk*.

### Linked alerts

| Alert | Severity | Detection | Source |
|---|---|---|---|
| `COR-1013` Successful SQL injection on FIN-SRV-WEB01 | critical | DR-028 SQLi pattern + 200 response | WAF |
| `COR-1012` Web server outbound C2 + scheduled task creation | critical | DR-016 Web server child process | Sysmon |

Use the raw events, not the alert list, to build the timeline: alerts are grouped detections, and the events show when each step actually happened.

## Evidence

| File | Contents |
|---|---|
| [`evidence/events.csv`](evidence/events.csv) | 60 log events (Windows Security, Sysmon, Entra ID, email, network) touching any incident entity; URLs and domains defanged |
| [`evidence/alerts.json`](evidence/alerts.json) | The 2 linked SIEM alerts with detection, ATT&CK and business context |
| [`evidence/entities.json`](evidence/entities.json) | Directory, CMDB and threat-intel context for 3 entities |
| [`evidence/l1-escalation-note.txt`](evidence/l1-escalation-note.txt) | The L1 handoff as received |

## Hunting queries

Starting points I used to scope the incident, written for both Splunk and Microsoft Sentinel. Field names follow the lab's data model in [`docs/environment.md`](../../docs/environment.md).

### WAF verdicts for the attacker

```spl
index=network sourcetype=waf src_ip=203.0.113.99
| stats count by action status
```

```kql
AzureDiagnostics
| where Category == "ApplicationGatewayFirewallLog" and clientIp_s == "203.0.113.99"
| summarize count() by action_s, httpStatus_d
```

### Children of the IIS worker process

```spl
index=sysmon EventCode=1 host=FIN-SRV-WEB01 ParentImage="*w3wp.exe"
| table _time Image CommandLine
```

```kql
DeviceProcessEvents
| where DeviceName == "FIN-SRV-WEB01" and InitiatingProcessFileName =~ "w3wp.exe"
| project Timestamp, FileName, ProcessCommandLine
```

### Outbound connections from the web tier

```spl
index=sysmon EventCode=3 host=FIN-SRV-WEB01
| stats count by Image DestinationIp DestinationPort
```

```kql
DeviceNetworkEvents
| where DeviceName == "FIN-SRV-WEB01" and RemoteIPType == "Public"
| summarize count() by InitiatingProcessFileName, RemoteIP, RemotePort
```

## Deliverables

| Deliverable | Status |
|---|---|
| [Incident report](report.md) | 📝 In progress |
| [Client notification](client-notification.md) | 📝 In progress |
| Containment actions logged | 📝 In progress |
| Simulator QA score | _ /100 |
