# INC-2034: Ransomware Precursor on an Accounting Workstation

| | |
|---|---|
| **Client** | Northbridge Financial Services (fictional) |
| **Severity / Priority** | critical / P1 |
| **Tier** | L3 |
| **Kill chain** | Execution → Defense Evasion → Impact; C2 |
| **Escalated by** | R. Castillo (L1, day shift) |
| **ATT&CK** | `T1490` Inhibit System Recovery · `T1571` Non-Standard Port |

## Handoff

Day shift escalated this incident to L2 with the note in [`evidence/l1-escalation-note.txt`](evidence/l1-escalation-note.txt). Day-shift assessment: *Single workstation; beacon active; no encryption yet*. Impact: *Financial close at risk; shadow copies deleted*.

### Linked alerts

| Alert | Severity | Detection | Source |
|---|---|---|---|
| `COR-1025` Ransomware precursor: vssadmin delete shadows | critical | DR-001 Ransomware precursor TTPs | Sysmon |
| `COR-1024` C2 beacon to 203.0.113.55:8443 (60s interval) | high | DR-019 Beaconing detection | Sysmon |

Use the raw events, not the alert list, to build the timeline: alerts are grouped detections, and the events show when each step actually happened.

## Evidence

| File | Contents |
|---|---|
| [`evidence/events.csv`](evidence/events.csv) | 8 log events (Windows Security, Sysmon, Entra ID, email, network) touching any incident entity; URLs and domains defanged |
| [`evidence/alerts.json`](evidence/alerts.json) | The 2 linked SIEM alerts with detection, ATT&CK and business context |
| [`evidence/entities.json`](evidence/entities.json) | Directory, CMDB and threat-intel context for 3 entities |
| [`evidence/l1-escalation-note.txt`](evidence/l1-escalation-note.txt) | The L1 handoff as received |

## Hunting queries

Starting points I used to scope the incident, written for both Splunk and Microsoft Sentinel. Field names follow the lab's data model in [`docs/environment.md`](../../docs/environment.md).

### Recovery inhibition commands

```spl
index=sysmon EventCode=1 host=FIN-WS-410 (Image="*vssadmin.exe" OR Image="*wbadmin.exe" OR Image="*whoami.exe")
| table _time User Image CommandLine
```

```kql
DeviceProcessEvents
| where DeviceName == "FIN-WS-410" and FileName in~ ("vssadmin.exe", "wbadmin.exe", "whoami.exe")
| project Timestamp, AccountName, FileName, ProcessCommandLine
```

### C2 beaconing

```spl
index=sysmon EventCode=3 DestinationIp=203.0.113.55
| stats count min(_time) as first max(_time) as last by host DestinationPort
```

```kql
DeviceNetworkEvents
| where RemoteIP == "203.0.113.55"
| summarize Connections = count(), First = min(Timestamp), Last = max(Timestamp) by DeviceName, RemotePort
```

### Other hosts talking to the same C2

```spl
index=* (dest_ip=203.0.113.55 OR DestinationIp=203.0.113.55)
| stats count by host
```

```kql
union DeviceNetworkEvents, CommonSecurityLog
| where RemoteIP == "203.0.113.55" or DestinationIP == "203.0.113.55"
| summarize count() by DeviceName
```

## Deliverables

| Deliverable | Status |
|---|---|
| [Incident report](report.md) | 📝 In progress |
| [Client notification](client-notification.md) | 📝 In progress |
| Containment actions logged | 📝 In progress |
| Simulator QA score | _ /100 |
