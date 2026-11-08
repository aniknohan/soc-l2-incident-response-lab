# Lab Environment

**SentriCore Security** is a fictional managed security service provider (MSSP). Its client, **Northbridge Financial Services**, is also fictional. Every IP address comes from the RFC 5737 documentation ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) or private RFC 1918 space, and every domain uses `example.net`, `example.com` or `example.org`. No real organisation, person or infrastructure is involved.

## Network

| Segment | Range | Contents |
|---|---|---|
| User workstations | `10.10.50.0/24` | Finance, Accounting, Operations, Legal, Sales endpoints |
| Core servers | `10.10.0.0/24`, `10.10.1.0/24`, `10.10.2.0/24` | Domain controllers, DNS, file, SQL, Linux app servers |
| DMZ | `172.16.10.0/24` | `FIN-SRV-WEB01` public customer portal (IIS) |
| Azure | `10.30.5.0/24` | `FIN-CLOUD-DB` |
| Backup | `10.10.1.50` | `FIN-SRV-BKP01`, the only host `svc_backup` should log on from |

## Log sources and data model

| Source | Splunk | Sentinel / Defender | Key fields |
|---|---|---|---|
| Windows Security | `index=wineventlog` | `SecurityEvent` | `EventCode`, `TargetUserName`, `IpAddress`, `LogonType` |
| Sysmon | `index=sysmon` | `DeviceProcessEvents`, `DeviceNetworkEvents` | `Image`, `ParentImage`, `CommandLine`, `DestinationIp` |
| Entra ID | `index=azuread` | `SigninLogs`, `AuditLogs` | `user`, `src_ip`, `mfa`, `result` |
| Exchange Online | `index=o365` | `OfficeActivity` | `Operation`, `UserId`, `Parameters` |
| Email gateway | `index=email` | `EmailEvents` | `sender`, `recipient`, `spf`, `dkim`, `url` |
| Firewall, proxy, DNS, VPN, WAF | `index=network` | `CommonSecurityLog`, `AzureDiagnostics` | `src_ip`, `dest_ip`, `action`, `status` |

The case `evidence/events.csv` files flatten every source to one schema: `event_time, source, category, event_type, host, user, src_ip, dst_ip, process, command_line, severity, raw`.

## Assets and identities

### Identities

| Account | Name | Title | Department | MFA | Flags |
|---|---|---|---|---|---|
| `j.martinez@example.net` | Jordan Martinez | Financial Analyst | Finance | Push | – |
| `k.larsen@example.net` | Karin Larsen | Treasury Director | Treasury | Push | VIP |
| `p.nguyen@example.net` | Phuong Nguyen | Customer Service Rep | Customer Service | None | – |
| `d.whitman@example.net` | Dana Whitman | Chief Financial Officer | Executive | FIDO2 key | VIP, Privileged |
| `t.okafor@example.net` | Tobi Okafor | Operations Specialist | Operations | Push | – |
| `s.lee@example.net` | Sun Lee | Senior Accountant | Accounting | Push | – |
| `svc_backup@example.net` | svc_backup | Backup service account | IT Infrastructure | Not supported | Privileged, Service |
| `j.reyes@example.net` | Jamie Reyes | Marketing Lead | Marketing | Push | – |
| `h.kim@example.net` | Hana Kim | Research Scientist | Quant Research | Push | – |
| `m.okafor@example.net` | Michael Okafor | IT Operations Manager | IT | FIDO2 key | Privileged |
| `c.dubois@example.net` | Camille Dubois | Sales Representative | Sales | Push | – |
| `f.rossi@example.net` | Francesca Rossi | Finance Manager | Finance | Push | – |
| `g.holloway@example.net` | Grant Holloway | Chief Executive Officer | Executive | FIDO2 key | VIP |
| `r.tanaka@example.net` | Ren Tanaka | Web Developer | Digital | Push | – |
| `e.ward@example.net` | Elise Ward | Legal Counsel | Legal | Push | – |
| `a.chen@example.net` | Alex Chen | Accounts Payable Clerk | Finance | Push | – |
| `m.santos@example.net` | Maria Santos | Customer Service Rep | Customer Service | Push | – |
| `o.farouk@example.net` | Omar Farouk | Risk Analyst | Risk | Push | – |
| `b.garcia@example.net` | Bea Garcia | Compliance Officer | Compliance | None | – |
| `l.brookes@example.net` | Liam Brookes | Payroll Specialist | HR | Push | – |
| `p.nair@example.net` | Priya Nair | Cloud Engineer | IT | FIDO2 key | Privileged |
| `d.park@example.net` | Daniel Park | DevOps Engineer | IT | Push | Privileged |
| `temp_admin` | temp_admin | No owner on record (created 17:52 UTC) | Unknown | None | Privileged |
| `r.patel@example.net` | Raj Patel | Compliance Analyst | Compliance | Push | – |

### Hosts

| Host | Role | OS | Owner | IP | Criticality | Site |
|---|---|---|---|---|---|---|
| `FIN-WS-117` | Endpoint | Windows 11 23H2 | j.martinez | `10.10.50.117` | Medium | NYC-3F |
| `FIN-WS-145` | Endpoint | Windows 11 23H2 | t.okafor | `10.10.50.145` | Medium | NYC-2F |
| `FIN-WS-410` | Endpoint | Windows 11 23H2 | s.lee | `10.10.50.210` | High | NYC-4F |
| `FIN-WS-277` | Endpoint | Windows 10 22H2 | b.garcia | `10.10.50.177` | Medium | NYC-5F |
| `FIN-WS-521` | Endpoint | Windows 11 23H2 | Compliance (shared) | `10.10.51.21` | Medium | NYC-5F |
| `FIN-WS-389` | Endpoint | Windows 11 23H2 | h.kim | `10.10.50.189` | High | Boston |
| `FIN-WS-401` | Endpoint | Windows 11 23H2 | m.okafor | `10.10.50.201` | High | NYC-1F |
| `FIN-WS-021` | Endpoint | Windows 11 23H2 | e.ward | `10.10.50.21` | Medium | NYC-6F |
| `FIN-WS-002` | Endpoint | Windows 10 22H2 | HR kiosk | `10.10.50.2` | Low | NYC-1F |
| `FIN-WS-088` | Endpoint | Windows 11 23H2 | Customer Service (shared) | `10.10.50.88` | Low | Charlotte |
| `FIN-WS-312` | Endpoint | macOS 15 | g.holloway | `10.10.50.112` | High | NYC-7F |
| `FIN-WS-063` | Endpoint | macOS 15 | j.reyes | `10.10.50.63` | Low | NYC-2F |
| `FIN-WS-155` | Endpoint | Windows 11 23H2 | a.chen | `10.10.50.155` | Medium | NYC-3F |
| `FIN-WS-077` | Endpoint | Windows 11 23H2 | f.rossi | `10.10.50.77` | Medium | NYC-3F |
| `FIN-WS-009` | Endpoint | Windows 11 23H2 | c.dubois | `10.10.50.9` | Low | Remote |
| `FIN-WS-204` | Endpoint | Windows 11 23H2 | o.farouk | `10.10.50.204` | Medium | NYC-4F |
| `FIN-WS-233` | Endpoint | Windows 11 23H2 | IT Desktop (test bench) | `10.10.50.233` | Low | NYC-1F |
| `FIN-PRN-03` | Endpoint | Printer firmware 9.2 | Facilities | `10.10.60.3` | Low | NYC-3F |
| `FIN-DC-01` | Domain controller | Windows Server 2022 | IT Infrastructure | `10.10.0.10` | Critical | NYC-DC |
| `FIN-DC-02` | Domain controller | Windows Server 2022 | IT Infrastructure | `10.10.0.11` | Critical | NJ-DR |
| `FIN-SRV-WEB01` | Server | Windows Server 2019 / IIS 10 | Digital | `172.16.10.21` | High | DMZ |
| `FIN-SRV-SQL01` | Server | Windows Server 2022 / SQL 2019 | Data Platform | `10.10.1.31` | Critical | NYC-DC |
| `FIN-SRV-FS01` | Server | Windows Server 2022 | IT Infrastructure | `10.10.1.40` | High | NYC-DC |
| `FIN-LX-APP01` | Server | Ubuntu 22.04 | Platform | `10.10.2.11` | Medium | NYC-DC |
| `FIN-LX-APP02` | Server | Ubuntu 22.04 | Platform | `10.10.2.12` | Medium | NYC-DC |
| `FIN-DNS-01` | Server | Windows Server 2022 | IT Infrastructure | `10.10.0.3` | Critical | NYC-DC |
| `FIN-CLOUD-DB` | Server | Azure SQL MI | Data Platform | `10.30.5.61` | High | Azure East US |
