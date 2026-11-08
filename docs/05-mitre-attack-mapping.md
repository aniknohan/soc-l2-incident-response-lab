# 05 — MITRE ATT&CK Mapping

Techniques observed across the five incidents, mapped to MITRE ATT&CK Enterprise. The detection column links the rule or hunt written for each behaviour.

---

## Coverage by Incident

| Incident | Tactic | Technique | Observed as | Detection |
|---|---|---|---|---|
| INC-2031 | Initial Access | `T1566.002` Spearphishing Link | Password-expiry lure to a look-alike login page | Email gateway alert |
| INC-2031 | Initial Access / Persistence | `T1078` Valid Accounts | Stolen credentials used from `198.51.100.42` | Entra ID new-ASN sign-in alert |
| INC-2031 | Execution | `T1059.001` PowerShell | `-EncodedCommand` launched from `explorer.exe` on `FIN-WS-117` | SIEM rule DR-014 (encoded PowerShell); the Office-parent variant is covered by [Office spawns encoded PowerShell](../detections/sigma/proc_office_spawns_encoded_powershell.yml) |
| INC-2032 | Initial Access | `T1566` Phishing | Fraudulent wire-instruction email from the hijacked mailbox to a look-alike vendor domain | Email gateway alert (BEC pattern) |
| INC-2032 | Persistence | `T1098.002` Additional Email Delegate Permissions | Hidden inbox rule moving replies to Archive | [Inbox rule hides or forwards mail](../detections/sigma/m365_inbox_rule_hide_or_forward.yml) |
| INC-2033 | Credential Access | `T1110.003` Password Spraying | 4771 failures across nine accounts from `203.0.113.99`, three successes | [Kerberos password spray](../detections/sigma/win_kerberos_password_spray.yml), SPL hunts 1–2 |
| INC-2034 | Impact | `T1490` Inhibit System Recovery | `vssadmin delete shadows`, `wbadmin delete backup` | [Shadow copy or backup deletion](../detections/sigma/proc_inhibit_system_recovery.yml) |
| INC-2034 | Command and Control | `T1571` Non-Standard Port | 60-second beacon to `203.0.113.55:8443` | SPL hunt 5, KQL hunt 5 (beaconing) |
| INC-2035 | Initial Access | `T1190` Exploit Public-Facing Application | `UNION SELECT` allowed by the WAF with HTTP 200 | SPL hunt 7 |
| INC-2035 | Persistence | `T1505.003` Web Shell | `w3wp.exe` child processes and C2 | [IIS worker spawns shell](../detections/sigma/proc_webserver_spawns_shell.yml) |
| INC-2035 | Persistence | `T1053.005` Scheduled Task | `schtasks /create` with parent `w3wp.exe` | [IIS worker spawns shell](../detections/sigma/proc_webserver_spawns_shell.yml) |

---

## Related Techniques Seen in the Same Environment

These appear in linked alerts during the shift and shape the detections, even though they are not the primary technique of a case.

| Technique | Where | Detection |
|---|---|---|
| `T1558.003` Kerberoasting | RC4 service-ticket burst from `FIN-WS-277` | [Kerberoasting via RC4 TGS](../detections/sigma/win_kerberoasting_rc4_tgs.yml) |
| `T1021.002` SMB / Admin Shares | `svc_backup` logon from a workstation to a DC | [Service account logon from workstation](../detections/sigma/win_service_account_network_logon_from_workstation.yml) |
| `T1204.002` Malicious File | Macro document from a spoofed partner | [Office spawns encoded PowerShell](../detections/sigma/proc_office_spawns_encoded_powershell.yml) |
| `T1621` MFA Request Generation | Denied pushes followed by approval | KQL hunt 9 |
| `T1486` Data Encrypted for Impact | Mass `.lockd` rename if INC-2034 is not contained in time | Simulator alert COR-1043 |

---

## Coverage by Tactic

| Tactic | Techniques covered |
|---|---|
| Initial Access | T1566, T1566.002, T1190, T1078 |
| Execution | T1059.001, T1204.002 |
| Persistence | T1098.002, T1505.003, T1053.005 |
| Credential Access | T1110.003, T1558.003, T1621 |
| Lateral Movement | T1021.002 |
| Command and Control | T1571 |
| Impact | T1490, T1486 |

**Gaps:** Discovery, Collection and Exfiltration have no dedicated rule in this lab. They are listed in the [Roadmap](../README.md#roadmap).
