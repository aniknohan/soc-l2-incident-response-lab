# Detections

Detection content written from the five incidents in this lab. Each rule targets the behaviour, not the specific indicator, so it still fires when the attacker changes infrastructure.

| Rule | Format | ATT&CK | Level | Source incident |
|---|---|---|---|---|
| [Kerberos password spray](sigma/win_kerberos_password_spray.yml) | Sigma | T1110.003 | medium | INC-2033 |
| [Kerberoasting via RC4 TGS](sigma/win_kerberoasting_rc4_tgs.yml) | Sigma | T1558.003 | high | COR-1048 |
| [Shadow copy or backup deletion](sigma/proc_inhibit_system_recovery.yml) | Sigma | T1490 | critical | INC-2034 |
| [IIS worker spawns shell or scheduler](sigma/proc_webserver_spawns_shell.yml) | Sigma | T1505.003, T1053.005 | high | INC-2035 |
| [Office spawns encoded PowerShell](sigma/proc_office_spawns_encoded_powershell.yml) | Sigma | T1204.002, T1059.001 | high | COR-1029 |
| [Inbox rule hides or forwards mail](sigma/m365_inbox_rule_hide_or_forward.yml) | Sigma | T1098.002, T1114.003 | high | INC-2032 |
| [Backup service account logon from a workstation](sigma/win_service_account_network_logon_from_workstation.yml) | Sigma | T1021.002, T1078.002 | high | COR-1022 |
| [Splunk hunts](splunk_hunts.spl) | SPL | 10 hunts | | all |
| [Sentinel hunts](sentinel_hunts.kql) | KQL | 9 hunts | | all |

## Converting the Sigma rules

```bash
pip install sigma-cli
sigma plugin install splunk microsoft365defender
sigma convert -t splunk -p sysmon detections/sigma/proc_inhibit_system_recovery.yml
sigma convert -t microsoft365defender detections/sigma/proc_webserver_spawns_shell.yml
```

## Tuning notes

- **Password spray** is a single-event rule; the spray threshold (more than 10 accounts from one IP in 30 minutes) lives in the SIEM aggregation (`splunk_hunts.spl` hunt 1).
- **Kerberoasting** excludes machine accounts (`$`) and `krbtgt`; add legacy RC4-only services to an allow list instead of lowering the level.
- **Service account logon** hard-codes the backup server `10.10.1.50`; move it to a lookup in production.
