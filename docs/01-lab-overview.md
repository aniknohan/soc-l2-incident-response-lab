# 01 — Lab Overview

## Executive Summary

This lab documents Tier 2 SOC incident response work on five incidents escalated by a Tier 1 analyst at **SentriCore Security**, a fictional managed security service provider (MSSP), for its fictional client **Northbridge Financial Services**.

Each incident is worked the way an L2 analyst handles an escalation on shift: review the quality of the L1 handoff, scope the attack from raw telemetry, contain it within delegated authority, write the incident report and client notification, and decide whether to resolve at L2 or escalate to Tier 3.

The work runs on SentriCore, a browser-based SOC console that simulates a live night shift: an ITSM ticket queue with SLAs, SIEM search, SOAR response actions with tier-based approvals, simulated teammates and QA-graded reports.

> **Lab Safety Notice:** All data in this lab is synthetic. IP addresses come from the RFC 5737 documentation ranges or private RFC 1918 space, domains use `example.net`, `example.com` and `example.org`, and every organisation and person is fictional. No live infrastructure, production environment or real user was involved.

---

## Scenario

It is the night shift on 17 October 2026. Day shift has escalated five incidents to the `SOC-L2-Incident-Response` queue. None of them are contained. One L1 analyst's notes are inconsistent: some are complete, some are not.

| Incident | Escalated as | Day-shift assessment |
|---|---|---|
| INC-2031 | Credential theft via phishing leading to PowerShell execution | Single workstation and one account; credential use confirmed |
| INC-2032 | Business email compromise of the Treasury Director | Mailbox only; potential $480,000 fraudulent wire |
| INC-2033 | Password spraying with three successes | Three accounts compromised; one without MFA |
| INC-2034 | Ransomware precursor on an Accounting workstation | Beacon active; shadow copies deleted; no encryption yet |
| INC-2035 | SQL injection leading to a web shell on the customer portal | Public portal; customer PII exposure risk |

---

## Objectives

- Assess each L1 handoff and give feedback where it falls short.
- Scope every incident beyond the original alert: all affected users, hosts and data.
- Choose containment that the evidence justifies, and route actions above L2 authority through approval.
- Produce an incident report for management, auditors and the client.
- Decide on disposition: resolve at L2 or escalate to Tier 3.
- Turn what each incident taught into detection content.

---

## Scope

| In scope | Out of scope |
|---|---|
| Windows Security, Sysmon, Entra ID, Exchange Online, email gateway, firewall, proxy, DNS, VPN and WAF telemetry | Memory forensics and malware reverse engineering (Tier 3) |
| Containment within L2 authority, and approval requests above it | Eradication and rebuild work owned by client IT |
| Incident reports and client notifications | Legal breach-notification decisions |
| Sigma, Splunk SPL and Microsoft Sentinel KQL detections | Production deployment of detections |

---

## Methodology

The investigation follows the **NIST SP 800-61** incident handling lifecycle, mapped to SOC tiers:

| NIST phase | L2 activity in this lab |
|---|---|
| Detection and analysis | Handoff review, scoping queries, timeline reconstruction |
| Containment | Isolation, session revocation, password resets, blocking, emergency change requests |
| Eradication and recovery | Recommendations to client IT; Tier 3 escalation where forensics is needed |
| Post-incident activity | Root cause, lessons learned, new detections and playbook updates |

The step-by-step method is in [04 — L2 Investigation Methodology](04-l2-investigation-methodology.md).

---

## Deliverables per Incident

| Deliverable | Location |
|---|---|
| Case brief, evidence pack and hunting queries | `cases/INC-xxxx-*/README.md`, `evidence/` |
| Incident report | `cases/INC-xxxx-*/report.md` |
| Client notification | `cases/INC-xxxx-*/client-notification.md` |
| Detection content | [`detections/`](../detections/) |
| Playbook | [`playbooks/`](../playbooks/) |
