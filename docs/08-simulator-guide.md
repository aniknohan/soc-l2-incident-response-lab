# 08 — Simulator Guide

A single-page SOC console I use as the lab environment: [`simulator/index.html`](../simulator/index.html). Open it in any browser or through GitHub Pages; progress is saved in the browser.

## What it simulates

- **A night shift with an SLA clock** (pause, 1×, 10×, 30×). New alerts keep arriving and pop up live.
- **An ITSM ticket queue** (`SIR` numbers, assignment groups, response and resolution SLAs).
- **L1 workflow:** acknowledge → analyze (attach evidence, worksheet, contact the user) → triage report → resolve or escalate → QA review.
- **L2 workflow:** accept and rate the handoff → scope with SIEM → contain → incident report and client notification → resolve or escalate to Tier 3 → QA review.
- **SIEM search** with field filters, wildcards, OR/NOT and `stats count by`, `head` and `sort`.
- **SOAR response actions** with tier-based approvals (emergency changes).
- **Six simulated teammates**, a team chat channel and manager nudges.
- **Dashboard**, threat intel, endpoints, network, vulnerabilities and ATT&CK coverage views.

## How I use it for this portfolio

1. Switch the role to **SOC Analyst L2**.
2. Open each incident (INC-2031 to INC-2035) and work it end to end.
3. Write the case `report.md` and `client-notification.md` in this repo from my own findings.
4. Record the simulator's QA score in the case `README.md`.
