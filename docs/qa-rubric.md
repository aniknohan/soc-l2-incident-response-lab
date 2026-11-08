# QA Rubric

The simulator grades every resolved ticket and incident against these rubrics. Each case's `README.md` records the score I achieved.

## L1 triage report (100 points)

| Criterion | Points | Full marks when |
|---|---|---|
| Analysis worksheet | 25 | Affected user, asset, external indicator, ATT&CK technique and outcome all correct |
| Summary | 10 | 60+ characters, names the affected user or asset |
| Affected users and assets | 10 | Every user and host entity listed |
| Indicators of compromise | 10 | Every malicious indicator listed; clean ones not mislabelled |
| Evidence attached | 10 | At least two log events, including the decisive high-severity one |
| Analysis performed | 10 | 80+ characters describing at least two distinct checks |
| Timestamps | 5 | UTC times included |
| Verdict and justification | 10 | Justified and consistent with the disposition |
| Recommendation | 10 | Containment or escalation for true positives; closure or tuning for benign |

## L2 incident report (100 points)

| Criterion | Points | Full marks when |
|---|---|---|
| L1 handoff review | 10 | Rating matches the note's real quality |
| Scoping accuracy | 20 | Every scoping question answered correctly from evidence |
| Containment | 20 | Every required containment action in place, nothing unneeded |
| Executive summary | 10 | 100+ characters, no log jargon |
| Timeline | 10 | Four or more timestamped entries |
| Root cause | 5 | Matches the evidence |
| Recommendations | 10 | At least two concrete recommendations |
| Client notification | 10 | 120+ characters, references the incident or client, no jargon |
| Disposition | 5 | Resolve vs escalate matches the incident |
