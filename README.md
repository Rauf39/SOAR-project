# Wazuh + n8n SOAR-Style Security Automation Lab

## Overview

This project is a SOAR-style security automation lab built with **Wazuh**, **n8n**, **OpenAI API**, **Gmail SMTP**, and **Wazuh Active Response**.

The goal of the lab is to demonstrate an end-to-end security workflow:

1. Detect high-severity security alerts with Wazuh
2. Forward alert data to n8n through a webhook
3. Generate an AI-assisted SOC triage report
4. Map the alert to MITRE ATT&CK where applicable
5. Send the report to email
6. Automatically block suspicious source IPs for SSH brute-force activity

This lab is designed for learning SOC automation, alert triage, and basic incident response workflows.

---

## Architecture

```text
┌──────────────┐
│ Wazuh Agent  │
│ Linux Host   │
└──────┬───────┘
       │
       │ Security event
       ▼
┌──────────────┐
│ Wazuh Manager│
│ Alert Engine │
└──────┬───────┘
       │
       │ Alert severity 7+
       ▼
┌────────────────────────┐
│ Custom Wazuh Integration│
│ Sends JSON to n8n       │
└──────┬─────────────────┘
       │
       │ Webhook
       ▼
┌──────────────┐
│ n8n Workflow │
│ Alert Logic  │
└──────┬───────┘
       │
       │ OpenAI API
       ▼
┌──────────────────────┐
│ AI SOC Triage Report │
│ MITRE + Evidence     │
└──────┬───────────────┘
       │
       │ SMTP
       ▼
┌──────────────┐
│ Gmail Report │
└──────────────┘

For SSH brute-force alerts:

┌──────────────┐
│ Wazuh Alert  │
│ Rule 2502    │
└──────┬───────┘
       ▼
┌──────────────────────┐
│ Wazuh Active Response│
│ firewall-drop        │
└──────┬───────────────┘
       ▼
┌──────────────┐
│ iptables DROP│
│ Source IP    │
└──────────────┘
```

---

## Tools Used

* **Wazuh** — SIEM/XDR platform for log monitoring and alerting
* **n8n** — automation platform used for webhook processing and workflow orchestration
* **OpenAI API** — used to generate SOC-style triage reports
* **Gmail SMTP** — used to deliver alert reports by email
* **iptables** — used by Wazuh Active Response to block suspicious IPs
* **Linux / Ubuntu** — monitored endpoint and Wazuh environment

---

## Features

### Wazuh Alert Forwarding

A custom Wazuh integration forwards alerts with severity level **7 or higher** to n8n.

```xml
<integration>
  <name>custom-n8n</name>
  <level>7</level>
  <alert_format>json</alert_format>
</integration>
```

This reduces noise and sends only medium/high severity alerts into the automation pipeline.

---

### n8n Webhook Workflow

n8n receives Wazuh alerts through a production webhook.

The workflow processes the alert, extracts useful fields, and prepares the data for AI-based triage.

Extracted fields include:

* Alert title
* Severity level
* Agent name
* Rule ID
* Timestamp
* Log source/location
* MITRE ATT&CK fields, if provided by Wazuh
* Full raw alert JSON

---

### AI-Generated SOC Report

OpenAI is used to generate a professional SOC triage report.

The report includes:

* Executive summary
* Alert details
* MITRE ATT&CK mapping
* Evidence observed
* Risk assessment
* False positive possibility
* Recommended investigation steps
* Recommended response actions

The goal is not to let AI make final incident decisions, but to assist the analyst with faster triage and better alert context.

---

### MITRE ATT&CK Mapping

If Wazuh provides MITRE ATT&CK fields, the report uses them directly.

If Wazuh does not provide MITRE data, the AI report attempts to infer a likely mapping and clearly marks it as an inferred mapping.

Example from SSH failed authentication activity:

```text
Tactic: Credential Access
Technique: Brute Force
Technique ID: T1110
Confidence: High
```

Example from Linux group/account modification activity:

```text
Tactic: Persistence / Privilege Escalation
Technique: Account Manipulation
Technique ID: T1098
Confidence: Medium
```

---

### Email Alert Delivery

After the SOC report is generated, n8n sends the report to email using SMTP.

Example subject:

```text
Wazuh Alert [Level 10]: syslog: User missed the password more than one time
```

The email contains the full triage report and recommended next steps.

---

### Automated IP Blocking

For SSH brute-force / failed authentication alerts, Wazuh Active Response is configured to automatically block the source IP.

Active Response uses `firewall-drop` to add a DROP rule through iptables.

Example:

```text
DROP all -- 192.168.0.175 0.0.0.0/0
```

This demonstrates basic automated containment.

---

## Active Response Configuration

The following Wazuh Active Response configuration was used for SSH authentication failure alerts:

```xml
<command>
  <name>firewall-drop</name>
  <executable>firewall-drop</executable>
  <timeout_allowed>yes</timeout_allowed>
</command>

<active-response>
  <command>firewall-drop</command>
  <location>local</location>
  <rules_id>2502</rules_id>
  <timeout>600</timeout>
</active-response>
```

This configuration blocks the source IP for **10 minutes** when Wazuh rule `2502` is triggered.

Rule `2502` was used during testing for repeated SSH authentication failures.

---

## Custom Wazuh Integration

The custom integration script sends Wazuh alert JSON to the n8n webhook.

Example script path:

```text
/var/ossec/integrations/custom-n8n
```

Example safe template:

```python
#!/usr/bin/env python3

import sys
import json
import urllib.request
from datetime import datetime

WEBHOOK_URL = "http://YOUR_N8N_SERVER:5678/webhook/wazuh-alert"
LOG_FILE = "/tmp/wazuh-n8n-integration.log"

def log(msg):
    with open(LOG_FILE, "a") as f:
        f.write(f"{datetime.now()} {msg}\n")

def main():
    try:
        alert_file = sys.argv[1]

        with open(alert_file, "r") as f:
            alert = json.load(f)

        data = json.dumps(alert).encode("utf-8")

        req = urllib.request.Request(
            WEBHOOK_URL,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST"
        )

        with urllib.request.urlopen(req, timeout=10) as response:
            log(f"Sent alert to n8n. Status: {response.status}")

    except Exception as e:
        log(f"ERROR: {str(e)}")

if __name__ == "__main__":
    main()
```

Permissions:

```bash
sudo chmod 750 /var/ossec/integrations/custom-n8n
sudo chown root:wazuh /var/ossec/integrations/custom-n8n
```

---

## Test Scenarios

### 1. Linux Group Creation

Command used:

```bash
sudo groupadd testgroup
```

Expected result:

* Wazuh detects a new group creation event
* Alert is forwarded to n8n
* AI SOC report is generated
* Email notification is delivered

Example alert title:

```text
New group added to the system.
```

---

### 2. SSH Failed Authentication

Test performed by attempting failed SSH login attempts from another machine.

Expected result:

* Wazuh detects multiple failed SSH authentication attempts
* Alert severity reaches high level
* Source IP is included in the report
* MITRE ATT&CK mapping is generated
* Email notification is delivered

Example MITRE mapping:

```text
T1110 - Brute Force
```

---

### 3. Automated Source IP Blocking

After SSH failed authentication alert was generated, Wazuh Active Response executed `firewall-drop`.

Verification command:

```bash
sudo iptables -L -n --line-numbers
```

Example result:

```text
DROP all -- 192.168.0.175 0.0.0.0/0
```

This confirmed that the suspicious source IP was automatically blocked.

---

## Screenshots

Add screenshots in the `screenshots/` folder.

Recommended screenshots:

```text
screenshots/n8n-workflow.png
screenshots/email-report.png
screenshots/iptables-block.png
screenshots/wazuh-alert.png
```

Example Markdown:

```markdown
![n8n Workflow](screenshots/n8n-workflow.png)

![SOC Email Report](screenshots/email-report.png)

![iptables IP Block](screenshots/iptables-block.png)
```

---

## Example SOC Report Output

Example report sections generated by the workflow:

```text
# Wazuh SOC Alert Report

## 1. Executive Summary
Wazuh generated a high-severity authentication alert showing multiple failed SSH password attempts from a source IP.

## 2. Alert Details
- Alert Name:
- Severity:
- Agent:
- Rule ID:
- Timestamp UTC:
- Timestamp Baku:
- Log Source / Location:

## 3. MITRE ATT&CK Mapping
- Tactic:
- Technique:
- Technique ID:
- Confidence:

## 4. Evidence Observed
Concrete evidence from the alert.

## 5. Risk Assessment
Low / Medium / High / Critical.

## 6. False Positive Possibility
When this activity could be benign.

## 7. Recommended Investigation Steps
Practical SOC L1 investigation steps.

## 8. Recommended Response Actions
Containment and remediation suggestions.
```

---

## Security Notes

This project is a lab environment and should not be treated as a production-ready SOAR deployment.

Sensitive values should never be committed to GitHub, including:

* OpenAI API keys
* Gmail app passwords
* n8n credentials
* SSH private keys
* Real passwords
* `.env` files

Use placeholders in public documentation.

Example:

```text
OPENAI_API_KEY=REDACTED
SMTP_PASSWORD=REDACTED
WEBHOOK_URL=http://YOUR_N8N_SERVER:5678/webhook/wazuh-alert
```

---

## Limitations

Current limitations:

* No alert deduplication yet
* No external enrichment for IP reputation
* No analyst approval before blocking
* No ticketing system integration
* No central database for storing alert history
* Email reports are generated from alert context only
* Active Response block confirmation is verified through logs/iptables, not automatically inserted into every report

---

## Future Improvements

Planned improvements:

* Add alert deduplication
* Add IP reputation enrichment
* Add Slack or Telegram escalation for critical alerts
* Add analyst approval before automated blocking
* Store alerts and reports in a database
* Add dashboarding for alert history
* Add TheHive/Jira ticket creation
* Improve HTML email formatting
* Add block-status verification into the report

---

## What I Learned

This lab helped me practice:

* Wazuh alerting and rule severity
* Custom Wazuh integrations
* n8n automation workflows
* API-based alert forwarding
* OpenAI-assisted SOC triage
* MITRE ATT&CK mapping
* SMTP email delivery
* Wazuh Active Response
* SSH brute-force detection
* Automated IP blocking with firewall-drop and iptables

---

## Disclaimer

This project was built for educational and lab purposes.

The AI-generated report should assist SOC analysts, not replace human investigation or final decision-making.

Automated blocking should be carefully controlled in production environments and ideally include approval workflows, allowlists, logging, and rollback procedures.
