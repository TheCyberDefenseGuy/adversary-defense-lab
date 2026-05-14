# Sigma Rules — APT29

The Sigma rules in this directory convert the APT29 Elastic SIEM detections to a portable format that can be used in any SIEM. The queries were based on real detections tested in this lab.

---

## What are Sigma Rules

Sigma is a generic detection rule format for SIEMs, similar to what Snort is for IDS. A Sigma rule can be converted to Elastic, Splunk, Microsoft Sentinel, QRadar, Chronicle and others using conversion tools like `sigma-cli` or online platforms like Uncoder.io.

Official repository: [https://github.com/SigmaHQ/sigma](https://github.com/SigmaHQ/sigma)

---

## Rules included

| File | TTPs | Description |
|---|---|---|
| apt29-sigma-rules.yml | 12 TTPs | All APT29 rules in a single file |

| Rule | TTP | Level |
|---|---|---|
| APT29 PowerShell Execution | T1059.001 | high |
| APT29 PowerShell Obfuscation Bypass | T1027 | high |
| APT29 Rundll32 Execution | T1218.011 | high |
| APT29 Account Discovery via Net User | T1087 | medium |
| APT29 Permission Groups Discovery | T1069 | medium |
| APT29 System Information Discovery | T1082 | medium |
| APT29 Process Discovery via Tasklist | T1057 | medium |
| APT29 Archive Collected Data with 7-Zip | T1560 | high |
| APT29 Registry Query Discovery | T1012 | medium |
| APT29 Startup Folder Persistence | T1547.009 | high |
| APT29 Spearphishing Download via Edge | T1566.002 | high |
| APT29 Ingress Tool Transfer | T1105 | high |

---

## Option 1 — Online Conversion with Uncoder.io

[Uncoder.io](https://uncoder.io/) is a free online platform that converts Sigma rules to any SIEM without installing anything. It is the fastest way to adapt the rules from this repository to your environment.

### How to use Uncoder.io

**Step 1** — Go to [https://uncoder.io/](https://uncoder.io/)

**Step 2** — In the left panel select the input format: `Sigma`

**Step 3** — Paste the content of the `apt29-sigma-rules.yml` file

**Step 4** — In the right panel select the target SIEM:

| SIEM | Output format |
|---|---|
| Elastic SIEM | Kibana KQL / Lucene / EQL |
| Splunk | SPL (Splunk Processing Language) |
| Microsoft Sentinel | KQL (Kusto Query Language) |
| IBM QRadar | AQL (Ariel Query Language) |
| Google Chronicle | YARA-L |
| Sumo Logic | Sumo Logic Query |
| Azure Data Explorer | KQL |
| CrowdStrike | CQL |

**Step 5** — Click **Translate** and copy the generated query directly into your SIEM.

### Conversion example

**Input (Sigma):**
```yaml
detection:
    selection:
        CommandLine|contains:
            - 'powershell'
    condition: selection
```

**Splunk output (SPL):**
```
CommandLine="*powershell*"
| stats count by CommandLine, Image, User
```

**Sentinel output (KQL):**
```kql
SecurityEvent
| where CommandLine contains "powershell"
| project TimeGenerated, CommandLine, Account, Computer
```

**Elastic output (Lucene):**
```
CommandLine:*powershell*
```

---

## Option 2 — CLI Conversion with sigma-cli

For those who prefer to automate the conversion or integrate it into a CI/CD pipeline.

### Install sigma-cli

```bash
pip3 install sigma-cli
sigma plugin install splunk
sigma plugin install sentinel
sigma plugin install qradar
sigma plugin install elasticsearch
```

### Convert to Splunk

```bash
sigma convert -t splunk apt29-sigma-rules.yml
```

### Convert to Microsoft Sentinel

```bash
sigma convert -t sentinel apt29-sigma-rules.yml
```

### Convert to QRadar

```bash
sigma convert -t qradar apt29-sigma-rules.yml
```

### Convert to Elastic Lucene

```bash
sigma convert -t lucene apt29-sigma-rules.yml
```

### Convert to Elastic EQL

```bash
sigma convert -t eql apt29-sigma-rules.yml
```

### Convert a specific rule by tag

```bash
sigma convert -t splunk apt29-sigma-rules.yml --filter "tags=attack.t1059.001"
```

### Convert with output to file

```bash
sigma convert -t splunk apt29-sigma-rules.yml -o apt29-splunk-queries.txt
sigma convert -t sentinel apt29-sigma-rules.yml -o apt29-sentinel-queries.kql
```

### Validate rules before converting

```bash
sigma check apt29-sigma-rules.yml
```

---

## Sigma rule structure

```yaml
title: APT29 PowerShell Execution          # Rule name
id: unique-uuid                             # Unique UUID
status: test                               # test / stable / deprecated
description: Detailed description          # What it detects
references:                                # MITRE links and sources
    - https://attack.mitre.org/...
author: TheCyberDefenseGuy
date: 2026-05-13
tags:                                      # MITRE ATT&CK mapping
    - attack.execution
    - attack.t1059.001
    - apt29
logsource:                                 # Log source
    category: process_creation
    product: windows
detection:                                 # Detection logic
    selection:
        CommandLine|contains:
            - 'powershell'
    condition: selection
falsepositives:                            # Known false positives
    - Legitimate administrative usage
level: high                                # informational/low/medium/high/critical
```

---

## References

- [Sigma HQ GitHub](https://github.com/SigmaHQ/sigma)
- [sigma-cli Documentation](https://github.com/SigmaHQ/sigma-cli)
- [Sigma Rule Specification](https://sigmahq.io/docs/specification.html)
- [Uncoder.io — Sigma Online Converter](https://uncoder.io/)
- [MITRE ATT&CK — APT29](https://attack.mitre.org/groups/G0016/)
