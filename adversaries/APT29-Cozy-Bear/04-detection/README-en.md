# APT29 Detection — Elastic SIEM

This directory contains all detection scripts developed and tested in this lab to detect APT29 techniques. The approach covers three layers: detection via REST API directly in Elasticsearch, automatic rule creation in Elastic SIEM via Kibana API, and full dashboard deployment via CLI.

---

## Structure

```
04-detection/
├── README.md                      ← PT-BR
├── README-en.md                   ← This file EN
├── elastic/
│   ├── apt29-detect-v4.py         ← Detection script 100% coverage via REST API
│   ├── apt29-create-rules.py      ← Creates 12 rules in Elastic SIEM via Kibana API
│   └── apt29-dashboard-deploy.sh  ← Full dashboard deployment via CLI
└── sigma/
    └── apt29-rules.yml            ← Sigma rules for portability
```

---

## Prerequisites

```bash
pip3 install requests urllib3
```

Confirm the Elastic Stack is accessible:

```bash
curl -sk -u elastic:tg8oCneGV2pgtFWxHbOD \
  https://192.168.10.20:9200/_cluster/health?pretty
```

Expected result:
```json
{
  "cluster_name": "elasticsearch",
  "status": "yellow",
  "number_of_nodes": 1
}
```

---

## Script 1 — apt29-detect-v4.py

### What it does

Searches directly in the `wazuh-alerts-*` Elasticsearch index via REST API and checks whether each APT29 TTP was detected. Generates a JSON report with timestamps, event counts and command samples captured.

### How to run

```bash
cd ~/AdversaryEmulation/
python3 apt29-detect-v4.py
```

### Expected output

```
=================================================================
  APT29 DETECTION REPORT v4 — 2026-05-13 10:46:24
=================================================================

  [T1059.001] PowerShell Execution
  [OK] DETECTED (25 events)
  First : 2026-05-13T11:12:44.537Z
  Last  : 2026-05-13T11:12:44.538Z
  Sample: powershell.exe -ep bypass -w hidden -e SQBF...

  [T1027] Obfuscation -ep bypass
  [OK] DETECTED (4 events)
  ...

=================================================================
  COVERAGE: 12/12 TTPs (100%)
=================================================================
  [+] Report: detection_report_v4_20260513_104624.json
```

### How it works internally

The script uses two query types depending on the TTP:

**wildcard** — for TTPs where the value can appear anywhere in the string:
```python
{"wildcard": {"data.win.eventdata.commandLine": "*powershell*"}}
```

**match_phrase** — for TTPs where the value is an exact string:
```python
{"match_phrase": {"data.win.eventdata.commandLine": "bypass"}}
```

All TTPs filter by `agent.name: WIN-DC01` to ensure events are from the correct endpoint.

### TTPs and queries

| TTP | Technique | Type | Field | Value |
|---|---|---|---|---|
| T1059.001 | PowerShell Execution | wildcard | commandLine | `*powershell*` |
| T1027 | Obfuscation | match_phrase | commandLine | `bypass` |
| T1218.011 | Rundll32 | match_phrase | commandLine | `rundll32` |
| T1087 | Account Discovery | match_phrase | commandLine | `net user` |
| T1069 | Permission Groups | match_phrase | commandLine | `net1 user` |
| T1082 | System Info | match_phrase | commandLine | `systeminfo` |
| T1057 | Process Discovery | match_phrase | commandLine | `tasklist` |
| T1560 | Archive Data | wildcard | commandLine | `*7z*` |
| T1012 | Registry Query | match_phrase | commandLine | `reg query` |
| T1547.009 | Startup Persistence | match_phrase | commandLine | `Startup` |
| T1566.002 | Spearphishing | match_phrase | commandLine | `edge` |
| T1105 | Tool Transfer | match_phrase | commandLine | `Invoke-WebRequest` |

### JSON report generated

```json
{
  "campaign": "APT29",
  "date": "2026-05-13T10:46:24",
  "coverage_pct": 100.0,
  "detected": 12,
  "total": 12,
  "results": [
    {
      "ttp": "T1059.001",
      "technique": "PowerShell Execution",
      "detected": true,
      "hits": 25,
      "first_seen": "2026-05-13T11:12:44.537Z"
    }
  ]
}
```

---

## Script 2 — apt29-create-rules.py

### What it does

Automatically creates 12 detection rules in Elastic SIEM via the Kibana Detection Engine API. Each rule includes the full MITRE ATT&CK mapping with tactic, technique and reference, severity, risk score and tags.

### How to run

```bash
cd ~/AdversaryEmulation/
python3 apt29-create-rules.py
```

### Expected output

```
=================================================================
  APT29 Detection Rules — Elastic SIEM
  2026-05-13 10:46:24
=================================================================
  [OK] [APT29] PowerShell Execution - T1059.001
  [OK] [APT29] Obfuscation -ep bypass - T1027
  [OK] [APT29] Rundll32 Execution - T1218.011
  [OK] [APT29] Account Discovery - T1087
  [OK] [APT29] System Information Discovery - T1082
  [OK] [APT29] Archive Collected Data - T1560
  [OK] [APT29] Registry Query - T1012
  [OK] [APT29] Startup Persistence - T1547.009
  [OK] [APT29] Ingress Tool Transfer - T1105
  [OK] [APT29] Spearphishing Download - T1566.002
  [OK] [APT29] Process Discovery - T1057
  [OK] [APT29] Permission Groups Discovery - T1069

=================================================================
  Rules created: 12/12
  Access Kibana: http://192.168.10.20:5601/app/security/rules
=================================================================
```

### Rules created in Kibana

| Rule | Severity | Risk Score | MITRE Tactic |
|---|---|---|---|
| PowerShell Execution - T1059.001 | High | 73 | TA0002 Execution |
| Obfuscation -ep bypass - T1027 | High | 73 | TA0005 Defense Evasion |
| Rundll32 Execution - T1218.011 | High | 73 | TA0005 Defense Evasion |
| Account Discovery - T1087 | Medium | 47 | TA0007 Discovery |
| System Information Discovery - T1082 | Medium | 47 | TA0007 Discovery |
| Archive Collected Data - T1560 | High | 73 | TA0009 Collection |
| Registry Query - T1012 | Medium | 47 | TA0007 Discovery |
| Startup Persistence - T1547.009 | High | 73 | TA0003 Persistence |
| Ingress Tool Transfer - T1105 | High | 73 | TA0011 Command and Control |
| Spearphishing Download - T1566.002 | High | 73 | TA0001 Initial Access |
| Process Discovery - T1057 | Medium | 47 | TA0007 Discovery |
| Permission Groups Discovery - T1069 | Medium | 47 | TA0007 Discovery |

To verify rules in Kibana:
```
http://192.168.10.20:5601
Security -> Rules -> Detection Rules (SIEM)
Filter by tag: APT29
```

If a rule already exists the script returns `[--] already exists` without failing and continues to the next one.

To recreate rules from scratch delete them in Kibana first and run the script again.

---

## Script 3 — apt29-dashboard-deploy.sh

### What it does

Creates a full dashboard in Kibana with 5 visualisations via Saved Objects API. The entire process is done via CLI without needing to interact with the Kibana GUI.

### How to run

```bash
cd ~/AdversaryEmulation/
chmod +x apt29-dashboard-deploy.sh
./apt29-dashboard-deploy.sh
```

### Expected output

```
======================================================
  APT29 Dashboard Deploy — 2026-05-13 11:36
======================================================
  →  Checking Kibana connection...
  ✅ Kibana accessible
🔧 Data View for SIEM alerts...
  ✅ Data View: APT29 Security Alerts
📊 VIZ 1/5 — Gauge: TTPs Detected
  ✅ lens/apt29-viz-gauge
📊 VIZ 2/5 — Bar: Alerts by TTP
  ✅ lens/apt29-viz-bar
📊 VIZ 3/5 — Timeline: Alerts over time
  ✅ lens/apt29-viz-timeline
📊 VIZ 4/5 — Treemap: MITRE Heatmap
  ✅ lens/apt29-viz-treemap
📊 VIZ 5/5 — Table: Latest Alerts
  ✅ lens/apt29-viz-table
📋 Main dashboard...
  ✅ dashboard/apt29-main-dashboard
======================================================
  ✅ APT29 Dashboard created successfully!
  🔗 http://192.168.10.20:5601/app/dashboards
======================================================
```

### Visualisations created

| Visualisation | Type | Content |
|---|---|---|
| TTPs Detected | Metric | Unique count of rules with alerts |
| Alerts by TTP | Horizontal bar | Top 12 TTPs by alert volume |
| Alert Timeline | Area chart | Alerts over time by severity |
| MITRE Heatmap | Treemap | Visual proportion by TTP |
| Latest Alerts | Datatable | Rule + severity + total sorted by count |

To recreate the dashboard from scratch:

```bash
./apt29-dashboard-deploy.sh --delete
./apt29-dashboard-deploy.sh
```

To access the dashboard:
```
http://192.168.10.20:5601
Dashboards -> APT29 Emulation — SOC Dashboard
Time range: Last 7 days
```

---

## Recommended execution order

The correct order is always to create the rules before running the attack so the SIEM is monitoring when events arrive.

```bash
# 1. Create detection rules
python3 apt29-create-rules.py

# 2. Deploy dashboard
./apt29-dashboard-deploy.sh

# 3. Run the emulation (see 03-emulation)
# ...

# 4. Verify detection after the attack
python3 apt29-detect-v4.py

# 5. Check alerts in Kibana
# http://192.168.10.20:5601 -> Security -> Alerts
```

---

## Results obtained in this lab

After the full APT29 emulation execution the results were:

```
Coverage:   12/12 TTPs — 100%
Alerts:     188 alerts generated
Severity:   169 High + 19 Medium
Rules:      12/12 with Succeeded status
```

---

## References

- [Elastic Detection Engine API](https://www.elastic.co/guide/en/security/current/rule-api-overview.html)
- [Kibana Saved Objects API](https://www.elastic.co/guide/en/kibana/current/saved-objects-api.html)
- [MITRE ATT&CK — APT29](https://attack.mitre.org/groups/G0016/)
- [Wazuh Elasticsearch Index](https://documentation.wazuh.com/current/user-manual/elasticsearch/indices.html)
