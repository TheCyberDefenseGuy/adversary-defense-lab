# LLM Pipeline — TTP to Detection Rule

This directory contains the hybrid pipeline that converts TTP IDs into Elastic SIEM detection rules. It works in two modes: without an API key it uses pre-defined local queries tested in the lab, with an Anthropic API key Claude generates dynamic KQL queries based on the TTP context.

The pipeline was designed to scale to multiple APTs. Adding a new adversary is simply adding a block to the `ttp-to-rule.py` file.

---

## Structure

```
tools/llm-pipeline/
├── README.md          ← PT-BR
├── README-en.md       ← This file EN
└── ttp-to-rule.py     ← Hybrid pipeline Local + Claude API
```

---

## Operating modes

### Local mode (without API key)

Works without any additional configuration. Queries are pre-defined in the file based on real detections tested in the lab.

```bash
python3 ttp-to-rule.py --list
python3 ttp-to-rule.py --apt APT29
python3 ttp-to-rule.py --ttp T1059.001
```

### Claude API mode (with API key)

With the API key configured Claude generates dynamic KQL queries based on the TTP context in MITRE ATT&CK. If the API fails the script automatically uses the local query as fallback.

```bash
export ANTHROPIC_API_KEY=sk-ant-...
python3 ttp-to-rule.py --apt APT29
```

The Anthropic API key is available at [console.anthropic.com](https://console.anthropic.com). Consumption for 12 TTPs is approximately 14,000 tokens per run, which is less than $0.05 with the Sonnet model.

---

## Installation

```bash
pip3 install requests urllib3
```

---

## Full usage

```bash
# List available TTPs for an APT
python3 ttp-to-rule.py --list
python3 ttp-to-rule.py --apt APT29 --list

# Create rules for all TTPs of an APT
python3 ttp-to-rule.py --apt APT29

# Create rule for a specific TTP
python3 ttp-to-rule.py --ttp T1059.001

# Delete created rules
python3 ttp-to-rule.py --delete

# With Claude API
export ANTHROPIC_API_KEY=sk-ant-...
python3 ttp-to-rule.py --apt APT29
```

---

## Expected output

```
==========================================================
  LLM Pipeline — TTP → Detection Rule
  APT: APT29 | Mode: Local (no API key)
  2026-05-13 12:02:55
==========================================================

  →  Checking Kibana connection...
  ✅ Kibana accessible

🚀 Processing 12 TTPs — APT29 — Cozy Bear

  [T1059.001] PowerShell Execution — Execution
  →  Local query: data.win.eventdata.commandLine:*powershell*
  ✅ [Local] T1059.001 — PowerShell Execution
  ...

==========================================================
  ✅ Created:     12/12
  📦 Local:       12
  🔗 http://192.168.10.20:5601/app/security/rules
==========================================================
```

---

## How to add a new APT

Open the `ttp-to-rule.py` file and add a new block in the `TTP_DB` dictionary following the same pattern as APT29:

```python
TTP_DB = {
    "APT29": {
        "name": "APT29 — Cozy Bear",
        "ttps": { ... }  # Existing TTPs
    },
    "APT28": {               # New APT
        "name": "APT28 — Fancy Bear",
        "ttps": {
            "T1059.001": {
                "name": "PowerShell Execution",
                "tactic": "Execution",
                "description": "APT28 uses PowerShell...",
                "severity": "high",
                "query": "data.win.eventdata.commandLine:*powershell*",
                "mitre_url": "https://attack.mitre.org/techniques/T1059/001/"
            }
        }
    }
}
```

Then run:

```bash
python3 ttp-to-rule.py --apt APT28 --list
python3 ttp-to-rule.py --apt APT28
```

---

## References

- [Anthropic API Documentation](https://docs.anthropic.com/)
- [Elastic Detection Engine API](https://www.elastic.co/guide/en/security/current/rule-api-overview.html)
- [MITRE ATT&CK — APT29](https://attack.mitre.org/groups/G0016/)
