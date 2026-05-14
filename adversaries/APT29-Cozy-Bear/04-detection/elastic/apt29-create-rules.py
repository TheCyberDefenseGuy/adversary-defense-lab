#!/usr/bin/env python3
"""
apt29-create-rules.py — APT29 Detection Rules Creator
Adversary Defense Lab — APT29 Cozy Bear Detection

Cria automaticamente 12 regras de detecção no Elastic SIEM
via Kibana Detection Engine API. Cada regra inclui mapeamento
MITRE ATT&CK completo com táctica, técnica e referência.

Uso:
    python3 apt29-create-rules.py

Pré-requisitos:
    pip3 install requests urllib3

Resultado:
    12 regras criadas em Security -> Rules no Kibana
    Visíveis em Security -> Alerts após dispararem
"""
import requests, json, urllib3
from datetime import datetime
urllib3.disable_warnings()

# ─── Configuração ──────────────────────────────────────────────────────────────
# Actualiza com o IP e credenciais do teu ambiente
KIBANA = {
    "url": "http://192.168.10.20:5601",
    "user": "elastic",
    "pass": "tg8oCneGV2pgtFWxHbOD"
}

# ─── Detection Rules APT29 ─────────────────────────────────────────────────────
# Cada regra aparece no Kibana Security -> Alerts quando disparar
# risk_score 73 = High | risk_score 47 = Medium
APT29_RULES = [
    {
        "name": "[APT29] PowerShell Execution - T1059.001",
        "description": "Detecta execucao de PowerShell - APT29 usa PowerShell para execucao de payloads",
        "risk_score": 73,
        "severity": "high",
        "type": "query",
        "query": 'agent.name: "WIN-DC01" AND data.win.eventdata.commandLine: *powershell*',
        "language": "kuery",
        "index": ["wazuh-alerts-*"],
        "tags": ["APT29", "T1059.001", "Execution"],
        "threat": [{
            "framework": "MITRE ATT&CK",
            "tactic": {"id": "TA0002", "name": "Execution", "reference": "https://attack.mitre.org/tactics/TA0002/"},
            "technique": [{"id": "T1059.001", "name": "PowerShell", "reference": "https://attack.mitre.org/techniques/T1059/001/"}]
        }]
    },
    {
        "name": "[APT29] Obfuscation -ep bypass - T1027",
        "description": "Detecta PowerShell com ExecutionPolicy bypass - evasao de defesas",
        "risk_score": 73,
        "severity": "high",
        "type": "query",
        "query": 'agent.name: "WIN-DC01" AND data.win.eventdata.commandLine: *bypass*',
        "language": "kuery",
        "index": ["wazuh-alerts-*"],
        "tags": ["APT29", "T1027", "Defense Evasion"],
        "threat": [{
            "framework": "MITRE ATT&CK",
            "tactic": {"id": "TA0005", "name": "Defense Evasion", "reference": "https://attack.mitre.org/tactics/TA0005/"},
            "technique": [{"id": "T1027", "name": "Obfuscated Files or Information", "reference": "https://attack.mitre.org/techniques/T1027/"}]
        }]
    },
    {
        "name": "[APT29] Rundll32 Execution - T1218.011",
        "description": "Detecta execucao via Rundll32 - APT29 usa para carregar DLLs maliciosas",
        "risk_score": 73,
        "severity": "high",
        "type": "query",
        "query": 'agent.name: "WIN-DC01" AND data.win.eventdata.commandLine: *rundll32*',
        "language": "kuery",
        "index": ["wazuh-alerts-*"],
        "tags": ["APT29", "T1218.011", "Defense Evasion"],
        "threat": [{
            "framework": "MITRE ATT&CK",
            "tactic": {"id": "TA0005", "name": "Defense Evasion", "reference": "https://attack.mitre.org/tactics/TA0005/"},
            "technique": [{"id": "T1218.011", "name": "Rundll32", "reference": "https://attack.mitre.org/techniques/T1218/011/"}]
        }]
    },
    {
        "name": "[APT29] Account Discovery - T1087",
        "description": "Detecta enumeracao de contas via net user",
        "risk_score": 47,
        "severity": "medium",
        "type": "query",
        "query": 'agent.name: "WIN-DC01" AND data.win.eventdata.commandLine: "net user"',
        "language": "kuery",
        "index": ["wazuh-alerts-*"],
        "tags": ["APT29", "T1087", "Discovery"],
        "threat": [{
            "framework": "MITRE ATT&CK",
            "tactic": {"id": "TA0007", "name": "Discovery", "reference": "https://attack.mitre.org/tactics/TA0007/"},
            "technique": [{"id": "T1087", "name": "Account Discovery", "reference": "https://attack.mitre.org/techniques/T1087/"}]
        }]
    },
    {
        "name": "[APT29] System Information Discovery - T1082",
        "description": "Detecta recolha de informacao do sistema via systeminfo",
        "risk_score": 47,
        "severity": "medium",
        "type": "query",
        "query": 'agent.name: "WIN-DC01" AND data.win.eventdata.commandLine: *systeminfo*',
        "language": "kuery",
        "index": ["wazuh-alerts-*"],
        "tags": ["APT29", "T1082", "Discovery"],
        "threat": [{
            "framework": "MITRE ATT&CK",
            "tactic": {"id": "TA0007", "name": "Discovery", "reference": "https://attack.mitre.org/tactics/TA0007/"},
            "technique": [{"id": "T1082", "name": "System Information Discovery", "reference": "https://attack.mitre.org/techniques/T1082/"}]
        }]
    },
    {
        "name": "[APT29] Archive Collected Data - T1560",
        "description": "Detecta compressao de dados com 7-Zip para exfiltracao",
        "risk_score": 73,
        "severity": "high",
        "type": "query",
        "query": 'agent.name: "WIN-DC01" AND data.win.eventdata.commandLine: *7z*',
        "language": "kuery",
        "index": ["wazuh-alerts-*"],
        "tags": ["APT29", "T1560", "Collection"],
        "threat": [{
            "framework": "MITRE ATT&CK",
            "tactic": {"id": "TA0009", "name": "Collection", "reference": "https://attack.mitre.org/tactics/TA0009/"},
            "technique": [{"id": "T1560", "name": "Archive Collected Data", "reference": "https://attack.mitre.org/techniques/T1560/"}]
        }]
    },
    {
        "name": "[APT29] Registry Query - T1012",
        "description": "Detecta query ao registry para descoberta de configuracoes",
        "risk_score": 47,
        "severity": "medium",
        "type": "query",
        "query": 'agent.name: "WIN-DC01" AND data.win.eventdata.commandLine: "reg query"',
        "language": "kuery",
        "index": ["wazuh-alerts-*"],
        "tags": ["APT29", "T1012", "Discovery"],
        "threat": [{
            "framework": "MITRE ATT&CK",
            "tactic": {"id": "TA0007", "name": "Discovery", "reference": "https://attack.mitre.org/tactics/TA0007/"},
            "technique": [{"id": "T1012", "name": "Query Registry", "reference": "https://attack.mitre.org/techniques/T1012/"}]
        }]
    },
    {
        "name": "[APT29] Startup Persistence - T1547.009",
        "description": "Detecta persistencia via pasta Startup",
        "risk_score": 73,
        "severity": "high",
        "type": "query",
        "query": 'agent.name: "WIN-DC01" AND data.win.eventdata.commandLine: *Startup*',
        "language": "kuery",
        "index": ["wazuh-alerts-*"],
        "tags": ["APT29", "T1547.009", "Persistence"],
        "threat": [{
            "framework": "MITRE ATT&CK",
            "tactic": {"id": "TA0003", "name": "Persistence", "reference": "https://attack.mitre.org/tactics/TA0003/"},
            "technique": [{"id": "T1547.009", "name": "Shortcut Modification", "reference": "https://attack.mitre.org/techniques/T1547/009/"}]
        }]
    },
    {
        "name": "[APT29] Ingress Tool Transfer - T1105",
        "description": "Detecta download de ferramentas via Invoke-WebRequest",
        "risk_score": 73,
        "severity": "high",
        "type": "query",
        "query": 'agent.name: "WIN-DC01" AND data.win.eventdata.commandLine: *Invoke-WebRequest*',
        "language": "kuery",
        "index": ["wazuh-alerts-*"],
        "tags": ["APT29", "T1105", "Command and Control"],
        "threat": [{
            "framework": "MITRE ATT&CK",
            "tactic": {"id": "TA0011", "name": "Command and Control", "reference": "https://attack.mitre.org/tactics/TA0011/"},
            "technique": [{"id": "T1105", "name": "Ingress Tool Transfer", "reference": "https://attack.mitre.org/techniques/T1105/"}]
        }]
    },
    {
        "name": "[APT29] Spearphishing Download - T1566.002",
        "description": "Detecta download via Edge browser - vector inicial APT29",
        "risk_score": 73,
        "severity": "high",
        "type": "query",
        "query": 'agent.name: "WIN-DC01" AND data.win.eventdata.commandLine: *edge*',
        "language": "kuery",
        "index": ["wazuh-alerts-*"],
        "tags": ["APT29", "T1566.002", "Initial Access"],
        "threat": [{
            "framework": "MITRE ATT&CK",
            "tactic": {"id": "TA0001", "name": "Initial Access", "reference": "https://attack.mitre.org/tactics/TA0001/"},
            "technique": [{"id": "T1566.002", "name": "Spearphishing Link", "reference": "https://attack.mitre.org/techniques/T1566/002/"}]
        }]
    },
    {
        "name": "[APT29] Process Discovery - T1057",
        "description": "Detecta enumeracao de processos via tasklist",
        "risk_score": 47,
        "severity": "medium",
        "type": "query",
        "query": 'agent.name: "WIN-DC01" AND data.win.eventdata.commandLine: *tasklist*',
        "language": "kuery",
        "index": ["wazuh-alerts-*"],
        "tags": ["APT29", "T1057", "Discovery"],
        "threat": [{
            "framework": "MITRE ATT&CK",
            "tactic": {"id": "TA0007", "name": "Discovery", "reference": "https://attack.mitre.org/tactics/TA0007/"},
            "technique": [{"id": "T1057", "name": "Process Discovery", "reference": "https://attack.mitre.org/techniques/T1057/"}]
        }]
    },
    {
        "name": "[APT29] Permission Groups Discovery - T1069",
        "description": "Detecta enumeracao de grupos via net localgroup",
        "risk_score": 47,
        "severity": "medium",
        "type": "query",
        "query": 'agent.name: "WIN-DC01" AND data.win.eventdata.commandLine: "net1 user"',
        "language": "kuery",
        "index": ["wazuh-alerts-*"],
        "tags": ["APT29", "T1069", "Discovery"],
        "threat": [{
            "framework": "MITRE ATT&CK",
            "tactic": {"id": "TA0007", "name": "Discovery", "reference": "https://attack.mitre.org/tactics/TA0007/"},
            "technique": [{"id": "T1069", "name": "Permission Groups Discovery", "reference": "https://attack.mitre.org/techniques/T1069/"}]
        }]
    }
]

def create_rule(rule):
    """
    Cria uma Detection Rule no Elastic SIEM via Kibana API.
    Retorna o status code e a resposta JSON do Kibana.
    Status 200/201 = criada com sucesso
    Status 409 = já existe, não é erro
    """
    payload = {
        "name": rule["name"],
        "description": rule["description"],
        "risk_score": rule["risk_score"],
        "severity": rule["severity"],
        "type": rule["type"],
        "query": rule["query"],
        "language": rule["language"],
        "index": rule["index"],
        "tags": rule["tags"],
        "threat": rule["threat"],
        "enabled": True,
        "from": "now-6h",
        "interval": "5m",
        "max_signals": 100,
        "rule_id": rule["name"].lower().replace(" ", "_").replace("[", "").replace("]", "").replace(".", "_")[:50]
    }

    r = requests.post(
        f"{KIBANA['url']}/api/detection_engine/rules",
        auth=(KIBANA['user'], KIBANA['pass']),
        headers={"kbn-xsrf": "true", "Content-Type": "application/json"},
        json=payload,
        verify=False,
        timeout=30
    )
    return r.status_code, r.json()

def run():
    """
    Executa a criação de todas as regras APT29.
    Regras já existentes são ignoradas sem erro.
    """
    print("=" * 65)
    print(f"  APT29 Detection Rules — Elastic SIEM")
    print(f"  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 65)

    created = 0
    failed = 0

    for rule in APT29_RULES:
        status, resp = create_rule(rule)
        if status in [200, 201]:
            created += 1
            print(f"  [OK] {rule['name']}")
        elif status == 409:
            print(f"  [--] {rule['name']} (ja existe)")
            created += 1
        else:
            failed += 1
            print(f"  [XX] {rule['name']} — {resp.get('message', status)}")

    print(f"\n{'=' * 65}")
    print(f"  Regras criadas: {created}/{len(APT29_RULES)}")
    if failed:
        print(f"  Falhas:         {failed}")
    print(f"  Acede ao Kibana: http://192.168.10.20:5601/app/security/rules")
    print("=" * 65)

if __name__ == "__main__":
    run()
