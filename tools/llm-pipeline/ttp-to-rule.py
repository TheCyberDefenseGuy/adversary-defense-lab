#!/usr/bin/env python3
"""
ttp-to-rule.py — LLM Pipeline Híbrido
Converte TTP IDs em Detection Rules no Elastic SIEM

Modo 1 (sem API key): queries pré-definidas locais
Modo 2 (com API key): Claude API gera queries dinâmicas

Uso:
    python3 ttp-to-rule.py                      # todos os TTPs APT29
    python3 ttp-to-rule.py --ttp T1059.001      # TTP específico
    python3 ttp-to-rule.py --apt APT29          # todos os TTPs de um APT
    python3 ttp-to-rule.py --list               # lista TTPs disponíveis
    python3 ttp-to-rule.py --delete             # apaga regras criadas

Variável de ambiente (opcional):
    export ANTHROPIC_API_KEY=sk-ant-...
"""

import os
import sys
import json
import argparse
import requests
from requests.auth import HTTPBasicAuth
from datetime import datetime

# ─── Configuração ──────────────────────────────────────────────────────────────
KIBANA_URL = "http://192.168.10.20:5601"
USERNAME   = "elastic"
PASSWORD   = "tg8oCneGV2pgtFWxHbOD"
AUTH       = HTTPBasicAuth(USERNAME, PASSWORD)
HEADERS    = {"Content-Type": "application/json", "kbn-xsrf": "true"}
INDEX      = "wazuh-alerts-*"

ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")

# ─── Cores ─────────────────────────────────────────────────────────────────────
R="\033[0;31m"; G="\033[0;32m"; Y="\033[1;33m"; B="\033[0;34m"; C="\033[0;36m"; NC="\033[0m"
def ok(m):   print(f"  {G}✅ {m}{NC}")
def fail(m): print(f"  {R}❌ {m}{NC}")
def info(m): print(f"  {B}→  {m}{NC}")
def warn(m): print(f"  {Y}⚠️  {m}{NC}")
def head(m): print(f"\n{C}{m}{NC}")

# ─── Base de conhecimento TTP ──────────────────────────────────────────────────
# Adiciona novos APTs aqui seguindo o mesmo padrão
TTP_DB = {
    "APT29": {
        "name": "APT29 — Cozy Bear",
        "ttps": {
            "T1059.001": {
                "name": "PowerShell Execution",
                "tactic": "Execution",
                "description": "APT29 usa PowerShell para execução de payloads e comandos de reconhecimento.",
                "severity": "high",
                "query": "data.win.eventdata.commandLine:*powershell* OR data.win.eventdata.image:*powershell.exe*",
                "mitre_url": "https://attack.mitre.org/techniques/T1059/001/"
            },
            "T1027": {
                "name": "Obfuscation -ep bypass",
                "tactic": "Defense Evasion",
                "description": "APT29 usa -EncodedCommand e -ExecutionPolicy Bypass para evadir defesas.",
                "severity": "high",
                "query": "data.win.eventdata.commandLine:*bypass* OR data.win.eventdata.commandLine:*encodedcommand* OR data.win.eventdata.commandLine:*-enc*",
                "mitre_url": "https://attack.mitre.org/techniques/T1027/"
            },
            "T1218.011": {
                "name": "Rundll32 Execution",
                "tactic": "Defense Evasion",
                "description": "APT29 usa rundll32.exe para executar DLLs maliciosas e evadir detecção.",
                "severity": "high",
                "query": "data.win.eventdata.image:*rundll32* OR data.win.eventdata.commandLine:*rundll32*",
                "mitre_url": "https://attack.mitre.org/techniques/T1218/011/"
            },
            "T1087": {
                "name": "Account Discovery",
                "tactic": "Discovery",
                "description": "APT29 enumera contas locais e de domínio com net user e net group.",
                "severity": "medium",
                "query": "data.win.eventdata.commandLine:*net user* OR data.win.eventdata.commandLine:*net1 user*",
                "mitre_url": "https://attack.mitre.org/techniques/T1087/"
            },
            "T1069": {
                "name": "Permission Groups Discovery",
                "tactic": "Discovery",
                "description": "APT29 enumera grupos de domínio para identificar alvos privilegiados.",
                "severity": "medium",
                "query": "data.win.eventdata.commandLine:*net group* OR data.win.eventdata.commandLine:*net1 group*",
                "mitre_url": "https://attack.mitre.org/techniques/T1069/"
            },
            "T1082": {
                "name": "System Information Discovery",
                "tactic": "Discovery",
                "description": "APT29 executa systeminfo para recolher informação do sistema comprometido.",
                "severity": "medium",
                "query": "data.win.eventdata.commandLine:*systeminfo* OR data.win.eventdata.image:*systeminfo*",
                "mitre_url": "https://attack.mitre.org/techniques/T1082/"
            },
            "T1057": {
                "name": "Process Discovery",
                "tactic": "Discovery",
                "description": "APT29 usa tasklist para enumerar processos em execução.",
                "severity": "medium",
                "query": "data.win.eventdata.commandLine:*tasklist* OR data.win.eventdata.image:*tasklist*",
                "mitre_url": "https://attack.mitre.org/techniques/T1057/"
            },
            "T1560": {
                "name": "Archive Collected Data",
                "tactic": "Collection",
                "description": "APT29 usa 7-Zip para comprimir dados antes de exfiltração.",
                "severity": "high",
                "query": "data.win.eventdata.commandLine:*7z* OR data.win.eventdata.image:*7z.exe* OR data.win.eventdata.commandLine:*7za*",
                "mitre_url": "https://attack.mitre.org/techniques/T1560/"
            },
            "T1012": {
                "name": "Registry Query",
                "tactic": "Discovery",
                "description": "APT29 consulta o registo para recolher configurações e credenciais.",
                "severity": "medium",
                "query": "data.win.eventdata.commandLine:*reg query* OR data.win.eventdata.image:*reg.exe*",
                "mitre_url": "https://attack.mitre.org/techniques/T1012/"
            },
            "T1547.009": {
                "name": "Startup Persistence",
                "tactic": "Persistence",
                "description": "APT29 usa a pasta Startup para persistência entre reboots.",
                "severity": "high",
                "query": "data.win.eventdata.targetFilename:*Startup* OR data.win.eventdata.commandLine:*Startup*",
                "mitre_url": "https://attack.mitre.org/techniques/T1547/009/"
            },
            "T1566.002": {
                "name": "Spearphishing Download",
                "tactic": "Initial Access",
                "description": "APT29 usa links maliciosos para induzir download de payloads via browser.",
                "severity": "high",
                "query": "data.win.eventdata.commandLine:*msedge* OR data.win.eventdata.image:*msedge* OR data.win.eventdata.commandLine:*edge*",
                "mitre_url": "https://attack.mitre.org/techniques/T1566/002/"
            },
            "T1105": {
                "name": "Ingress Tool Transfer",
                "tactic": "Command and Control",
                "description": "APT29 usa Invoke-WebRequest para transferir ferramentas adicionais.",
                "severity": "high",
                "query": "data.win.eventdata.commandLine:*Invoke-WebRequest* OR data.win.eventdata.commandLine:*wget* OR data.win.eventdata.commandLine:*curl*",
                "mitre_url": "https://attack.mitre.org/techniques/T1105/"
            }
        }
    }
    # Para adicionar APT28:
    # "APT28": {
    #     "name": "APT28 — Fancy Bear",
    #     "ttps": { ... }
    # }
}

# ─── Tactic ID map ─────────────────────────────────────────────────────────────
TACTIC_IDS = {
    "Initial Access": "0001",
    "Execution": "0002",
    "Persistence": "0003",
    "Privilege Escalation": "0004",
    "Defense Evasion": "0005",
    "Credential Access": "0006",
    "Discovery": "0007",
    "Lateral Movement": "0008",
    "Collection": "0009",
    "Exfiltration": "0010",
    "Command and Control": "0011",
    "Impact": "0040"
}

# ─── Claude API ────────────────────────────────────────────────────────────────
def claude_generate_query(ttp_id, ttp_data):
    """Usa Claude API para gerar KQL query dinâmica."""
    if not ANTHROPIC_API_KEY:
        return None

    info(f"Claude API → a gerar query para {ttp_id}...")

    prompt = f"""És um engenheiro de detecção SOC especialista em Elastic SIEM e MITRE ATT&CK.

TTP: {ttp_id} — {ttp_data['name']}
Táctica: {ttp_data['tactic']}
Descrição: {ttp_data['description']}
Índice: wazuh-alerts-*

Campos disponíveis:
- data.win.eventdata.commandLine  (linha de comando)
- data.win.eventdata.image        (path do executável)
- data.win.eventdata.targetFilename (ficheiro criado)
- data.win.system.eventID         (Windows Event ID)
- data.win.eventdata.user         (utilizador)

Gera UMA KQL query para detectar este TTP.
Responde APENAS com a query KQL, sem explicação, sem markdown."""

    try:
        response = requests.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "Content-Type": "application/json",
                "x-api-key": ANTHROPIC_API_KEY,
                "anthropic-version": "2023-06-01"
            },
            json={
                "model": "claude-sonnet-4-20250514",
                "max_tokens": 300,
                "messages": [{"role": "user", "content": prompt}]
            },
            timeout=30
        )
        if response.status_code == 200:
            query = response.json()["content"][0]["text"].strip()
            ok(f"Claude gerou: {query[:80]}...")
            return query
        else:
            warn(f"Claude API {response.status_code} — fallback local")
            return None
    except Exception as e:
        warn(f"Claude API erro ({e}) — fallback local")
        return None

# ─── Kibana API ────────────────────────────────────────────────────────────────
def create_rule(apt_name, ttp_id, ttp_data, query):
    """Cria Detection Rule no Elastic SIEM."""
    rule_id = f"{apt_name.lower()}-{ttp_id.lower().replace('.', '-')}"
    tactic_id = TACTIC_IDS.get(ttp_data['tactic'], "0000")

    payload = {
        "type": "query",
        "language": "kuery",
        "query": query,
        "index": [INDEX],
        "name": f"[{apt_name}] {ttp_data['name']} - {ttp_id}",
        "description": ttp_data['description'],
        "severity": ttp_data['severity'],
        "risk_score": 73 if ttp_data['severity'] == "high" else 47,
        "enabled": True,
        "rule_id": rule_id,
        "tags": [apt_name, ttp_id, ttp_data['tactic'], "MITRE ATT&CK"],
        "threat": [{
            "framework": "MITRE ATT&CK",
            "tactic": {
                "id": f"TA{tactic_id}",
                "name": ttp_data['tactic'],
                "reference": f"https://attack.mitre.org/tactics/TA{tactic_id}/"
            },
            "technique": [{
                "id": ttp_id.split(".")[0],
                "name": ttp_data['name'],
                "reference": ttp_data['mitre_url']
            }]
        }],
        "interval": "5m",
        "from": "now-6m",
        "max_signals": 100
    }

    r = requests.post(
        f"{KIBANA_URL}/api/detection_engine/rules",
        auth=AUTH, headers=HEADERS, json=payload, verify=False, timeout=30
    )

    if r.status_code in (200, 201):
        mode = "Claude API" if ANTHROPIC_API_KEY else "Local"
        ok(f"[{mode}] {ttp_id} — {ttp_data['name']}")
        return True
    elif r.status_code == 409:
        warn(f"{ttp_id} já existe — a actualizar...")
        payload["rule_id"] = rule_id
        r2 = requests.put(
            f"{KIBANA_URL}/api/detection_engine/rules",
            auth=AUTH, headers=HEADERS, json=payload, verify=False, timeout=30
        )
        if r2.status_code == 200:
            ok(f"Actualizado: {ttp_id}")
            return True
    fail(f"{ttp_id} → HTTP {r.status_code}: {r.text[:150]}")
    return False

def delete_rules(apt_name, ttp_ids):
    """Apaga todas as regras de um APT."""
    head(f"🗑  A apagar regras {apt_name}...")
    for ttp_id in ttp_ids:
        rule_id = f"{apt_name.lower()}-{ttp_id.lower().replace('.', '-')}"
        r = requests.delete(
            f"{KIBANA_URL}/api/detection_engine/rules?rule_id={rule_id}",
            auth=AUTH, headers=HEADERS, verify=False, timeout=30
        )
        status = "🗑  Apagado" if r.status_code == 200 else f"⚠️  {r.status_code}"
        print(f"  {status}: {rule_id}")

# ─── Main ──────────────────────────────────────────────────────────────────────
def main():
    import urllib3
    urllib3.disable_warnings()

    parser = argparse.ArgumentParser(
        description="LLM Pipeline — TTP ID → Elastic Detection Rule",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemplos:
  python3 ttp-to-rule.py                        # APT29 completo
  python3 ttp-to-rule.py --ttp T1059.001        # TTP específico
  python3 ttp-to-rule.py --apt APT29 --list     # listar TTPs
  python3 ttp-to-rule.py --delete               # apagar regras
  ANTHROPIC_API_KEY=sk-ant-... python3 ttp-to-rule.py  # com Claude API
        """
    )
    parser.add_argument("--ttp",    help="TTP ID específico (ex: T1059.001)")
    parser.add_argument("--apt",    default="APT29", help="APT group (default: APT29)")
    parser.add_argument("--list",   action="store_true", help="Lista TTPs disponíveis")
    parser.add_argument("--delete", action="store_true", help="Apaga regras criadas")
    args = parser.parse_args()

    # Banner
    mode_str = f"{C}Claude API ✨{NC}" if ANTHROPIC_API_KEY else f"{Y}Local (sem API key){NC}"
    print(f"\n{B}{'='*58}{NC}")
    print(f"{B}  LLM Pipeline — TTP → Detection Rule{NC}")
    print(f"  APT: {Y}{args.apt}{NC} | Modo: {mode_str}")
    print(f"  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{B}{'='*58}{NC}\n")

    if not ANTHROPIC_API_KEY:
        warn("ANTHROPIC_API_KEY não definida — modo local activo")
        print(f"  Para activar Claude API:")
        print(f"  {Y}export ANTHROPIC_API_KEY=sk-ant-...{NC}\n")

    # Verificar APT
    apt_data = TTP_DB.get(args.apt)
    if not apt_data:
        fail(f"APT '{args.apt}' não encontrado.")
        print(f"  Disponíveis: {list(TTP_DB.keys())}")
        sys.exit(1)

    ttps = apt_data["ttps"]

    # --list
    if args.list:
        head(f"📋 TTPs — {apt_data['name']} ({len(ttps)} técnicas)")
        for ttp_id, data in ttps.items():
            sev_color = R if data['severity'] == 'high' else Y
            print(f"  {C}{ttp_id:<12}{NC} {data['name']:<35} {sev_color}[{data['severity']}]{NC} {data['tactic']}")
        print()
        return

    # --delete
    if args.delete:
        delete_rules(args.apt, ttps.keys())
        return

    # Verificar Kibana
    info("A verificar ligação ao Kibana...")
    try:
        r = requests.get(f"{KIBANA_URL}/api/status", auth=AUTH, verify=False, timeout=10)
        if r.status_code != 200:
            fail(f"Kibana não acessível: {r.status_code}"); sys.exit(1)
        ok("Kibana acessível")
    except Exception as e:
        fail(f"Erro de ligação: {e}"); sys.exit(1)

    # Seleccionar TTPs
    if args.ttp:
        if args.ttp not in ttps:
            fail(f"TTP '{args.ttp}' não encontrado. Usa --list para ver disponíveis.")
            sys.exit(1)
        selected = {args.ttp: ttps[args.ttp]}
    else:
        selected = ttps

    # Processar
    head(f"🚀 A processar {len(selected)} TTPs — {apt_data['name']}")
    results = {"ok": 0, "fail": 0, "claude": 0, "local": 0}

    for ttp_id, ttp_data in selected.items():
        sev_color = R if ttp_data['severity'] == 'high' else Y
        print(f"\n  {C}[{ttp_id}]{NC} {ttp_data['name']} — {sev_color}{ttp_data['tactic']}{NC}")

        # Claude API → fallback local
        query = claude_generate_query(ttp_id, ttp_data)
        if query:
            results["claude"] += 1
        else:
            query = ttp_data["query"]
            info(f"Query local: {query[:80]}")
            results["local"] += 1

        if create_rule(args.apt, ttp_id, ttp_data, query):
            results["ok"] += 1
        else:
            results["fail"] += 1

    # Relatório final
    print(f"\n{B}{'='*58}{NC}")
    print(f"  {G}✅ Criadas:     {results['ok']}/{len(selected)}{NC}")
    if results["claude"]: print(f"  {C}✨ Claude API:  {results['claude']}{NC}")
    if results["local"]:  print(f"  {Y}📦 Local:       {results['local']}{NC}")
    if results["fail"]:   print(f"  {R}❌ Falhas:      {results['fail']}{NC}")
    print(f"\n  🔗 {KIBANA_URL}/app/security/rules")
    print(f"{B}{'='*58}{NC}\n")

if __name__ == "__main__":
    main()
