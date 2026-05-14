#!/usr/bin/env python3
"""
apt29-detect-v4.py — APT29 Detection Script v4
Adversary Defense Lab — APT29 Cozy Bear Detection

Pesquisa directamente no índice wazuh-alerts-* do Elasticsearch
via API REST e verifica se cada TTP APT29 foi detectado.
Gera um relatório JSON com timestamps, contagem de eventos
e sample dos comandos capturados.

Coverage: 12/12 TTPs — 100%

Uso:
    python3 apt29-detect-v4.py

Pré-requisitos:
    pip3 install requests urllib3

Resultado:
    detection_report_v4_YYYYMMDD_HHMMSS.json
"""
import requests, json, urllib3
from datetime import datetime
urllib3.disable_warnings()

# ─── Configuração ──────────────────────────────────────────────────────────────
# Actualiza com o IP e credenciais do teu ambiente
ELASTIC = {
    "url": "https://192.168.10.20:9200",
    "user": "elastic",
    "pass": "tg8oCneGV2pgtFWxHbOD",
    "index": "wazuh-alerts-*"
}

# ─── TTPs APT29 mapeados ────────────────────────────────────────────────────────
# Cada entrada define o TTP, a técnica, o tipo de query e o valor a pesquisar
# tipo wildcard: valor pode aparecer em qualquer posição (*value*)
# tipo match_phrase: correspondência exacta da string
DETECTIONS = [
    {"ttp": "T1059.001", "technique": "PowerShell Execution",        "type": "wildcard",      "field": "data.win.eventdata.commandLine", "value": "*powershell*"},
    {"ttp": "T1027",     "technique": "Obfuscation -ep bypass",      "type": "match_phrase",  "field": "data.win.eventdata.commandLine", "value": "bypass"},
    {"ttp": "T1218.011", "technique": "Rundll32 Execution",          "type": "match_phrase",  "field": "data.win.eventdata.commandLine", "value": "rundll32"},
    {"ttp": "T1087",     "technique": "Account Discovery net user",  "type": "match_phrase",  "field": "data.win.eventdata.commandLine", "value": "net user"},
    {"ttp": "T1069",     "technique": "Permission Groups Discovery", "type": "match_phrase",  "field": "data.win.eventdata.commandLine", "value": "net1 user"},
    {"ttp": "T1082",     "technique": "System Info Discovery",       "type": "match_phrase",  "field": "data.win.eventdata.commandLine", "value": "systeminfo"},
    {"ttp": "T1057",     "technique": "Process Discovery tasklist",  "type": "match_phrase",  "field": "data.win.eventdata.commandLine", "value": "tasklist"},
    {"ttp": "T1560",     "technique": "Archive Collected Data 7zip", "type": "wildcard",      "field": "data.win.eventdata.commandLine", "value": "*7z*"},
    {"ttp": "T1012",     "technique": "Registry Query",              "type": "match_phrase",  "field": "data.win.eventdata.commandLine", "value": "reg query"},
    {"ttp": "T1547.009", "technique": "Startup Persistence",         "type": "match_phrase",  "field": "data.win.eventdata.commandLine", "value": "Startup"},
    {"ttp": "T1566.002", "technique": "Spearphishing Edge Download", "type": "match_phrase",  "field": "data.win.eventdata.commandLine", "value": "edge"},
    {"ttp": "T1105",     "technique": "Ingress Tool Transfer",       "type": "match_phrase",  "field": "data.win.eventdata.commandLine", "value": "Invoke-WebRequest"},
]

def search(det, minutes=360):
    """
    Pesquisa no Elasticsearch por eventos que correspondam ao TTP.
    Filtra por agent.name WIN-DC01 e janela temporal de 360 minutos.
    Retorna os últimos 3 eventos encontrados para o sample.
    """
    if det["type"] == "match_phrase":
        query_clause = {"match_phrase": {det["field"]: det["value"]}}
    else:
        query_clause = {"wildcard": {det["field"]: det["value"]}}

    q = {
        "query": {"bool": {
            "must": [
                {"match": {"agent.name": "WIN-DC01"}},
                query_clause
            ],
            "filter": [{"range": {"@timestamp": {"gte": f"now-{minutes}m"}}}]
        }},
        "sort": [{"@timestamp": {"order": "asc"}}],
        "size": 3
    }
    try:
        r = requests.post(
            f"{ELASTIC['url']}/{ELASTIC['index']}/_search",
            auth=(ELASTIC['user'], ELASTIC['pass']),
            json=q, verify=False, timeout=10)
        return r.json()
    except Exception as e:
        return {"error": str(e)}

def run():
    """
    Executa a detecção para todos os TTPs e gera o relatório.
    Imprime resultados no terminal e guarda JSON com timestamps.
    """
    print("=" * 65)
    print(f"  APT29 DETECTION REPORT v4 — {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 65)
    detected = 0
    results = []

    for det in DETECTIONS:
        r = search(det)
        hits = r.get("hits", {}).get("total", {}).get("value", 0) if "error" not in r else 0
        docs = r.get("hits", {}).get("hits", []) if "error" not in r else []
        first = docs[0]["_source"].get("@timestamp", "-") if docs else "-"
        last  = docs[-1]["_source"].get("@timestamp", "-") if docs else "-"
        cmd   = docs[0]["_source"].get("data",{}).get("win",{}).get("eventdata",{}).get("commandLine","-")[:60] if docs else "-"

        if hits > 0:
            detected += 1
            status = "OK"
        else:
            status = "XX"

        print(f"\n  [{det['ttp']}] {det['technique']}")
        print(f"  [{status}] {'DETECTED' if hits > 0 else 'MISSED'} ({hits} eventos)")
        if hits > 0:
            print(f"  First : {first}")
            print(f"  Last  : {last}")
            print(f"  Sample: {cmd}")

        results.append({
            "ttp": det["ttp"],
            "technique": det["technique"],
            "detected": hits > 0,
            "hits": hits,
            "first_seen": first
        })

    pct = detected / len(DETECTIONS) * 100
    print(f"\n{'=' * 65}")
    print(f"  COVERAGE: {detected}/{len(DETECTIONS)} TTPs ({pct:.0f}%)")
    print("=" * 65)

    # Guardar relatório JSON
    fname = f"detection_report_v4_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(fname, "w") as f:
        json.dump({
            "campaign": "APT29",
            "date": datetime.now().isoformat(),
            "coverage_pct": round(pct, 1),
            "detected": detected,
            "total": len(DETECTIONS),
            "results": results
        }, f, indent=2)
    print(f"  [+] Relatorio: {fname}")

run()
