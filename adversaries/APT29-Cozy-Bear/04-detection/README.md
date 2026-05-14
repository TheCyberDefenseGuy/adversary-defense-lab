# Detecção APT29 — Elastic SIEM

Este directório contém todos os scripts de detecção desenvolvidos e testados neste laboratório para detectar as técnicas do APT29. A abordagem cobre três camadas: detecção via API REST directamente no Elasticsearch, criação automática de regras no Elastic SIEM via Kibana API, e deployment de um dashboard completo via CLI.

---

## Estrutura

```
04-detection/
├── README.md                      ← Este ficheiro PT-BR
├── README-en.md                   ← EN
├── elastic/
│   ├── apt29-detect-v4.py         ← Detection script 100% coverage via API REST
│   ├── apt29-create-rules.py      ← Cria 12 regras no Elastic SIEM via Kibana API
│   └── apt29-dashboard-deploy.sh  ← Deploy do dashboard completo via CLI
└── sigma/
    └── apt29-rules.yml            ← Sigma rules para portabilidade
```

---

## Pré-requisitos

```bash
pip3 install requests urllib3
```

Confirma que o Elastic Stack está acessível:

```bash
curl -sk -u elastic:tg8oCneGV2pgtFWxHbOD \
  https://192.168.10.20:9200/_cluster/health?pretty
```

Resultado esperado:
```json
{
  "cluster_name": "elasticsearch",
  "status": "yellow",
  "number_of_nodes": 1
}
```

---

## Script 1 — apt29-detect-v4.py

### O que faz

Pesquisa directamente no índice `wazuh-alerts-*` do Elasticsearch via API REST e verifica se cada TTP APT29 foi detectado. Gera um relatório JSON com timestamps, contagem de eventos e sample dos comandos capturados.

### Como executar

```bash
cd ~/AdversaryEmulation/
python3 apt29-detect-v4.py
```

### Output esperado

```
=================================================================
  APT29 DETECTION REPORT v4 — 2026-05-13 10:46:24
=================================================================

  [T1059.001] PowerShell Execution
  [OK] DETECTED (25 eventos)
  First : 2026-05-13T11:12:44.537Z
  Last  : 2026-05-13T11:12:44.538Z
  Sample: powershell.exe -ep bypass -w hidden -e SQBF...

  [T1027] Obfuscation -ep bypass
  [OK] DETECTED (4 eventos)
  First : 2026-05-13T11:12:44.536Z
  Last  : 2026-05-13T11:12:44.537Z
  Sample: powershell.exe -ep bypass -w hidden -e SQBF...

  [T1218.011] Rundll32 Execution
  [OK] DETECTED (8 eventos)
  ...

=================================================================
  COVERAGE: 12/12 TTPs (100%)
=================================================================
  [+] Relatorio: detection_report_v4_20260513_104624.json
```

### Como funciona internamente

O script usa dois tipos de query dependendo do TTP:

**wildcard** — para TTPs onde o valor pode aparecer em qualquer posição da string:
```python
{"wildcard": {"data.win.eventdata.commandLine": "*powershell*"}}
```

**match_phrase** — para TTPs onde o valor é uma string exacta:
```python
{"match_phrase": {"data.win.eventdata.commandLine": "bypass"}}
```

Todos os TTPs filtram por `agent.name: WIN-DC01` para garantir que os eventos são do endpoint correcto.

### TTPs e queries

| TTP | Técnica | Tipo | Campo | Valor |
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

### Relatório JSON gerado

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

### O que faz

Cria automaticamente 12 regras de detecção no Elastic SIEM via Kibana Detection Engine API. Cada regra inclui o mapeamento MITRE ATT&CK completo com táctica, técnica e referência, severity, risk score e tags.

### Como executar

```bash
cd ~/AdversaryEmulation/
python3 apt29-create-rules.py
```

### Output esperado

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
  Regras criadas: 12/12
  Acede ao Kibana: http://192.168.10.20:5601/app/security/rules
=================================================================
```

### Regras criadas no Kibana

| Regra | Severity | Risk Score | Táctica MITRE |
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

Para verificar as regras no Kibana:
```
http://192.168.10.20:5601
Security -> Rules -> Detection Rules (SIEM)
Filtrar por tag: APT29
```

Se uma regra já existir o script retorna `[--] já existe` sem falhar e continua para a próxima.

Para recriar as regras do zero apaga-as primeiro no Kibana e executa novamente o script.

---

## Script 3 — apt29-dashboard-deploy.sh

### O que faz

Cria um dashboard completo no Kibana com 5 visualizações via Saved Objects API. Todo o processo é feito via CLI sem necessidade de interagir com a interface gráfica do Kibana.

### Como executar

```bash
cd ~/AdversaryEmulation/
chmod +x apt29-dashboard-deploy.sh
./apt29-dashboard-deploy.sh
```

### Output esperado

```
======================================================
  APT29 Dashboard Deploy — 2026-05-13 11:36
======================================================
  →  A verificar ligação ao Kibana...
  ✅ Kibana acessível
🔧 Data View para alertas SIEM...
  ✅ Data View: APT29 Security Alerts
📊 VIZ 1/5 — Gauge: TTPs Detectados
  ✅ lens/apt29-viz-gauge
📊 VIZ 2/5 — Bar: Alertas por TTP
  ✅ lens/apt29-viz-bar
📊 VIZ 3/5 — Timeline: Alertas ao longo do tempo
  ✅ lens/apt29-viz-timeline
📊 VIZ 4/5 — Treemap: MITRE Heatmap
  ✅ lens/apt29-viz-treemap
📊 VIZ 5/5 — Tabela: Últimos Alertas
  ✅ lens/apt29-viz-table
📋 Dashboard principal...
  ✅ dashboard/apt29-main-dashboard
======================================================
  ✅ Dashboard APT29 criado com sucesso!
  🔗 http://192.168.10.20:5601/app/dashboards
======================================================
```

### Visualizações criadas

| Visualização | Tipo | Conteúdo |
|---|---|---|
| TTPs Detectados | Metric | Unique count de regras com alertas |
| Alertas por TTP | Bar horizontal | Top 12 TTPs por volume de alertas |
| Timeline de Alertas | Area chart | Alertas ao longo do tempo por severity |
| MITRE Heatmap | Treemap | Proporção visual por TTP |
| Últimos Alertas | Datatable | Regra + severity + total ordenado por count |

Para recriar o dashboard do zero:

```bash
./apt29-dashboard-deploy.sh --delete
./apt29-dashboard-deploy.sh
```

Para aceder ao dashboard:
```
http://192.168.10.20:5601
Dashboards -> APT29 Emulation — SOC Dashboard
Time range: Last 7 days
```

---

## Ordem recomendada de execução

A ordem correcta é sempre criar as regras antes de executar o ataque para que o SIEM esteja a monitorizar quando os eventos chegarem.

```bash
# 1. Criar as regras de detecção
python3 apt29-create-rules.py

# 2. Deploy do dashboard
./apt29-dashboard-deploy.sh

# 3. Executar a emulação (ver 03-emulation)
# ...

# 4. Verificar detecção após o ataque
python3 apt29-detect-v4.py

# 5. Verificar alertas no Kibana
# http://192.168.10.20:5601 -> Security -> Alerts
```

---

## Resultados obtidos neste lab

Após a execução completa da emulação APT29 os resultados foram:

```
Coverage:   12/12 TTPs — 100%
Alertas:    188 alertas gerados
Severity:   169 High + 19 Medium
Regras:     12/12 com status Succeeded
```

---

## Referências

- [Elastic Detection Engine API](https://www.elastic.co/guide/en/security/current/rule-api-overview.html)
- [Kibana Saved Objects API](https://www.elastic.co/guide/en/kibana/current/saved-objects-api.html)
- [MITRE ATT&CK — APT29](https://attack.mitre.org/groups/G0016/)
- [Wazuh Elasticsearch Index](https://documentation.wazuh.com/current/user-manual/elasticsearch/indices.html)
