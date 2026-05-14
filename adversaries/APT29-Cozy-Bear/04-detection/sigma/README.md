# Sigma Rules — APT29

As Sigma rules deste directório convertem as detecções APT29 do Elastic SIEM para um formato portável que pode ser usado em qualquer SIEM. As queries foram baseadas nas detecções reais testadas neste laboratório.

---

## O que são Sigma Rules

Sigma é um formato de regras de detecção genérico para SIEMs, semelhante ao que o Snort é para IDS. Uma regra Sigma pode ser convertida para Elastic, Splunk, Microsoft Sentinel, QRadar, Chronicle e outros usando ferramentas de conversão como o `sigma-cli` ou plataformas online como o Uncoder.io.

Repositório oficial: [https://github.com/SigmaHQ/sigma](https://github.com/SigmaHQ/sigma)

---

## Regras incluídas

| Ficheiro | TTPs | Descrição |
|---|---|---|
| apt29-sigma-rules.yml | 12 TTPs | Todas as regras APT29 num único ficheiro |

| Regra | TTP | Nível |
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

## Opção 1 — Conversão Online com Uncoder.io

O [Uncoder.io](https://uncoder.io/) é uma plataforma online gratuita que converte regras Sigma para qualquer SIEM sem instalar nada. É a forma mais rápida de adaptar as regras deste repositório para o teu ambiente.

### Como usar o Uncoder.io

**Passo 1** — Acede a [https://uncoder.io/](https://uncoder.io/)

**Passo 2** — No painel esquerdo selecciona o formato de entrada: `Sigma`

**Passo 3** — Cola o conteúdo do ficheiro `apt29-sigma-rules.yml`

**Passo 4** — No painel direito selecciona o SIEM de destino:

| SIEM | Formato de saída |
|---|---|
| Elastic SIEM | Kibana KQL / Lucene / EQL |
| Splunk | SPL (Splunk Processing Language) |
| Microsoft Sentinel | KQL (Kusto Query Language) |
| IBM QRadar | AQL (Ariel Query Language) |
| Google Chronicle | YARA-L |
| Sumo Logic | Sumo Logic Query |
| Azure Data Explorer | KQL |
| CrowdStrike | CQL |

**Passo 5** — Clica em **Translate** e copia a query gerada directamente para o teu SIEM.

### Exemplo de conversão

**Entrada (Sigma):**
```yaml
detection:
    selection:
        CommandLine|contains:
            - 'powershell'
    condition: selection
```

**Saída Splunk (SPL):**
```
CommandLine="*powershell*"
| stats count by CommandLine, Image, User
```

**Saída Sentinel (KQL):**
```kql
SecurityEvent
| where CommandLine contains "powershell"
| project TimeGenerated, CommandLine, Account, Computer
```

**Saída Elastic (Lucene):**
```
CommandLine:*powershell*
```

---

## Opção 2 — Conversão via CLI com sigma-cli

Para quem prefere automatizar a conversão ou integrar num pipeline CI/CD.

### Instalar o sigma-cli

```bash
pip3 install sigma-cli
sigma plugin install splunk
sigma plugin install sentinel
sigma plugin install qradar
sigma plugin install elasticsearch
```

### Converter para Splunk

```bash
sigma convert -t splunk apt29-sigma-rules.yml
```

### Converter para Microsoft Sentinel

```bash
sigma convert -t sentinel apt29-sigma-rules.yml
```

### Converter para QRadar

```bash
sigma convert -t qradar apt29-sigma-rules.yml
```

### Converter para Elastic Lucene

```bash
sigma convert -t lucene apt29-sigma-rules.yml
```

### Converter para Elastic EQL

```bash
sigma convert -t eql apt29-sigma-rules.yml
```

### Converter uma regra específica por tag

```bash
sigma convert -t splunk apt29-sigma-rules.yml --filter "tags=attack.t1059.001"
```

### Converter com output para ficheiro

```bash
sigma convert -t splunk apt29-sigma-rules.yml -o apt29-splunk-queries.txt
sigma convert -t sentinel apt29-sigma-rules.yml -o apt29-sentinel-queries.kql
```

### Validar as regras antes de converter

```bash
sigma check apt29-sigma-rules.yml
```

---

## Estrutura de uma regra Sigma

```yaml
title: APT29 PowerShell Execution          # Nome da regra
id: uuid-único                              # UUID único
status: test                               # test / stable / deprecated
description: Descrição detalhada           # O que detecta
references:                                # Links MITRE e fontes
    - https://attack.mitre.org/...
author: TheCyberDefenseGuy
date: 2026-05-13
tags:                                      # Mapeamento MITRE ATT&CK
    - attack.execution
    - attack.t1059.001
    - apt29
logsource:                                 # Fonte de logs
    category: process_creation
    product: windows
detection:                                 # Lógica de detecção
    selection:
        CommandLine|contains:
            - 'powershell'
    condition: selection
falsepositives:                            # Falsos positivos conhecidos
    - Legitimate administrative usage
level: high                                # informational/low/medium/high/critical
```

---

## Referências

- [Sigma HQ GitHub](https://github.com/SigmaHQ/sigma)
- [sigma-cli Documentation](https://github.com/SigmaHQ/sigma-cli)
- [Sigma Rule Specification](https://sigmahq.io/docs/specification.html)
- [Uncoder.io — Sigma Online Converter](https://uncoder.io/)
- [MITRE ATT&CK — APT29](https://attack.mitre.org/groups/G0016/)
