# LLM Pipeline — TTP to Detection Rule

Este directório contém o pipeline híbrido que converte TTP IDs em regras de detecção no Elastic SIEM. Funciona em dois modos: sem API key usa queries locais pré-definidas testadas em laboratório, com API key da Anthropic o Claude gera queries KQL dinâmicas baseadas no contexto do TTP.

O pipeline foi desenhado para escalar para múltiplos APTs. Adicionar um novo adversário é apenas adicionar um bloco ao ficheiro `ttp-to-rule.py`.

---

## Estrutura

```
tools/llm-pipeline/
├── README.md          ← Este ficheiro PT-BR
├── README-en.md       ← EN
└── ttp-to-rule.py     ← Pipeline híbrido Local + Claude API
```

---

## Modos de funcionamento

### Modo Local (sem API key)

Funciona sem qualquer configuração adicional. As queries estão pré-definidas no ficheiro com base nas detecções reais testadas no laboratório.

```bash
python3 ttp-to-rule.py --list
python3 ttp-to-rule.py --apt APT29
python3 ttp-to-rule.py --ttp T1059.001
```

### Modo Claude API (com API key)

Com a API key configurada o Claude gera queries KQL dinâmicas baseadas no contexto do TTP no MITRE ATT&CK. Se a API falhar o script usa automaticamente a query local como fallback.

```bash
export ANTHROPIC_API_KEY=sk-ant-...
python3 ttp-to-rule.py --apt APT29
```

A API key da Anthropic está disponível em [console.anthropic.com](https://console.anthropic.com). O consumo para 12 TTPs é de aproximadamente 14.000 tokens por execução, o que representa menos de $0.05 com o modelo Sonnet.

---

## Instalação

```bash
pip3 install requests urllib3
```

---

## Uso completo

```bash
# Listar TTPs disponíveis para um APT
python3 ttp-to-rule.py --list
python3 ttp-to-rule.py --apt APT29 --list

# Criar regras para todos os TTPs de um APT
python3 ttp-to-rule.py --apt APT29

# Criar regra para um TTP específico
python3 ttp-to-rule.py --ttp T1059.001

# Apagar regras criadas
python3 ttp-to-rule.py --delete

# Com Claude API
export ANTHROPIC_API_KEY=sk-ant-...
python3 ttp-to-rule.py --apt APT29
```

---

## Output esperado

```
==========================================================
  LLM Pipeline — TTP → Detection Rule
  APT: APT29 | Modo: Local (sem API key)
  2026-05-13 12:02:55
==========================================================

  →  A verificar ligação ao Kibana...
  ✅ Kibana acessível

🚀 A processar 12 TTPs — APT29 — Cozy Bear

  [T1059.001] PowerShell Execution — Execution
  →  Query local: data.win.eventdata.commandLine:*powershell*
  ✅ [Local] T1059.001 — PowerShell Execution
  ...

==========================================================
  ✅ Criadas:     12/12
  📦 Local:       12
  🔗 http://192.168.10.20:5601/app/security/rules
==========================================================
```

---

## Como adicionar um novo APT

Abre o ficheiro `ttp-to-rule.py` e adiciona um novo bloco no dicionário `TTP_DB` seguindo o mesmo padrão do APT29:

```python
TTP_DB = {
    "APT29": {
        "name": "APT29 — Cozy Bear",
        "ttps": { ... }  # TTPs existentes
    },
    "APT28": {               # Novo APT
        "name": "APT28 — Fancy Bear",
        "ttps": {
            "T1059.001": {
                "name": "PowerShell Execution",
                "tactic": "Execution",
                "description": "APT28 usa PowerShell...",
                "severity": "high",
                "query": "data.win.eventdata.commandLine:*powershell*",
                "mitre_url": "https://attack.mitre.org/techniques/T1059/001/"
            }
        }
    }
}
```

Depois executa:

```bash
python3 ttp-to-rule.py --apt APT28 --list
python3 ttp-to-rule.py --apt APT28
```

---

## Referências

- [Anthropic API Documentation](https://docs.anthropic.com/)
- [Elastic Detection Engine API](https://www.elastic.co/guide/en/security/current/rule-api-overview.html)
- [MITRE ATT&CK — APT29](https://attack.mitre.org/groups/G0016/)
