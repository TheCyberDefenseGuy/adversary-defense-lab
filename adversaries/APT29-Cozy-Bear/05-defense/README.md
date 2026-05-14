# Defesa APT29 — Estratégia e Mitigações

Este directório documenta as estratégias de defesa contra as técnicas do APT29 emuladas neste laboratório. Cada mitigação é baseada nas recomendações oficiais do MITRE ATT&CK e nos controlos do CIS Benchmark, com referências directas para implementação em ambiente real.

O objectivo não é apenas detectar — é dificultar, atrasar e bloquear o ataque em cada fase.

---

## Estrutura

```
05-defense/
├── README.md                ← Este ficheiro PT-BR
├── README-en.md             ← EN
├── mitre-mitigations.md     ← Mitigações por TTP com links MITRE
└── cis-hardening.md         ← CIS Controls aplicáveis por fase
```

---

## Filosofia de Defesa

A defesa contra o APT29 não é um problema de um único controlo. O grupo é sofisticado, paciente e adapta as suas técnicas rapidamente após exposição. A abordagem correcta é **defesa em profundidade** — aplicar múltiplas camadas de controlos para que mesmo que uma falhe as outras continuem a proteger.

```
Fase do Ataque       Controlo Principal
─────────────────    ──────────────────────────────────────
Initial Access    →  Email filtering + User awareness
Execution         →  PowerShell CLM + AppLocker
Defense Evasion   →  Script Block Logging + AMSI
Discovery         →  Process auditing + Least privilege
Collection        →  DLP + File monitoring
Persistence       →  Startup folder restrictions
C2                →  Egress filtering + DNS monitoring
```

---

## Documentos desta secção

**mitre-mitigations.md** — Para cada TTP emulado neste lab documenta a mitigação recomendada pelo MITRE com o ID da mitigação, a descrição e o link directo para a página oficial.

**cis-hardening.md** — Para cada fase do ataque mapeia os controlos CIS Benchmark relevantes com referência ao CIS Controls v8 e ao CIS Benchmark Windows Server 2022, com os comandos de verificação e implementação.

---

## Referências

- [MITRE ATT&CK — APT29 Mitigations](https://attack.mitre.org/groups/G0016/)
- [CIS Controls v8](https://www.cisecurity.org/controls/v8)
- [CIS Benchmark Windows Server 2022](https://www.cisecurity.org/benchmark/microsoft_windows_server)
- [Microsoft Security Baselines](https://learn.microsoft.com/en-us/windows/security/operating-system-security/device-management/windows-security-configuration-framework/windows-security-baselines)
