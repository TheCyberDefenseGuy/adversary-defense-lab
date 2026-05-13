# Adversários

Este directório contém a emulação de grupos APT reais testados em laboratório controlado. Cada adversário é documentado com perfil, timeline de ataque, scripts de emulação, regras de detecção e estratégias de defesa.

O objectivo é cobrir o maior número possível de TTPs do MITRE ATT&CK por grupo, executar cada técnica em ambiente isolado, detectar com um SIEM funcional e documentar como defender.

---

## Adversários Documentados

| APT | Nome | Origem | TTPs Emulados | Status |
|---|---|---|---|---|
| [APT29](APT29-Cozy-Bear/) | Cozy Bear | Rússia (SVR) | 12 | ✅ Completo |
| APT28 | Fancy Bear | Rússia (GRU) | em breve | 🔜 |
| Lazarus Group | Hidden Cobra | Coreia do Norte | em breve | 🔜 |

---

## Como cada adversário é documentado

Cada pasta segue a mesma estrutura para manter consistência e facilitar a contribuição da comunidade.

```
APT-Name/
├── 01-profile/          ← Quem são, histórico, campanhas reais
├── 02-attack-phases/    ← Timeline do ataque com TTPs e evidências
├── 03-emulation/        ← Scripts testados em laboratório
├── 04-detection/        ← Regras SIEM, dashboard e Sigma rules
└── 05-defense/          ← Mitigações MITRE e CIS Controls
```

Para adicionar um novo adversário consulta o [CONTRIBUTING.md](../CONTRIBUTING.md).

---

Referência: [MITRE ATT&CK Groups](https://attack.mitre.org/groups/)
