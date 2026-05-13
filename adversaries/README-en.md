# Adversaries

This directory contains the emulation of real APT groups tested in a controlled lab environment. Each adversary is documented with a profile, attack timeline, emulation scripts, detection rules and defense strategies.

The goal is to cover as many MITRE ATT&CK TTPs as possible per group, execute each technique in an isolated environment, detect with a functional SIEM and document how to defend.

---

## Documented Adversaries

| APT | Name | Origin | TTPs Emulated | Status |
|---|---|---|---|---|
| [APT29](APT29-Cozy-Bear/) | Cozy Bear | Russia (SVR) | 12 | ✅ Complete |
| APT28 | Fancy Bear | Russia (GRU) | coming soon | 🔜 |
| Lazarus Group | Hidden Cobra | North Korea | coming soon | 🔜 |

---

## How each adversary is documented

Each folder follows the same structure to maintain consistency and make community contribution easier.

```
APT-Name/
├── 01-profile/          ← Who they are, history, real campaigns
├── 02-attack-phases/    ← Attack timeline with TTPs and evidence
├── 03-emulation/        ← Scripts tested in the lab
├── 04-detection/        ← SIEM rules, dashboard and Sigma rules
└── 05-defense/          ← MITRE mitigations and CIS Controls
```

To add a new adversary check [CONTRIBUTING.md](../CONTRIBUTING.md).

---

Reference: [MITRE ATT&CK Groups](https://attack.mitre.org/groups/)
