# APT29 Defense — Strategy and Mitigations

This directory documents the defense strategies against the APT29 techniques emulated in this lab. Each mitigation is based on official MITRE ATT&CK recommendations and CIS Benchmark controls, with direct references for implementation in real environments.

The goal is not just to detect — it is to hinder, delay and block the attack at each phase.

---

## Structure

```
05-defense/
├── README.md                ← PT-BR
├── README-en.md             ← This file EN
├── mitre-mitigations.md     ← Mitigations per TTP with MITRE links
└── cis-hardening.md         ← Applicable CIS Controls per phase
```

---

## Defense Philosophy

Defense against APT29 is not a single control problem. The group is sophisticated, patient and adapts its techniques quickly after exposure. The correct approach is **defense in depth** — applying multiple layers of controls so that even if one fails the others continue to protect.

```
Attack Phase         Primary Control
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

## Documents in this section

**mitre-mitigations.md** — For each TTP emulated in this lab documents the MITRE-recommended mitigation with the mitigation ID, description and direct link to the official page.

**cis-hardening.md** — For each attack phase maps the relevant CIS Benchmark controls with reference to CIS Controls v8 and CIS Benchmark Windows Server 2022, with verification and implementation commands.

---

## References

- [MITRE ATT&CK — APT29 Mitigations](https://attack.mitre.org/groups/G0016/)
- [CIS Controls v8](https://www.cisecurity.org/controls/v8)
- [CIS Benchmark Windows Server 2022](https://www.cisecurity.org/benchmark/microsoft_windows_server)
- [Microsoft Security Baselines](https://learn.microsoft.com/en-us/windows/security/operating-system-security/device-management/windows-security-configuration-framework/windows-security-baselines)
