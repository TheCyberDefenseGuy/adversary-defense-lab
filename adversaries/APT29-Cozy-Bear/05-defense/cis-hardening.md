# CIS Controls — Hardening APT29

Este documento mapeia os controlos CIS relevantes para cada fase do ataque APT29 emulado neste laboratório. As referências são baseadas no CIS Controls v8.1 e no CIS Benchmark Windows Server 2022.

Os controlos estão organizados por fase do ataque para que seja fácil priorizar a implementação com base no risco mais imediato.

---

## Referências Base

- [CIS Controls v8.1 — Página oficial](https://www.cisecurity.org/controls/v8-1)
- [CIS Controls v8.1 — Download gratuito](https://learn.cisecurity.org/cis-controls-download)
- [CIS Controls — Lista dos 18 controlos](https://www.cisecurity.org/controls/cis-controls-list)
- [CIS Controls Navigator — Ferramenta online](https://www.cisecurity.org/controls/cis-controls-navigator)
- [CIS Benchmark Microsoft Windows Server 2022](https://www.cisecurity.org/benchmark/microsoft_windows_server)
- [CIS Benchmark Microsoft Windows 11](https://www.cisecurity.org/benchmark/microsoft_windows_desktop)
- [CIS Benchmarks — Todos os produtos](https://www.cisecurity.org/cis-benchmarks)

---

## Fase 1 — Initial Access

### CIS Control 9 — Email and Web Browser Protections

**Subcontrol 9.1** — Ensure only fully supported browsers and email clients are used.
Mantém o Microsoft Edge actualizado para garantir que as protecções SmartScreen e Safe Browsing estão activas com as últimas assinaturas.

**Subcontrol 9.3** — Maintain and enforce network-based URL filters.
Implementa um proxy de saída com categorização de URLs para bloquear acesso a domínios de phishing, domínios recém-registados e categorias de alto risco.

**Subcontrol 9.6** — Block unnecessary file types.
Configura o browser e o email gateway para bloquear ou quarentenar anexos e downloads de tipos perigosos: LNK, VBS, JS, HTA, EXE, SCR, BAT.

**Verificação:**
```powershell
# Confirmar que SmartScreen está activo
Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" | Select-Object EnableSmartScreen
```

---

## Fase 2 — Execution e Defense Evasion

### CIS Control 2 — Inventory and Control of Software Assets

**Subcontrol 2.5** — Allowlist authorized software.
Implementa AppLocker ou Windows Defender Application Control com uma lista de aplicações autorizadas. Scripts PowerShell não assinados devem ser bloqueados por defeito.

**Verificação:**
```powershell
# Ver política AppLocker activa
Get-AppLockerPolicy -Effective | Format-List
```

### CIS Control 10 — Malware Defenses

**Subcontrol 10.1** — Deploy and maintain anti-malware software.
Mantém o Windows Defender activo e actualizado. O AMSI intercede na execução de scripts PowerShell ofuscados mesmo antes da execução.

**Subcontrol 10.5** — Enable anti-exploitation features.
Activa o Windows Defender Exploit Guard em todos os endpoints com as seguintes protecções: Attack Surface Reduction rules, Network Protection e Controlled Folder Access.

**Verificação:**
```powershell
# Confirmar estado do Defender
Get-MpComputerStatus | Select-Object AMServiceEnabled, RealTimeProtectionEnabled, AMProductVersion

# Verificar ASR rules activas
Get-MpPreference | Select-Object AttackSurfaceReductionRules_Ids, AttackSurfaceReductionRules_Actions
```

**ASR Rules críticas para APT29:**
```powershell
# Bloquear execução de conteúdo executável de email e webmail
Set-MpPreference -AttackSurfaceReductionRules_Ids BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550 -AttackSurfaceReductionRules_Actions Enabled

# Bloquear criação de processos filho por Office
Set-MpPreference -AttackSurfaceReductionRules_Ids D4F940AB-401B-4EFC-AADC-AD5F3C50688A -AttackSurfaceReductionRules_Actions Enabled

# Bloquear scripts ofuscados
Set-MpPreference -AttackSurfaceReductionRules_Ids 5BEB7EFE-FD9A-4556-801D-275E5FFC04CC -AttackSurfaceReductionRules_Actions Enabled
```

### CIS Control 16 — Application Software Security

**Subcontrol 16.9** — Disable features not in use.
Desactiva Windows Script Host, Windows PowerShell v2 e outros componentes não necessários.

**Verificação:**
```powershell
# Confirmar que PowerShell v2 está desactivado
Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root

# Desactivar se necessário
Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root
```

---

## Fase 3 — Discovery

### CIS Control 5 — Account Management

**Subcontrol 5.3** — Disable dormant accounts.
Desactiva contas que não são usadas regularmente. Contas como svc.backup devem ter o mínimo de permissões necessárias e ser monitorizadas activamente.

**Subcontrol 5.4** — Restrict administrator privileges.
Implementa o modelo de administração em camadas (Tier Model). Administradores de domínio não devem fazer login em workstations e servidores comuns.

**Verificação:**
```powershell
# Ver contas com privilégios de Domain Admin
Get-ADGroupMember "Domain Admins" | Select-Object Name, SamAccountName

# Ver contas inactivas nos últimos 90 dias
Search-ADAccount -AccountInactive -TimeSpan (New-TimeSpan -Days 90) | Select-Object Name, LastLogonDate
```

### CIS Control 6 — Access Control Management

**Subcontrol 6.1** — Establish an access granting process.
Revê e documenta todas as permissões de contas de serviço e utilizadores privilegiados. Nenhuma conta deve ter mais permissões do que o necessário para a sua função.

**Subcontrol 6.3** — Require MFA for externally-exposed applications.
Para acesso remoto e VPN exige autenticação multifactor para prevenir que credenciais comprometidas sejam suficientes para acesso inicial.

---

## Fase 4 — Collection e Persistence

### CIS Control 3 — Data Protection

**Subcontrol 3.3** — Configure data access control lists.
Restringe o acesso a pastas com dados sensíveis.

**Subcontrol 3.11** — Encrypt sensitive data at rest.
Activa BitLocker em todos os volumes com dados sensíveis.

**Verificação:**
```powershell
# Ver estado do BitLocker
Get-BitLockerVolume | Select-Object MountPoint, VolumeStatus, EncryptionPercentage
```

### CIS Control 13 — Network Monitoring and Defense

**Subcontrol 13.1** — Centralize security event alerting.
Garante que todos os eventos de segurança relevantes (EventID 4688, Sysmon EventID 1, 11) são enviados para o SIEM centralizado.

**Subcontrol 13.3** — Deploy a network intrusion detection solution.
Monitoriza o tráfego de saída para detectar downloads de ferramentas e comunicações C2.

### CIS Control 4 — Secure Configuration of Enterprise Assets

**Subcontrol 4.6** — Securely manage enterprise assets and software.
A pasta Startup deve ter permissões restritivas. Apenas administradores devem poder escrever nesta localização.

**Verificação:**
```powershell
# Ver permissões da pasta Startup
icacls "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
icacls "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
```

---

## Logging e Auditoria

### CIS Control 8 — Audit Log Management

**Subcontrol 8.2** — Collect audit logs.
Activa e centraliza os logs críticos para detecção APT29:

```powershell
# Process Creation Auditing (EventID 4688 com commandLine)
auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable

# PowerShell Script Block Logging (EventID 4104)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 1

# PowerShell Module Logging (EventID 4103)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -Name "EnableModuleLogging" -Value 1

# PowerShell Transcription Logging
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -Name "EnableTranscripting" -Value 1
```

**Subcontrol 8.5** — Collect detailed audit logs.
O Sysmon com a config Olaf fornece visibilidade adicional: EventID 1 (Process Creation), EventID 3 (Network Connect), EventID 11 (File Create), EventID 13 (Registry Value Set).

**Verificação:**
```powershell
# Ver config Sysmon activa
sysmon -c

# Ver se o serviço está a correr
Get-Service Sysmon64 | Select-Object Status, StartType
```

---

## Prioridade de Implementação

| Prioridade | Controlo | Impacto |
|---|---|---|
| 1 | PowerShell Script Block Logging (8.2) | Visibilidade imediata de T1059.001 e T1027 |
| 2 | Process Creation Auditing com commandLine (8.2) | Visibilidade de todos os TTPs de Discovery |
| 3 | Sysmon com config Olaf (8.5) | Visibilidade de T1547.009 e T1560 |
| 4 | Windows Defender + AMSI activo (10.1) | Bloqueia payloads ofuscados |
| 5 | ASR Rules (10.5) | Reduz superfície de ataque para T1059.001 |
| 6 | Least Privilege em contas (5.4, 6.1) | Limita impacto após comprometimento |
| 7 | Egress filtering via proxy (9.3, 13.3) | Bloqueia C2 e tool transfer |
| 8 | AppLocker/WDAC (2.5) | Bloqueia execução de payloads não assinados |

---

## Referências

- [CIS Controls v8.1](https://www.cisecurity.org/controls/v8-1)
- [CIS Controls Download gratuito](https://learn.cisecurity.org/cis-controls-download)
- [CIS Controls Navigator](https://www.cisecurity.org/controls/cis-controls-navigator)
- [CIS Benchmark Microsoft Windows Server 2022](https://www.cisecurity.org/benchmark/microsoft_windows_server)
- [CIS Benchmark Microsoft Windows 11](https://www.cisecurity.org/benchmark/microsoft_windows_desktop)
- [Microsoft Security Baselines](https://learn.microsoft.com/en-us/windows/security/operating-system-security/device-management/windows-security-configuration-framework/windows-security-baselines)
- [Sysmon Config Olaf](https://github.com/olafhartong/sysmon-modular)
- [MITRE ATT&CK — APT29](https://attack.mitre.org/groups/G0016/)
