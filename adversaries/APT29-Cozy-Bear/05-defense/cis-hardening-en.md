# CIS Controls — APT29 Hardening

This document maps the relevant CIS controls for each phase of the APT29 attack emulated in this lab. References are based on CIS Controls v8 and the CIS Benchmark Windows Server 2022.

Controls are organised by attack phase to make it easy to prioritise implementation based on the most immediate risk.

---

## Base References

- [CIS Controls v8](https://www.cisecurity.org/controls/v8)
- [CIS Benchmark Microsoft Windows Server 2022](https://www.cisecurity.org/benchmark/microsoft_windows_server)
- [CIS Benchmark Microsoft Windows 11](https://www.cisecurity.org/benchmark/microsoft_windows_desktop)

---

## Phase 1 — Initial Access

### CIS Control 9 — Email and Web Browser Protections

**Subcontrol 9.1** — Ensure only fully supported browsers and email clients are used.
Keep Microsoft Edge up to date to ensure SmartScreen and Safe Browsing protections are active with the latest signatures.

**Subcontrol 9.3** — Maintain and enforce network-based URL filters.
Implement an outbound proxy with URL categorisation to block access to phishing domains, newly registered domains and high-risk categories.

**Subcontrol 9.6** — Block unnecessary file types.
Configure the browser and email gateway to block or quarantine attachments and downloads of dangerous types: LNK, VBS, JS, HTA, EXE, SCR, BAT.

**Verification:**
```powershell
# Confirm SmartScreen is active
Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" | Select-Object EnableSmartScreen
```

---

## Phase 2 — Execution and Defense Evasion

### CIS Control 2 — Inventory and Control of Software Assets

**Subcontrol 2.5** — Allowlist authorized software.
Implement AppLocker or Windows Defender Application Control with an authorised application list. Unsigned PowerShell scripts should be blocked by default.

**Verification:**
```powershell
# View active AppLocker policy
Get-AppLockerPolicy -Effective | Format-List
```

### CIS Control 10 — Malware Defenses

**Subcontrol 10.1** — Deploy and maintain anti-malware software.
Keep Windows Defender active and updated. AMSI intercepts obfuscated PowerShell scripts even before execution.

**Subcontrol 10.5** — Enable anti-exploitation features.
Enable Windows Defender Exploit Guard on all endpoints with the following protections:
- Attack Surface Reduction (ASR) rules
- Network Protection
- Controlled Folder Access

**Verification:**
```powershell
# Confirm Defender status
Get-MpComputerStatus | Select-Object AMServiceEnabled, RealTimeProtectionEnabled, AMProductVersion

# Check active ASR rules
Get-MpPreference | Select-Object AttackSurfaceReductionRules_Ids, AttackSurfaceReductionRules_Actions
```

**Critical ASR Rules for APT29:**
```powershell
# Block executable content from email and webmail
Set-MpPreference -AttackSurfaceReductionRules_Ids BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550 -AttackSurfaceReductionRules_Actions Enabled

# Block Office from creating child processes
Set-MpPreference -AttackSurfaceReductionRules_Ids D4F940AB-401B-4EFC-AADC-AD5F3C50688A -AttackSurfaceReductionRules_Actions Enabled

# Block obfuscated scripts
Set-MpPreference -AttackSurfaceReductionRules_Ids 5BEB7EFE-FD9A-4556-801D-275E5FFC04CC -AttackSurfaceReductionRules_Actions Enabled
```

### CIS Control 16 — Application Software Security

**Subcontrol 16.9** — Disable features not in use.
Disable Windows Script Host, Windows PowerShell v2 (vulnerable to logging bypass) and other unnecessary components.

**Verification:**
```powershell
# Confirm PowerShell v2 is disabled
Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root

# Disable if needed
Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root
```

---

## Phase 3 — Discovery

### CIS Control 5 — Account Management

**Subcontrol 5.3** — Disable dormant accounts.
Disable accounts that are not used regularly. Accounts like svc.backup should have minimum required permissions and be actively monitored.

**Subcontrol 5.4** — Restrict administrator privileges.
Implement the tiered administration model (Tier Model). Domain administrators should not log in to common workstations and servers.

**Verification:**
```powershell
# View accounts with Domain Admin privileges
Get-ADGroupMember "Domain Admins" | Select-Object Name, SamAccountName

# View accounts inactive in the last 90 days
Search-ADAccount -AccountInactive -TimeSpan (New-TimeSpan -Days 90) | Select-Object Name, LastLogonDate
```

### CIS Control 6 — Access Control Management

**Subcontrol 6.1** — Establish an access granting process.
Review and document all service account and privileged user permissions. No account should have more permissions than necessary for its role.

**Subcontrol 6.3** — Require MFA for externally-exposed applications.
For remote access and VPN require multi-factor authentication to prevent compromised credentials alone being sufficient for initial access.

---

## Phase 4 — Collection and Persistence

### CIS Control 3 — Data Protection

**Subcontrol 3.3** — Configure data access control lists.
Restrict access to folders with sensitive data. The Administrator user should not have default access to all system documents.

**Subcontrol 3.11** — Encrypt sensitive data at rest.
Enable BitLocker on all volumes with sensitive data so that even if data is copied it is not readable.

**Verification:**
```powershell
# Check BitLocker status
Get-BitLockerVolume | Select-Object MountPoint, VolumeStatus, EncryptionPercentage
```

### CIS Control 13 — Network Monitoring and Defense

**Subcontrol 13.1** — Centralize security event alerting.
Ensure all relevant security events (EventID 4688, Sysmon EventID 1, 11) are sent to the centralised SIEM.

**Subcontrol 13.3** — Deploy a network intrusion detection solution.
Monitor outbound traffic to detect tool downloads and C2 communications even in HTTPS via TLS inspection.

### CIS Control 4 — Secure Configuration of Enterprise Assets

**Subcontrol 4.1** — Establish and maintain a secure configuration process.
Use a documented configuration baseline for all endpoints. The CIS Benchmark Windows Server 2022 provides 300+ specific controls.

**Subcontrol 4.6** — Securely manage enterprise assets and software.
The Startup folder should have restrictive permissions. Only administrators should be able to write to this location.

**Verification:**
```powershell
# View Startup folder permissions
icacls "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
icacls "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
```

---

## Logging and Auditing

A critical component of APT29 detection is having logging correctly configured. Without logs the SIEM detects nothing.

### CIS Control 8 — Audit Log Management

**Subcontrol 8.2** — Collect audit logs.
Enable and centralise the following logs that are critical for APT29 detection:

```powershell
# Process Creation Auditing (EventID 4688 with commandLine)
auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable

# PowerShell Script Block Logging (EventID 4104)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 1

# PowerShell Module Logging (EventID 4103)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -Name "EnableModuleLogging" -Value 1

# PowerShell Transcription Logging
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -Name "EnableTranscripting" -Value 1
```

**Subcontrol 8.5** — Collect detailed audit logs.
Sysmon with the Olaf config provides additional visibility beyond native Windows logs:
- EventID 1 — Process Creation with hash and commandLine
- EventID 3 — Network Connect
- EventID 11 — File Create
- EventID 13 — Registry Value Set

**Sysmon config verification:**
```powershell
# View active Sysmon config
sysmon -c

# Check service is running
Get-Service Sysmon64 | Select-Object Status, StartType
```

---

## Implementation Priority

If you cannot implement everything at once, this is the recommended order based on impact against APT29:

| Priority | Control | Impact |
|---|---|---|
| 1 | PowerShell Script Block Logging (8.2) | Immediate visibility of T1059.001 and T1027 |
| 2 | Process Creation Auditing with commandLine (8.2) | Visibility of all Discovery TTPs |
| 3 | Sysmon with Olaf config (8.5) | Visibility of T1547.009 and T1560 |
| 4 | Windows Defender + AMSI active (10.1) | Blocks obfuscated payloads |
| 5 | ASR Rules (10.5) | Reduces attack surface for T1059.001 |
| 6 | Least Privilege on accounts (5.4, 6.1) | Limits impact after compromise |
| 7 | Egress filtering via proxy (9.3, 13.3) | Blocks C2 and tool transfer |
| 8 | AppLocker/WDAC (2.5) | Blocks execution of unsigned payloads |

---

## References

- [CIS Controls v8](https://www.cisecurity.org/controls/v8)
- [CIS Benchmark Windows Server 2022](https://www.cisecurity.org/benchmark/microsoft_windows_server)
- [Microsoft Security Baselines](https://learn.microsoft.com/en-us/windows/security/operating-system-security/device-management/windows-security-configuration-framework/windows-security-baselines)
- [Sysmon Config Olaf](https://github.com/olafhartong/sysmon-modular)
- [MITRE ATT&CK — APT29](https://attack.mitre.org/groups/G0016/)
