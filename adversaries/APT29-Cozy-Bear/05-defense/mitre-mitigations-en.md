# MITRE ATT&CK Mitigations — APT29

For each TTP emulated in this lab the MITRE ATT&CK recommended mitigations are documented. Mitigations are organised by attack phase following the real emulation sequence.

---

## Phase 1 — Initial Access

### T1566.002 — Spearphishing Link

APT29 delivers the payload through a malicious link that forces the download of an LNK file via browser.

**M1054 — Software Configuration**
Configure the browser to block automatic downloads of dangerous file types such as LNK, EXE and SCR. In Microsoft Edge enable SmartScreen and configure restrictive download policies.
[https://attack.mitre.org/mitigations/M1054/](https://attack.mitre.org/mitigations/M1054/)

**M1017 — User Training**
Train users to recognise spearphishing emails and not click links or open files from unverified sources. Regular phishing simulations significantly increase resistance.
[https://attack.mitre.org/mitigations/M1017/](https://attack.mitre.org/mitigations/M1017/)

**M1021 — Restrict Web-Based Content**
Use web proxies and URL filters to block access to known malicious domains and high-risk site categories.
[https://attack.mitre.org/mitigations/M1021/](https://attack.mitre.org/mitigations/M1021/)

---

### T1204.002 — Malicious File (LNK)

The user executes the LNK file which contains a hidden PowerShell command.

**M1038 — Execution Prevention**
Use AppLocker or Windows Defender Application Control to block execution of LNK files from download and temp folders.
[https://attack.mitre.org/mitigations/M1038/](https://attack.mitre.org/mitigations/M1038/)

**M1017 — User Training**
Train users not to open downloaded files without prior verification, especially files with PDF or document icons that are actually LNK shortcuts.
[https://attack.mitre.org/mitigations/M1017/](https://attack.mitre.org/mitigations/M1017/)

---

## Phase 2 — Execution and Command and Control

### T1059.001 — PowerShell Execution

APT29 uses PowerShell to execute payloads and establish C2.

**M1045 — Code Signing**
Configure PowerShell Execution Policy to AllSigned or RemoteSigned, requiring scripts to be digitally signed by a trusted entity.
[https://attack.mitre.org/mitigations/M1045/](https://attack.mitre.org/mitigations/M1045/)

**M1042 — Disable or Remove Feature or Program**
Where PowerShell is not needed for end users, disable it or restrict access via Group Policy. For users who need PowerShell use Constrained Language Mode.
[https://attack.mitre.org/mitigations/M1042/](https://attack.mitre.org/mitigations/M1042/)

**M1026 — Privileged Account Management**
Restrict which accounts can run PowerShell with elevated privileges. Standard users should not have access to administrative PowerShell.
[https://attack.mitre.org/mitigations/M1026/](https://attack.mitre.org/mitigations/M1026/)

---

### T1027 — Obfuscation

APT29 obfuscates payloads with Base64 and -ExecutionPolicy Bypass to evade detection.

**M1049 — Antivirus/Antimalware**
Enable AMSI (Antimalware Scan Interface) which intercepts decoded PowerShell scripts before execution, even when obfuscated with Base64 or other techniques.
[https://attack.mitre.org/mitigations/M1049/](https://attack.mitre.org/mitigations/M1049/)

**M1040 — Behavior Prevention on Endpoint**
Use EDR with behavioural detection to identify obfuscation patterns even when static signatures do not detect them.
[https://attack.mitre.org/mitigations/M1040/](https://attack.mitre.org/mitigations/M1040/)

---

### T1218.011 — Rundll32

APT29 uses Rundll32 to load malicious DLLs and evade controls that only block executables.

**M1050 — Exploit Protection**
Configure Windows Defender Exploit Guard to apply additional protections to rundll32.exe, including blocking Win32k calls and preventing code injection.
[https://attack.mitre.org/mitigations/M1050/](https://attack.mitre.org/mitigations/M1050/)

**M1038 — Execution Prevention**
Use AppLocker or WDAC to block execution of unsigned DLLs via rundll32, allowing only DLLs from authorised paths.
[https://attack.mitre.org/mitigations/M1038/](https://attack.mitre.org/mitigations/M1038/)

---

### T1071.001 — C2 via HTTPS

APT29 uses HTTPS on port 443 to disguise C2 communications as legitimate traffic.

**M1031 — Network Intrusion Prevention**
Implement TLS inspection on the outbound proxy to inspect HTTPS traffic and detect C2 communications even in encrypted channels.
[https://attack.mitre.org/mitigations/M1031/](https://attack.mitre.org/mitigations/M1031/)

**M1037 — Filter Network Traffic**
Restrict outbound traffic to known and authorised destinations. Endpoints should not establish direct HTTPS connections to arbitrary IPs without going through a proxy.
[https://attack.mitre.org/mitigations/M1037/](https://attack.mitre.org/mitigations/M1037/)

---

## Phase 3 — Discovery

### T1087 — Account Discovery
### T1069 — Permission Groups Discovery
### T1082 — System Information Discovery
### T1057 — Process Discovery
### T1012 — Registry Query

APT29 uses native Windows tools like net, systeminfo, tasklist and reg to map the environment without installing additional tools (living off the land).

**M1028 — Operating System Configuration**
Audit and restrict who can run enumeration commands. Standard users should not have access to net.exe for domain queries.
[https://attack.mitre.org/mitigations/M1028/](https://attack.mitre.org/mitigations/M1028/)

**M1026 — Privileged Account Management**
Implement the principle of least privilege. Service accounts and normal users should not have Domain User permissions that allow extensive AD enumeration.
[https://attack.mitre.org/mitigations/M1026/](https://attack.mitre.org/mitigations/M1026/)

**M1018 — User Account Management**
Review and remove excessive permissions on accounts like svc.backup that should not have access to administration tools.
[https://attack.mitre.org/mitigations/M1018/](https://attack.mitre.org/mitigations/M1018/)

---

## Phase 4 — Collection and Persistence

### T1560 — Archive Collected Data

APT29 uses 7-Zip to compress data before exfiltration.

**M1057 — Data Loss Prevention**
Implement DLP to detect and block the creation of ZIP archives in suspicious paths or outside authorised working folders.
[https://attack.mitre.org/mitigations/M1057/](https://attack.mitre.org/mitigations/M1057/)

**M1041 — Encrypt Sensitive Information**
Encrypt sensitive data at rest so that even if compressed and exfiltrated it is not readable without the decryption key.
[https://attack.mitre.org/mitigations/M1041/](https://attack.mitre.org/mitigations/M1041/)

---

### T1105 — Ingress Tool Transfer

APT29 uses Invoke-WebRequest to download additional tools to the compromised system.

**M1031 — Network Intrusion Prevention**
Block downloads of executables and DLLs from unauthorised IPs. Outbound traffic should pass through a proxy with content inspection.
[https://attack.mitre.org/mitigations/M1031/](https://attack.mitre.org/mitigations/M1031/)

**M1037 — Filter Network Traffic**
Restrict which processes can make outbound network calls. powershell.exe should not be able to download files directly from the internet without going through a proxy.
[https://attack.mitre.org/mitigations/M1037/](https://attack.mitre.org/mitigations/M1037/)

---

### T1547.009 — Startup Folder Persistence

APT29 copies the LNK payload to the Startup folder to ensure execution on the next login.

**M1022 — Restrict File and Directory Permissions**
Remove write permissions on the Startup folder for non-administrator users. Only elevated processes should be able to write to this location.
[https://attack.mitre.org/mitigations/M1022/](https://attack.mitre.org/mitigations/M1022/)

**M1024 — Restrict Registry Permissions**
For registry-based persistence (T1547.001 variant), restrict permissions on Run and RunOnce keys to administrators.
[https://attack.mitre.org/mitigations/M1024/](https://attack.mitre.org/mitigations/M1024/)

---

## Mitigation Summary by TTP

| TTP | Technique | Primary Mitigation | MITRE ID |
|---|---|---|---|
| T1566.002 | Spearphishing Link | Software Configuration + User Training | M1054, M1017 |
| T1204.002 | Malicious File LNK | Execution Prevention | M1038 |
| T1059.001 | PowerShell Execution | Code Signing + Disable Feature | M1045, M1042 |
| T1027 | Obfuscation | Antivirus/AMSI | M1049 |
| T1218.011 | Rundll32 | Exploit Protection + Execution Prevention | M1050, M1038 |
| T1071.001 | C2 HTTPS | Network Intrusion Prevention | M1031 |
| T1087 | Account Discovery | OS Configuration + Least Privilege | M1028, M1026 |
| T1069 | Permission Groups | Privileged Account Management | M1026 |
| T1082 | System Info | OS Configuration | M1028 |
| T1057 | Process Discovery | OS Configuration | M1028 |
| T1012 | Registry Query | OS Configuration | M1028 |
| T1560 | Archive Data | Data Loss Prevention | M1057 |
| T1105 | Tool Transfer | Network Intrusion Prevention | M1031 |
| T1547.009 | Startup Persistence | Restrict File Permissions | M1022 |

---

## References

- [MITRE ATT&CK — APT29](https://attack.mitre.org/groups/G0016/)
- [MITRE ATT&CK — Mitigations](https://attack.mitre.org/mitigations/enterprise/)
- [CISA — APT29 Advisory](https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-352a)
- [Microsoft — Protect against APT29](https://www.microsoft.com/en-us/security/blog/2024/01/25/midnight-blizzard-guidance-for-responders-on-nation-state-attack/)
