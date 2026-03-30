@echo off
setlocal enabledelayedexpansion

:: --- CONFIGURAZIONE WEBHOOK ---
set "https://discord.com/api/webhooks/1488243848496025731/WxeXkRYRM3QgUH-2gxFLf467nJZOSyBi7Uuk_rh-d71Pam1BgF6wN1si3imYYciR5pDT"
:: ------------------------------

set "LOGFILE=%temp%\Report_SS.txt"
echo --- INIZIO ANALISI MULTIACCOUNT/CHEAT --- > "%LOGFILE%"
echo Data: %date% %time% >> "%LOGFILE%"
echo Utente: %username% >> "%LOGFILE%"
echo ------------------------------------------ >> "%LOGFILE%"

:: 1. ANALISI USN JOURNAL (Tutte le tue stringhe + Log)
fsutil usn readjournal C: csv | findstr /i /C:"0x80000200" | findstr /i /C:"latest.log" /i /C:".log.gz" /i /C:"launcher_profiles.json" /i /C:"usernamecache.json" /i /C:"usercache.json" /i /C:"shig.inima" /i /C:"launcher_accounts.json" >> "%LOGFILE%" 2>nul

:: 2. ANALISI ESTENSIONI E JNATIVEHOOK
fsutil usn readjournal c: csv | findstr /i /C:"0x80000200" /i /C:"0x00001000" /i /C:"0x00002000" | findstr /i /C:".pf" /i /C:".exe" /i /C:".bat" /i /C:".cmd" /i /C:".jar" /i /C:".pif" /i /C:"jnativehook" >> "%LOGFILE%" 2>nul

:: 3. CONTROLLO BAM (Background Activity Moderator) - Executabili eseguiti
echo. >> "%LOGFILE%"
echo [BAM EXECUTION HISTORY] >> "%LOGFILE%"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings" /s >> "%LOGFILE%" 2>nul

:: 4. CONTROLLO RECENT DOCS E OPEN/SAVE PIDL (Spoofing)
echo. >> "%LOGFILE%"
echo [COMDLG32 / OPENSAVE HISTORY] >> "%LOGFILE%"
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU" /s >> "%LOGFILE%" 2>nul
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs" /s >> "%LOGFILE%" 2>nul

:: 5. STRINGHE EXTRA: ALTERNATE DATA STREAMS (ADS)
:: Cerca file che hanno dati nascosti dietro il nome (tecnica usata per nascondere DLL)
echo. >> "%LOGFILE%"
echo [DETECTION ADS - DATA STREAMS] >> "%LOGFILE%"
dir /R "%appdata%\.minecraft" | findstr ":$DATA" >> "%LOGFILE%" 2>nul

:: 6. CONTROLLO EVENTI (Cancellazione Log 1102 / 104)
echo. >> "%LOGFILE%"
echo [EVENT LOG DELETION CHECK] >> "%LOGFILE%"
wevtutil qe Security /q:"*[System[(EventID=1102)]]" /f:text /c:1 >> "%LOGFILE%" 2>nul
wevtutil qe System /q:"*[System[(EventID=104)]]" /f:text /c:1 >> "%LOGFILE%" 2>nul

:: 7. CONTROLLO SOFTWARE PERIFERICHE (Macro)
echo. >> "%LOGFILE%"
echo [PERIPHERAL MACRO CHECK] >> "%LOGFILE%"
if exist "%appdata%\Local\LGHUB" echo Logitech G Hub Trovato >> "%LOGFILE%"
if exist "%appdata%\Local\Razer\Synapse3" echo Razer Synapse Trovato >> "%LOGFILE%"
dir /s /b "%userprofile%\Documents\*Macro*" >> "%LOGFILE%" 2>nul

:: 8. INVIO A DISCORD
echo Invio report a Discord...
curl -F "file=@%LOGFILE%" -F "payload_json={\"content\": \"**Report SS Completo**\nUtente: %username%\nID: %computername%\"}" %WEBHOOK_URL%

:: PULIZIA
del "%LOGFILE%"
exit
