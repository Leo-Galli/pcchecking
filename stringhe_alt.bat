@echo off
setlocal enabledelayedexpansion

:: --- CONFIGURAZIONE DIRETTA ---
set "WEBHOOK_URL=https://discord.com/api/webhooks/1488243848496025731/WxeXkRYRM3QgUH-2gxFLf467nJZOSyBi7Uuk_rh-d71Pam1BgF6wN1si3imYYciR5pDT"
set "LOGFILE=%temp%\Scan_Report_%username%.txt"

:: --- INIZIO RACCOLTA DATI ---
echo [!] ANALISI AVVIATA SU: %computername% > "%LOGFILE%"
echo [!] UTENTE: %username% >> "%LOGFILE%"
echo ------------------------------------------ >> "%LOGFILE%"

:: 1. USN JOURNAL - MULTIACCOUNT & LOGS (Tutte le tue stringhe)
echo [JOURNAL MULTIACCOUNT] >> "%LOGFILE%"
fsutil usn readjournal C: csv | findstr /i /C:"0x80000200" | findstr /i /C:"latest.log" /i /C:".log.gz" /i /C:"launcher_profiles.json" /i /C:"usernamecache.json" /i /C:"usercache.json" /i /C:"shig.inima" /i /C:"launcher_accounts.json" >> "%LOGFILE%" 2>nul

:: 2. USN JOURNAL - ESEGUIBILI & SCRIPTS
echo. >> "%LOGFILE%"
echo [JOURNAL EXECUTABLES] >> "%LOGFILE%"
fsutil usn readjournal c: csv | findstr /i /C:"0x80000200" /i /C:"0x00001000" /i /C:"0x00002000" | findstr /i /C:".pf" /i /C:".exe" /i /C:".bat" /i /C:".cmd" /i /C:".jar" /i /C:".pif" /i /C:"jnativehook" >> "%LOGFILE%" 2>nul

:: 3. REGISTRY - MUICACHE (Programmi eseguiti anche se cancellati)
echo. >> "%LOGFILE%"
echo [MUICACHE DETECTION] >> "%LOGFILE%"
reg query "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache" /s >> "%LOGFILE%" 2>nul

:: 4. REGISTRY - DIRECTINPUT (Periferiche e software mouse)
echo. >> "%LOGFILE%"
echo [DIRECT INPUT / MOUSE] >> "%LOGFILE%"
reg query "HKCU\Software\Microsoft\DirectInput\MostRecentApplication" /s >> "%LOGFILE%" 2>nul
reg query "HKCU\Control Panel\Mouse" /s >> "%LOGFILE%" 2>nul

:: 5. REGISTRY - BAM & PREFETCH PARAMETERS
echo. >> "%LOGFILE%"
echo [BAM & PREFETCH SETTINGS] >> "%LOGFILE%"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings" /s >> "%LOGFILE%" 2>nul
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" >> "%LOGFILE%" 2>nul

:: 6. REGISTRY - COMDLG32 (Estensioni e DLL iniettate)
echo. >> "%LOGFILE%"
echo [COMDLG32 / DLL INJECT CHECK] >> "%LOGFILE%"
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU" /s >> "%LOGFILE%" 2>nul
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU" /s >> "%LOGFILE%" 2>nul

:: 7. FILE SYSTEM - JNATIVEHOOK & TEMP FILES
echo. >> "%LOGFILE%"
echo [FILE SYSTEM TRACES] >> "%LOGFILE%"
dir /s /b "%temp%\JNativeHook*" >> "%LOGFILE%" 2>nul
dir /s /b "%appdata%\.minecraft\launcher_accounts.json" >> "%LOGFILE%" 2>nul

:: 8. EVENT LOGS - CANCELLAZIONE REGISTRI (1102, 4616, 104)
echo. >> "%LOGFILE%"
echo [EVENT LOGS HISTORY] >> "%LOGFILE%"
wevtutil qe Security /q:"*[System[(EventID=1102)]]" /f:text /c:1 >> "%LOGFILE%" 2>nul
wevtutil qe Security /q:"*[System[(EventID=4616)]]" /f:text /c:1 >> "%LOGFILE%" 2>nul

:: --- INVIO A DISCORD ---
curl -X POST -F "file1=@%LOGFILE%" -F "payload_json={\"content\": \"**NUOVO CONTROLLO SS**\nTarget: `%username%`\nStatus: Analisi completata.\"}" %WEBHOOK_URL%

:: PULIZIA FINALE
del "%LOGFILE%"
exit
