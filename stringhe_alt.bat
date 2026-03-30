@echo off
setlocal enabledelayedexpansion
color 0c
title SCANNER SS - OFFLINE MODE

:: Setup Cartella Desktop
set "FOLDER=%userprofile%\Desktop\REPORT_SS_CARTELLA"
if not exist "%FOLDER%" mkdir "%FOLDER%"
set "R=%FOLDER%\REPORT_GENERALE.txt"

echo [!] ANALISI IN CORSO... NON CHIUDERE LA FINESTRA.
echo [!] LOG: %R%

echo --- REPORT SS COMPLETO --- > "%R%"
echo UTENTE: %username% >> "%R%"
echo DATA: %date% %time% >> "%R%"
echo ------------------------------------------ >> "%R%"

:: 1. USN JOURNAL - MULTIACCOUNT & LOGS
echo [1/5] Scansione Journal (Account/Logs)...
fsutil usn readjournal C: csv | findstr /i /C:"0x80000200" | findstr /i /C:"latest.log" /i /C:".log.gz" /i /C:"launcher_profiles" /i /C:"usernamecache.json" /i /C:"usercache.json" /i /C:"shig.inima" /i /C:"launcher_accounts" /i /C:"lunar" /i /C:"badlion" /i /C:"vape" /i /C:"drip" >> "%R%" 2>nul

:: 2. USN JOURNAL - EXECUTABLES & PIF
echo [2/5] Scansione Journal (Eseguibili/Cheat)...
fsutil usn readjournal c: csv | findstr /i /C:"0x80000200" /i /C:"0x00001000" /i /C:"0x00002000" | findstr /i /C:".pf" /i /C:".exe" /i /C:".bat" /i /C:".cmd" /i /C:".jar" /i /C:".pif" /i /C:"jnativehook" >> "%R%" 2>nul

:: 3. REGISTRI DI SISTEMA (Tutte le tue stringhe Registry)
echo [3/5] Estrazione Registri (MuiCache/UserAssist/BAM)...
reg query "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache" /s >> "%R%" 2>nul
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist" /s >> "%R%" 2>nul
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU" /s >> "%R%" 2>nul
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU" /s >> "%R%" 2>nul
reg query "HKLM\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings" /s >> "%R%" 2>nul
reg query "HKLM\SYSTEM\ControlSet001\Enum\USB" /s >> "%FOLDER%\USB_HISTORY.txt" 2>nul
reg query "HKLM\SYSTEM\MountedDevices" >> "%FOLDER%\VOLUMI.txt" 2>nul
reg query "HKCU\Software\Microsoft\DirectInput\MostRecentApplication" /s >> "%R%" 2>nul

:: 4. RICERCA FILE FISICI & VERSIONI
echo [4/5] Ricerca Versioni e JNativeHook...
dir /s /b "%temp%\JNativeHook*" >> "%R%" 2>nul
dir /s /b "%appdata%\.minecraft\launcher_accounts.json" >> "%R%" 2>nul
dir /s /b "%appdata%\.minecraft\versions\*\*.json" >> "%R%" 2>nul
dir /s /b "%userprofile%\Downloads\*.jar" >> "%R%" 2>nul

:: 5. EVENT LOGS (Cancellazioni)
echo [5/5] Controllo Log Eventi (1102/4616)...
wevtutil qe Security /q:"*[System[(EventID=1102)]]" /f:text /c:1 >> "%R%" 2>nul
wevtutil qe Security /q:"*[System[(EventID=4616)]]" /f:text /c:1 >> "%R%" 2>nul

echo ------------------------------------------ >> "%R%"
echo [!] FINE ANALISI. >> "%R%"

:: Apertura automatica
start notepad.exe "%R%"

echo.
echo ======================================================
echo  ANALISI COMPLETATA CON SUCCESSO!
echo  Cartella creata sul Desktop: REPORT_SS_CARTELLA
echo ======================================================
echo Se vedi errori "Accesso negato", riesegui come AMMINISTRATORE.
echo.
pause
