@echo off
setlocal enabledelayedexpansion
color 0e
title Scanner SS - Cartella Desktop

set "FOLDER=%userprofile%\Desktop\CONTROLLO_SS_REPORT"
if not exist "%FOLDER%" mkdir "%FOLDER%"
set "R=%FOLDER%\REPORT_GENERALE.txt"

echo [!] ANALISI IN CORSO... NON CHIUDERE.
echo [!] I RISULTATI SARANNO NELLA CARTELLA '%FOLDER%'

echo --- REPORT SS COMPLETO --- > "%R%"
echo UTENTE: %username% >> "%R%"
echo DATA: %date% %time% >> "%R%"
echo ------------------------------------------ >> "%R%"

echo [1/6] Analisi USN Journal (Account e Log)...
fsutil usn readjournal C: csv | findstr /i /C:"0x80000200" | findstr /i /C:"latest.log" /i /C:".log.gz" /i /C:"launcher_profiles" /i /C:"usernamecache.json" /i /C:"usercache.json" /i /C:"shig.inima" /i /C:"launcher_accounts" /i /C:"lunar" /i /C:"badlion" /i /C:"vape" /i /C:"drip" >> "%R%" 2>nul

echo [2/6] Analisi USN Journal (Eseguibili e Scripts)...
fsutil usn readjournal c: csv | findstr /i /C:"0x80000200" /i /C:"0x00001000" /i /C:"0x00002000" | findstr /i /C:".pf" /i /C:".exe" /i /C:".bat" /i /C:".cmd" /i /C:".jar" /i /C:".pif" /i /C:"jnativehook" >> "%R%" 2>nul

echo [3/6] Estrazione Registri (MuiCache, UserAssist, BAM)...
reg query "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache" /s >> "%R%" 2>nul
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist" /s >> "%R%" 2>nul
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU" /s >> "%R%" 2>nul
reg query "HKLM\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings" /s >> "%R%" 2>nul
reg query "HKCU\Software\Microsoft\DirectInput\MostRecentApplication" /s >> "%R%" 2>nul

echo [4/6] Verifica Hardware e USB...
reg query "HKLM\SYSTEM\ControlSet001\Enum\USB" /s >> "%FOLDER%\USB_HISTORY.txt" 2>nul
reg query "HKLM\SYSTEM\MountedDevices" >> "%FOLDER%\VOLUMI_MONTATI.txt" 2>nul

echo [5/6] Ricerca File Fisici (JNativeHook e Launcher)...
dir /s /b "%temp%\JNativeHook*" >> "%R%" 2>nul
dir /s /b "%appdata%\.minecraft\launcher_accounts.json" >> "%R%" 2>nul
dir /s /b "%appdata%\.minecraft\versions\*\*.json" >> "%R%" 2>nul

echo [6/6] Controllo Log Eventi (Pulizia Tracce)...
wevtutil qe Security /q:"*[System[(EventID=1102)]]" /f:text /c:1 >> "%R%" 2>nul
wevtutil qe Security /q:"*[System[(EventID=4616)]]" /f:text /c:1 >> "%R%" 2>nul

echo ------------------------------------------ >> "%R%"
echo [!] SCANSIONE TERMINATA.

start notepad.exe "%R%"

echo.
echo ======================================================
echo  OPERAZIONE COMPLETATA!
echo  I file sono nella cartella: %FOLDER%
echo  Se vedi errori sopra, assicurati di aver usato 'Esegui come Amministratore'.
echo ======================================================
echo Premi un tasto per chiudere questa finestra.
pause
