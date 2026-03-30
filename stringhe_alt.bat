@echo off
setlocal enabledelayedexpansion
color 0b
set "R=%userprofile%\Desktop\REPORT_SS_MANUALE.txt"

echo [!] SCANSIONE IN CORSO... IL REPORT APPARIRA SUL DESKTOP.
echo --- REPORT CONTROLLO SS --- > "%R%"
echo UTENTE: %username% >> "%R%"
echo DATA: %date% %time% >> "%R%"
echo ------------------------------------------ >> "%R%"

fsutil usn readjournal C: csv | findstr /i /C:"0x80000200" | findstr /i /C:"latest.log" /i /C:".log.gz" /i /C:"launcher_profiles" /i /C:"usernamecache.json" /i /C:"usercache.json" /i /C:"shig.inima" /i /C:"launcher_accounts" /i /C:"lunar" /i /C:"badlion" /i /C:"vape" /i /C:"drip" >> "%R%" 2>nul

fsutil usn readjournal c: csv | findstr /i /C:"0x80000200" /i /C:"0x00001000" /i /C:"0x00002000" | findstr /i /C:".pf" /i /C:".exe" /i /C:".bat" /i /C:".cmd" /i /C:".jar" /i /C:".pif" /i /C:"jnativehook" >> "%R%" 2>nul

reg query "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache" /s >> "%R%" 2>nul
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist" /s >> "%R%" 2>nul
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU" /s >> "%R%" 2>nul
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU" /s >> "%R%" 2>nul
reg query "HKLM\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings" /s >> "%R%" 2>nul
reg query "HKLM\SYSTEM\ControlSet001\Enum\USB" /s >> "%R%" 2>nul
reg query "HKLM\SYSTEM\MountedDevices" >> "%R%" 2>nul
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs" /s >> "%R%" 2>nul
reg query "HKCU\Software\Microsoft\DirectInput\MostRecentApplication" /s >> "%R%" 2>nul

dir /s /b "%temp%\JNativeHook*" >> "%R%" 2>nul
dir /s /b "%appdata%\.minecraft\launcher_accounts.json" >> "%R%" 2>nul
dir /s /b "%appdata%\.minecraft\launcher_profiles.json" >> "%R%" 2>nul
dir /s /b "%appdata%\.minecraft\versions\*\*.json" >> "%R%" 2>nul

wevtutil qe Security /q:"*[System[(EventID=1102)]]" /f:text /c:1 >> "%R%" 2>nul
wevtutil qe Security /q:"*[System[(EventID=4616)]]" /f:text /c:1 >> "%R%" 2>nul

echo --- FINE REPORT --- >> "%R%"
start notepad.exe "%R%"
exit
