mode con:cols=50 lines=1

title Start work...
call :PostClear>>"%userprofile%\Desktop\PostClear.log" 2>&1
EXIT /b 0
:PostClear

title Wait Explorer
taskkill /f /im explorer.exe
taskkill /f /im ShellExperienceHost.exe
taskkill /f /im backgroundTaskHost.exe
if exist %programdata%\PostClear\FirstLoad.reg (
	title Stopping DiagTrack
	net stop DiagTrack
	title Applying FirstLoad.reg
	%programdata%\PostClear\superUser64.exe /ws %windir%\System32\reg.exe import %programdata%\PostClear\FirstLoad.reg
	title Deleting Defender tasks
	schtasks /delete /tn "Microsoft\Windows\Windows Defender\Windows Defender Cache Maintenance" /f
	schtasks /delete /tn "Microsoft\Windows\Windows Defender\Windows Defender Cleanup" /f
	schtasks /delete /tn "Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan" /f
	schtasks /delete /tn "Microsoft\Windows\Windows Defender\Windows Defender Verification" /f
	del /f /q %programdata%\PostClear\FirstLoad.reg
	goto Reboot
)
if exist %programdata%\PostClear\PostClearM.bat (
	title Fix explorer bar
	%programdata%\PostClear\ViVe\ViVeTool.exe /enable /id:18755234
	rd /s /q %programdata%\PostClear\ViVe
	title Install ClassicShell Start
	%programdata%\PostClear\ClassicShell.msi /qn ADDLOCAL=ClassicStartMenu
	xcopy /y /e "%programdata%\PostClear\Classic Shell" "%programfiles%\Classic Shell"
	rd /s /q "%programdata%\PostClear\Classic Shell"
	del /f /q %programdata%\PostClear\ClassicShell.msi
	title Applying PostClearM.bat
	call %programdata%\PostClear\PostClearM.bat
	del /f /q %programdata%\PostClear\PostClearM.bat
	title Shortcuts
	rd /s /q "%programdata%\Microsoft\Windows\Start Menu\Programs\Maintenance"
	rd /s /q "%programdata%\Microsoft\Windows\Start Menu\Programs\Windows PowerShell"
	rd /s /q "%programdata%\Microsoft\Windows\Start Menu\Programs\Classic Shell"
	rd /s /q "%programdata%\Microsoft\Windows\Start Menu\Programs\Accessories\System Tools"
	del /f /q "%programdata%\Microsoft\Windows\Start Menu\Programs\Administrative Tools\System Configuration.lnk"
	del /f /q "%programdata%\Microsoft\Windows\Start Menu\Programs\System Tools\Task Manager.lnk"
	%programdata%\PostClear\HelpTool.exe %windir%\system32\msconfig.exe "%programdata%\Microsoft\Windows\Start Menu\Programs\Administrative Tools\Конфигурация системы.lnk"
	%programdata%\PostClear\HelpTool.exe "%windir%\system32\gpedit.msc" "%programdata%\Microsoft\Windows\Start Menu\Programs\Administrative Tools\Групповые политики.lnk"
	%programdata%\PostClear\HelpTool.exe "%windir%\system32\charmap.exe" "%programdata%\Microsoft\Windows\Start Menu\Programs\Accessories\Таблица символов.lnk"
	%programdata%\PostClear\HelpTool.exe %windir%\System32\calc.exe "%programdata%\Microsoft\Windows\Start Menu\Programs\Accessories\Калькулятор.lnk"
	%programdata%\PostClear\HelpTool.exe "%programfiles(x86)%\Microsoft\Edge\Application\msedge.exe" "%programdata%\Microsoft\Windows\Start Menu\Programs\Accessories\Microsoft Edge.lnk"
	%programdata%\PostClear\HelpTool.exe "%programfiles%\Internet Explorer\iexplore.exe" "%programdata%\Microsoft\Windows\Start Menu\Programs\Accessories\Internet Explorer.lnk" "%programfiles%\Internet Explorer" "\ -Embedding"
	%programdata%\PostClear\HelpTool.exe %windir%\system32\taskmgr.exe "%programdata%\Microsoft\Windows\Start Menu\Programs\System Tools\Диспетчер задач.lnk"
	%programdata%\PostClear\HelpTool.exe %programdata%\PostClear\WinTool.exe "%programdata%\Microsoft\Windows\Start Menu\Programs\System Tools\WinTool.lnk"
	%programdata%\PostClear\HelpTool.exe %windir%\System32\WindowsPowerShell\v1.0\powershell.exe "%programdata%\Microsoft\Windows\Start Menu\Programs\System Tools\Windows PowerShell.lnk" %windir%
	%programdata%\PostClear\HelpTool.exe %windir%\System32\WindowsPowerShell\v1.0\powershell_ise.exe "%programdata%\Microsoft\Windows\Start Menu\Programs\System Tools\Windows PowerShell ISE.lnk"
	del /f /q %programdata%\PostClear\HelpTool.exe
) else (
	for /F "skip=1 tokens=2*" %%A in ('reg query "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\InstallService" /V Start') do (if %%B equ 0x4 (title Press any key && start cmd /c "mode con:cols=60 lines=3 && title AppX Warning && echo off && echo "Microsoft Store Install Service" is Disabled! && echo Before create new account you must Enable AppX support. && pause" && pause))
)

title User shortcuts
del /f /q "%userprofile%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\OneDrive.lnk"
del /f /q "%userprofile%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Accessories\Internet Explorer.lnk"
del /f /q "%userprofile%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\System Tools\Administrative Tools.lnk"
del /f /q "%userprofile%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\System Tools\computer.lnk"
rd /s /q "%userprofile%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Maintenance"
rd /s /q "%userprofile%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Windows PowerShell"

title Edge settings
mkdir "%userprofile%\AppData\Local\Microsoft\Edge\User Data\"
copy /y "%programdata%\PostClear\Local State" "%userprofile%\AppData\Local\Microsoft\Edge\User Data\"

title Applying _PostClear.reg
reg import %programdata%\PostClear\_PostClear.reg

title Turn-off auto run last apps
For /F Tokens^=3^ Delims^=^" %%G In ('%windir%\System32\whoami.exe /User /Fo CSV /NH') DO SET SID=%%G
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\UserARSO\%SID%" /v OptOut /t REG_DWORD /d 1 /f

title Copy shell view types
set shell="HKEY_CURRENT_USER\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\Shell\Bags\AllFolders\Shell\
reg copy %shell%{5C4F28B5-F869-4E84-8E60-F11DB97C5CC7}" %shell%{7D49D726-3C21-4F05-99AA-FDC2C9474656}" /s /f
reg copy %shell%{B3690E58-E961-423B-B687-386EBFD83239}" %shell%{5FA96407-7E77-483C-AC93-691D05850DE8}" /s /f
set search=%shell%{7FDE1A1E-8B31-49A5-93B8-6BE14CFA4943}"
reg copy %search% %shell%{36011842-DCCC-40FE-AA3D-6177EA401788}" /s /f
reg copy %search% %shell%{4DCAFE13-E6A7-4C28-BE02-CA8C2126280D}" /s /f
reg copy %search% %shell%{71689AC1-CC88-45D0-8A22-2943C3E7DFB3}" /s /f
reg copy %search% %shell%{EA25FBD7-3BF7-409E-B97F-3352240903F4}" /s /f
reg copy "HKEY_CURRENT_USER\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\Shell\Bags\AllFolders\Shell" "HKEY_CURRENT_USER\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\Shell\Bags\AllFolders\ComDlg" /s /f

:Reboot
title Start Explorer
start %windir%\explorer.exe
TIMEOUT /T 2 /NOBREAK >nul

title Rebooting...
SHUTDOWN -r -t 3
