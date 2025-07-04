mode con:cols=50 lines=1

title Start work...
call :Clear>>Z:\Clear.log 2>&1
EXIT /b 0
:Clear

del /f /q Z:\InputSwitch.jpg

if exist Z:\boot.wim (
	title Mount boot.wim
	mkdir Z:\boot
	dism /mount-image /imagefile:Z:\boot.wim /index:2 /mountdir:Z:\boot
	
	title Load registry
	reg load HKEY_LOCAL_MACHINE\WIM_DEFAULT Z:\boot\Windows\System32\config\DEFAULT
	
	title Disable Mouse acceleration
	reg add "HKEY_LOCAL_MACHINE\WIM_DEFAULT\Control Panel\Mouse" /v MouseSpeed /t REG_DWORD /d 0 /f
	reg add "HKEY_LOCAL_MACHINE\WIM_DEFAULT\Control Panel\Mouse" /v MouseThreshold1 /t REG_DWORD /d 0 /f
	reg add "HKEY_LOCAL_MACHINE\WIM_DEFAULT\Control Panel\Mouse" /v MouseThreshold2 /t REG_DWORD /d 0 /f
	
	title Unload registry
	reg unload HKEY_LOCAL_MACHINE\WIM_DEFAULT
	
	title Unmount boot.wim
	dism /unmount-wim /mountdir:Z:\boot /commit
	
	title Compress boot.wim
	Z:\WimOptimize.exe Z:\boot.wim
)

title Applying _Clear.ps1
%windir%\System32\WindowsPowerShell\v1.0\Powershell.exe -executionpolicy bypass -File Z:\_Clear.ps1
del /f /q Z:\_Clear.ps1

title Load registry
reg load HKEY_LOCAL_MACHINE\WIM_SOFTWARE Z:\Install\Windows\System32\config\SOFTWARE
reg load HKEY_LOCAL_MACHINE\WIM_SYSTEM Z:\Install\Windows\System32\config\SYSTEM
reg load HKEY_LOCAL_MACHINE\WIM_CURRENT_USER Z:\Install\Users\Default\NTUSER.DAT

title Applying _Clear.reg
reg import Z:\_Clear.reg
del /f /q Z:\_Clear.reg

title Disable Secondary Logs
for /f "tokens=*" %%a in ('reg QUERY "HKEY_LOCAL_MACHINE\WIM_SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels"') do (
	reg add "%%a" /v Enabled /t REG_DWORD /d 0 /f
)

title Unload registry
reg unload HKEY_LOCAL_MACHINE\WIM_CURRENT_USER
reg unload HKEY_LOCAL_MACHINE\WIM_SYSTEM
reg unload HKEY_LOCAL_MACHINE\WIM_SOFTWARE

title Hide NTUSER.DAT
ATTRIB Z:\Install\Users\Default\NTUSER.DAT +S +H

title EdgeUpdate
mkdir "Z:\Install\Program Files (x86)\Microsoft\EdgeCore"
mkdir "Z:\Install\Program Files (x86)\Microsoft\EdgeWebView\Application"
rd /s /q "Z:\Install\Program Files (x86)\Microsoft\EdgeUpdate"
rd /s /q "Z:\Install\Program Files (x86)\Microsoft\Edge\Application\92.0.902.67\Installer"
del /f /q "Z:\Install\Program Files (x86)\Microsoft\Edge\Application\92.0.902.67\elevation_service.exe"
del /f /q "Z:\Install\Program Files (x86)\Microsoft\Edge\Application\92.0.902.67\notification_helper.exe"
del /f /q "Z:\Install\Program Files (x86)\Microsoft\Edge\Application\92.0.902.67\notification_helper.exe.manifest"

title Editing .dll`s
set DLLLIST=Z:\Install\Windows\System32\energyprov.dll Z:\Install\Windows\System32\umpoext.dll Z:\Install\Windows\System32\InputSwitch.dll Z:\Install\Windows\ImmersiveControlPanel\SystemSettings.dll
for %%a in (%DLLLIST%) do (
	takeown /f %%a
	icacls %%a /grant "%username%":f /c /l /q
)
Z:\PostClear\HelpTool.exe Z:\Install\Windows\System32\energyprov.dll "2E 00 65 00 74 00 6C 00" "2E 00 3F 00 3F 00 3F 00"
Z:\PostClear\HelpTool.exe Z:\Install\Windows\System32\umpoext.dll "2E 00 65 00 74 00 6C 00" "2E 00 3F 00 3F 00 3F 00" *
Z:\PostClear\HelpTool.exe Z:\Install\Windows\System32\InputSwitch.dll "48 63 D0 48 8D 0D 71 09 03 00 48 C1 E2 04 48 03 D1 48 8B CF 48 89 57 58 8B D0 E8 24 02 00 00" "90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90"
Z:\PostClear\HelpTool.exe Z:\Install\Windows\ImmersiveControlPanel\SystemSettings.dll "00 00 00 00 00 43 00 4E 00 00 00 00 00" "00 00 00 00 00 52 00 55 00 00 00 00 00"

title Add OneDrive
set DELETELIST=Z:\Install\Windows\SysWOW64\OneDriveSetup.exe Z:\Install\Windows\WinSxS\Manifests\amd64_microsoft-windows-onedrive-setup_31bf3856ad364e35_10.0.19041.1_none_db314eafc56dd1eb.manifest Z:\Install\Windows\WinSxS\Manifests\wow64_microsoft-windows-onedrive-setup_31bf3856ad364e35_10.0.19041.1_none_e585f901f9ce93e6.manifest Z:\Install\Windows\servicing\Packages\Microsoft-Windows-OneDrive-Setup-Package~31bf3856ad364e35~amd64~~10.0.19041.1.cat Z:\Install\Windows\servicing\Packages\Microsoft-Windows-OneDrive-Setup-Package~31bf3856ad364e35~amd64~~10.0.19041.1.mum Z:\Install\Windows\servicing\Packages\Microsoft-Windows-OneDrive-Setup-Package~31bf3856ad364e35~amd64~ru-RU~10.0.19041.1.cat Z:\Install\Windows\servicing\Packages\Microsoft-Windows-OneDrive-Setup-Package~31bf3856ad364e35~amd64~ru-RU~10.0.19041.1.mum Z:\Install\Windows\servicing\Packages\Microsoft-Windows-OneDrive-Setup-WOW64-Package~31bf3856ad364e35~amd64~~10.0.19041.1.cat Z:\Install\Windows\servicing\Packages\Microsoft-Windows-OneDrive-Setup-WOW64-Package~31bf3856ad364e35~amd64~~10.0.19041.1.mum Z:\Install\Windows\servicing\Packages\Microsoft-Windows-OneDrive-Setup-WOW64-Package~31bf3856ad364e35~amd64~ru-RU~10.0.19041.1.cat Z:\Install\Windows\servicing\Packages\Microsoft-Windows-OneDrive-Setup-WOW64-Package~31bf3856ad364e35~amd64~ru-RU~10.0.19041.1.mum Z:\Install\Windows\System32\CatRoot\{F750E6C3-38EE-11D1-85E5-00C04FC295EE}\Microsoft-Windows-OneDrive-Setup-Package~31bf3856ad364e35~amd64~~10.0.19041.1.cat Z:\Install\Windows\System32\CatRoot\{F750E6C3-38EE-11D1-85E5-00C04FC295EE}\Microsoft-Windows-OneDrive-Setup-Package~31bf3856ad364e35~amd64~ru-RU~10.0.19041.1.cat Z:\Install\Windows\System32\CatRoot\{F750E6C3-38EE-11D1-85E5-00C04FC295EE}\Microsoft-Windows-OneDrive-Setup-WOW64-Package~31bf3856ad364e35~amd64~~10.0.19041.1.cat Z:\Install\Windows\System32\CatRoot\{F750E6C3-38EE-11D1-85E5-00C04FC295EE}\Microsoft-Windows-OneDrive-Setup-WOW64-Package~31bf3856ad364e35~amd64~ru-RU~10.0.19041.1.cat Z:\Install\Windows\WinSxS\wow64_microsoft-windows-onedrive-setup_31bf3856ad364e35_10.0.19041.1_none_e585f901f9ce93e6
title Add Chromium
set DELETELIST=%DELETELIST% Z:\Install\Windows\WinSxS\Manifests\amd64_microsoft-windows-edgechromium_31bf3856ad364e35_10.0.19041.3636_none_7437336f112dbb3d.manifest Z:\Install\Windows\WinSxS\amd64_microsoft-windows-edgechromium_31bf3856ad364e35_10.0.19041.3636_none_7437336f112dbb3d
title Add WaaS
set DELETELIST=%DELETELIST% Z:\Install\Windows\WinSxS\FileMaps\$$_waas_services_ddfc4ae175ff1678.cdf-ms Z:\Install\Windows\WinSxS\FileMaps\$$_waas_tasks_0504086c7768f632.cdf-ms Z:\Install\Windows\WaaS\services Z:\Install\Windows\WaaS\tasks Z:\Install\Windows\WaaS
title Add UPFC
set DELETELIST=%DELETELIST% Z:\Install\Windows\WinSxS\Manifests\amd64_microsoft-windows-upfc_31bf3856ad364e35_10.0.19041.1_none_5d169326bbc0abdb.manifest Z:\Install\Windows\WinSxS\amd64_microsoft-windows-upfc_31bf3856ad364e35_10.0.19041.1_none_5d169326bbc0abdb
title Add Calc
set DELETELIST=%DELETELIST% Z:\Install\Windows\SysWOW64\calc.exe Z:\Install\Windows\WinSxS\Manifests\amd64_microsoft-windows-calc_31bf3856ad364e35_10.0.19041.1_none_5faf0ebeba197e78.manifest Z:\Install\Windows\WinSxS\Manifests\wow64_microsoft-windows-calc_31bf3856ad364e35_10.0.19041.1_none_6a03b910ee7a4073.manifest Z:\Install\Windows\WinSxS\amd64_microsoft-windows-calc_31bf3856ad364e35_10.0.19041.1_none_5faf0ebeba197e78 Z:\Install\Windows\WinSxS\wow64_microsoft-windows-calc_31bf3856ad364e35_10.0.19041.1_none_6a03b910ee7a4073
title Processing DELETELIST
for %%a in (%DELETELIST%) do (
	if exist %%a\ (
		Z:\PostClear\superUser64.exe /ws %windir%\System32\cmd.exe /c rd /s /q %%a
	) else (
		Z:\PostClear\superUser64.exe /ws %windir%\System32\cmd.exe /c del /f /q %%a
	)
)

title Add Replace files
Z:\PostClear\superUser64.exe /ws %windir%\System32\cmd.exe /c xcopy /e /y Z:\Replace Z:\Install\
rd /s /q Z:\Replace

title Restore ACL
set DLLLIST=%DLLLIST% Z:\Install\Windows\bcastdvr\KnownGameList.bin Z:\Install\Windows\Panther\unattend.xml Z:\Install\Windows\System32\calc.exe Z:\Install\Windows\System32\ru-RU\calc.exe.mui Z:\Install\Windows\System32\msconfig.exe Z:\Install\Windows\System32\ru-RU\msconfig.exe.mui Z:\Install\Windows\System32\taskmgr.exe Z:\Install\Windows\System32\ru-RU\taskmgr.exe.mui Z:\Install\Windows\System32\upfc.exe Z:\Install\Windows\SystemResources\imageres.dll.mun Z:\Install\Windows\SystemResources\DDORes.dll.mun Z:\Install\Windows\SystemResources\mmres.dll.mun Z:\Install\Windows\SystemResources\shell32.dll.mun
for %%a in (%DLLLIST%) do (
	%windir%\System32\WindowsPowerShell\v1.0\Powershell.exe -executionpolicy remotesigned -Command "& Get-Acl -Path Z:\Install\Windows\System32\control.exe | Set-Acl -Path %%a"
)

title Disable Appx Protect
%windir%\System32\WindowsPowerShell\v1.0\Powershell.exe -executionpolicy remotesigned -Command "& Get-Acl -Path Z:\Install\Windows | Set-Acl -Path 'Z:\Install\Program Files\WindowsApps'"

title Clear WinSxS Backup
for /f "tokens=*" %%i in ('dir Z:\Install\Windows\WinSxS\Backup /b /a:-d') do (
	Z:\PostClear\superUser64.exe /ws %windir%\System32\cmd.exe /c del /f /q "Z:\Install\Windows\WinSxS\Backup\%%~i"
)
move Z:\PostClear Z:\Install\ProgramData

title Compress Winre
Z:\WimOptimize.exe Z:\Install\Windows\System32\Recovery\Winre.wim
del /f /q Z:\WimOptimize.exe

title Unmounting
dism /unmount-wim /mountdir:Z:\Install /commit

title Done...
del /f /q Z:\Windows-10-DISM-Scripts.rar
del /f /q Z:\_Clear.bat
