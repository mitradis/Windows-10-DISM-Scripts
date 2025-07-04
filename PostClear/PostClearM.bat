title Applying PostClearM.reg
%programdata%\PostClear\superUser64.exe /ws %windir%\System32\reg.exe import %programdata%\PostClear\PostClearM.reg
del /f /q %programdata%\PostClear\PostClearM.reg

title WinTool processing
%programdata%\PostClear\WinTool.exe -setup=131071

title Deleting tasks
schtasks /delete /tn Microsoft\XblGameSave\XblGameSaveTask /f
schtasks /delete /tn "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /f
schtasks /delete /tn "Microsoft\Windows\Application Experience\PcaPatchDbTask" /f
schtasks /delete /tn "Microsoft\Windows\Application Experience\ProgramDataUpdater" /f
schtasks /delete /tn "Microsoft\Windows\Application Experience\StartupAppTask" /f
schtasks /delete /tn Microsoft\Windows\Autochk\Proxy /f
schtasks /delete /tn Microsoft\Windows\CloudExperienceHost\CreateObjectTask /f
schtasks /delete /tn "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /f
schtasks /delete /tn "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /f
schtasks /delete /tn Microsoft\Windows\Diagnosis\Scheduled /f
schtasks /delete /tn Microsoft\Windows\DiskCleanup\SilentCleanup /f
schtasks /delete /tn Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector /f
schtasks /delete /tn "Microsoft\Windows\ExploitGuard\ExploitGuard MDM policy Refresh" /f
schtasks /delete /tn Microsoft\Windows\Feedback\Siuf\DmClient /f
schtasks /delete /tn Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload /f
schtasks /delete /tn "Microsoft\Windows\FileHistory\File History (maintenance mode)" /f
schtasks /delete /tn Microsoft\Windows\Flighting\FeatureConfig\ReconcileFeatures /f
schtasks /delete /tn Microsoft\Windows\Flighting\FeatureConfig\UsageDataFlushing /f
schtasks /delete /tn Microsoft\Windows\Flighting\FeatureConfig\UsageDataReporting /f
schtasks /delete /tn Microsoft\Windows\Flighting\OneSettings\RefreshCache /f
schtasks /delete /tn Microsoft\Windows\HelloFace\FODCleanupTask /f
schtasks /delete /tn "Microsoft\Windows\International\Synchronize Language Settings" /f
schtasks /delete /tn Microsoft\Windows\LanguageComponentsInstaller\Installation /f
schtasks /delete /tn Microsoft\Windows\Maintenance\WinSAT /f
schtasks /delete /tn Microsoft\Windows\Maps\MapsToastTask /f
schtasks /delete /tn Microsoft\Windows\Maps\MapsUpdateTask /f
schtasks /delete /tn Microsoft\Windows\MemoryDiagnostic\ProcessMemoryDiagnosticEvents /f
schtasks /delete /tn Microsoft\Windows\MemoryDiagnostic\RunFullMemoryDiagnostic /f
schtasks /delete /tn Microsoft\Windows\NetTrace\GatherNetworkInfo /f
schtasks /delete /tn "Microsoft\Windows\Offline Files\Background Synchronization" /f
schtasks /delete /tn "Microsoft\Windows\Offline Files\Logon Synchronization" /f
schtasks /delete /tn Microsoft\Windows\PI\Sqm-Tasks /f
schtasks /delete /tn "Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem" /f
schtasks /delete /tn Microsoft\Windows\PushToInstall\LoginCheck /f
schtasks /delete /tn Microsoft\Windows\PushToInstall\Registration /f
schtasks /delete /tn Microsoft\Windows\Registry\RegIdleBackup /f
schtasks /delete /tn Microsoft\Windows\RetailDemo\CleanupOfflineContent /f
schtasks /delete /tn Microsoft\Windows\Setup\SetupCleanupTask /f
schtasks /delete /tn Microsoft\Windows\Shell\FamilySafetyMonitor /f
schtasks /delete /tn Microsoft\Windows\Shell\FamilySafetyRefreshTask /f
schtasks /delete /tn Microsoft\Windows\Shell\IndexerAutomaticMaintenance /f
schtasks /delete /tn Microsoft\Windows\Speech\SpeechModelDownloadTask /f
schtasks /delete /tn Microsoft\Windows\Sysmain\WsSwapAssessmentTask /f
schtasks /delete /tn Microsoft\Windows\SystemRestore\SR /f
schtasks /delete /tn "Microsoft\Windows\Time Synchronization\ForceSynchronizeTime" /f
schtasks /delete /tn "Microsoft\Windows\Time Synchronization\SynchronizeTime" /f
schtasks /delete /tn "Microsoft\Windows\Time Zone\SynchronizeTimeZone" /f
schtasks /delete /tn Microsoft\Windows\UNP\RunUpdateNotificationMgr /f
schtasks /delete /tn "Microsoft\Windows\User Profile Service\HiveUploadTask" /f
schtasks /delete /tn Microsoft\Windows\WaaSMedic\PerformRemediation /f
schtasks /delete /tn "Microsoft\Windows\Windows Error Reporting\QueueReporting" /f
schtasks /delete /tn "Microsoft\Windows\WindowsUpdate\Refresh Group Policy Cache" /f
schtasks /delete /tn "Microsoft\Windows\WindowsUpdate\Scheduled Start" /f
%programdata%\PostClear\superUser64.exe /ws %windir%\System32\schtasks.exe /delete /tn "Microsoft\Windows\UpdateOrchestrator\Report policies" /f
%programdata%\PostClear\superUser64.exe /ws %windir%\System32\schtasks.exe /delete /tn "Microsoft\Windows\UpdateOrchestrator\Start Oobe Expedite Work" /f
%programdata%\PostClear\superUser64.exe /ws %windir%\System32\schtasks.exe /delete /tn Microsoft\Windows\UpdateOrchestrator\StartOobeAppsScan_LicenseAccepted /f
%programdata%\PostClear\superUser64.exe /ws %windir%\System32\schtasks.exe /delete /tn Microsoft\Windows\UpdateOrchestrator\StartOobeAppsScanAfterUpdate /f
%programdata%\PostClear\superUser64.exe /ws %windir%\System32\schtasks.exe /delete /tn "Microsoft\Windows\UpdateOrchestrator\Schedule Scan" /f
%programdata%\PostClear\superUser64.exe /ws %windir%\System32\schtasks.exe /delete /tn "Microsoft\Windows\UpdateOrchestrator\Schedule Scan Static Task" /f
%programdata%\PostClear\superUser64.exe /ws %windir%\System32\schtasks.exe /delete /tn "Microsoft\Windows\UpdateOrchestrator\Schedule Work" /f
%programdata%\PostClear\superUser64.exe /ws %windir%\System32\schtasks.exe /delete /tn Microsoft\Windows\UpdateOrchestrator\UpdateModelTask /f
%programdata%\PostClear\superUser64.exe /ws %windir%\System32\schtasks.exe /delete /tn Microsoft\Windows\UpdateOrchestrator\USO_UxBroker /f
set BLOCKLIST=%windir%\System32\Tasks\Microsoft\Windows\UpdateOrchestrator %windir%\System32\Tasks\Microsoft\Windows\WaaSMedic "%windir%\System32\Tasks\Microsoft\Windows\Windows Defender" %windir%\System32\Tasks\Microsoft\Windows\WindowsUpdate
for %%a in (%BLOCKLIST%) do (
	takeown /f %%a
	icacls %%a /grant "%username%":f /c /l /q
	icacls %%a /deny "*S-1-1-0:(W,D,X,R,RX,M,F)" "*S-1-5-7:(W,D,X,R,RX,M,F)"
)

title Applying GroupPolicy
%programdata%\PostClear\LGPO.exe /m %programdata%\PostClear\GPM.pol
%programdata%\PostClear\LGPO.exe /u %programdata%\PostClear\GPU.pol
TIMEOUT /T 1 /NOBREAK >nul
del /f /q %programdata%\PostClear\GPM.pol
del /f /q %programdata%\PostClear\GPU.pol
del /f /q %programdata%\PostClear\LGPO.exe
gpupdate /force

title Stopping SuperFetch
net stop SysMain
TIMEOUT /T 1 /NOBREAK >nul

title Deleting SuperFetch cache
for /f "tokens=*" %%i in ('dir /b /s %windir%\Prefetch\*.pf') do (
	del /f /q "%%~i"
)

title Stopping WindowsSearch
net stop WSearch
TIMEOUT /T 1 /NOBREAK >nul

title Deleting WindowsSearch cache
rd /s /q %programdata%\Microsoft\Search

title Disable ReservedStorage
Dism /Online /Set-ReservedStorageState /State:Disabled

title Disable Hibernate and Standby
powercfg /hibernate off
powercfg /change monitor-timeout-ac 10
powercfg /change monitor-timeout-dc 5
powercfg /change standby-timeout-ac 0
powercfg /change standby-timeout-dc 0

title Remove protect
set KEYSLIST=Launcher.AllAppsDesktopApplication Launcher.Computer Launcher.DesktopPackagedApplication Launcher.ImmersiveApplication Launcher.SystemSettings IE.AssocFile.WEBSITE Microsoft.Website
for %%a in (%KEYSLIST%) do (
	reg export HKEY_CLASSES_ROOT\%%a\shellex\ContextMenuHandlers %programdata%\PostClear\_temp.reg /y
	%programdata%\PostClear\superUser64.exe /ws %windir%\System32\reg.exe delete HKEY_CLASSES_ROOT\%%a\shellex\ContextMenuHandlers /f
	%programdata%\PostClear\superUser64.exe /ws %programdata%\PostClear\HelpTool.exe HKC %%a\shellex "S-1-5-18|S-1-5-32-544|S-1-5-32-545"
	reg import %programdata%\PostClear\_temp.reg
	del /f /q %programdata%\PostClear\_temp.reg
)

title Remove protect
%programdata%\PostClear\superUser64.exe /ws %programdata%\PostClear\HelpTool.exe HKL SYSTEM\CurrentControlSet\Services\bam\State\UserSettings "S-1-5-18|S-1-5-32-544"
del /f /q %programdata%\PostClear\superUser64.exe

title Deleting Edge services
sc delete edgeupdate
sc delete edgeupdatem

title Edge location
mklink /j "%programfiles(x86)%\Microsoft\EdgeCore\92.0.902.67" "%programfiles(x86)%\Microsoft\Edge\Application\92.0.902.67"
mklink /j "%programfiles(x86)%\Microsoft\EdgeWebView\Application\92.0.902.67" "%programfiles(x86)%\Microsoft\Edge\Application\92.0.902.67"
reg add HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\{56EB18F8-B008-4CBD-B6D2-8C97FE7E9062} /v location /t REG_SZ /d "%programfiles(x86)%\Microsoft\Edge\Application"
reg add HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5} /v location /t REG_SZ /d "%programfiles(x86)%\Microsoft\EdgeWebView\Application"
reg add HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\ClientState\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5} /v EBWebView /t REG_SZ /d "%programfiles(x86)%\Microsoft\EdgeWebView\Application\92.0.902.67"
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Microsoft Edge" /v InstallLocation /t REG_SZ /d "%programfiles(x86)%\Microsoft\Edge\Application"
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Microsoft EdgeWebView" /v InstallLocation /t REG_SZ /d "%programfiles(x86)%\Microsoft\EdgeWebView\Application"

title Delete Temp folders
rd /s /q %systemdrive%\inetpub
rd /s /q %systemdrive%\PerfLogs
