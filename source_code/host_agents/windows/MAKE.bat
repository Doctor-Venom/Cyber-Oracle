call pack_windows_host_agent.bat
call pack_windows_host_agent_installer.bat
call pack_windows_host_agent_uninstaller.bat

copy /Y .\windows_host_agent_installer.exe ..\..\central_monitor\media\windows_host_agent_installer.exe
copy /Y .\windows_host_agent_uninstaller.exe ..\..\central_monitor\media\windows_host_agent_uninstaller.exe

echo "MAKE SURE THAT THE COMPILED FILES HAVE BEEN COPIED INTO /media directory on the central monitor"
pause

