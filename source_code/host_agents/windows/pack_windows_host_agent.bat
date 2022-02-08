for /f "delims=" %%a in ('openssl rand -hex 32') do @set KEY=%%a

pyinstaller --key %KEY% -F --noupx --add-data "binaries_for_windows_host_agent/nmap_utils;nmap_utils" --add-data "binaries_for_windows_host_agent/winPEASany.exe;." --add-data "binaries_for_windows_host_agent/PsExec64.exe;." windows_host_agent.py

copy /Y .\dist\windows_host_agent.exe .\binaries_for_windows_host_agent_installer

rmdir /S /Q __pycache__
rmdir /S /Q build
rmdir /S /Q dist
del windows_host_agent.spec