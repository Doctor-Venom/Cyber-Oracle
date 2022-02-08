for /f "delims=" %%a in ('openssl rand -hex 32') do @set KEY=%%a

pyinstaller --key %KEY% -F --noupx --add-data "binaries_for_windows_host_agent_installer/python-3.8.5-amd64.exe;." --add-data "binaries_for_windows_host_agent_installer/vcredist_x86.exe;." --add-data "binaries_for_windows_host_agent_installer/npcap-1.00.exe;." --add-data "binaries_for_windows_host_agent_installer/windows_host_agent.exe;." windows_host_agent_installer.py

copy /Y .\dist\windows_host_agent_installer.exe .\windows_host_agent_installer.exe

rmdir /S /Q __pycache__
rmdir /S /Q build
rmdir /S /Q dist
del windows_host_agent_installer.spec