rmdir /S /Q __pycache__
rmdir /S /Q build
rmdir /S /Q dist
del windows_installer.spec

for /f "delims=" %%a in ('openssl rand -hex 32') do @set KEY=%%a
pyinstaller --key %KEY% -F --noupx windows_host_agent_uninstaller.py
copy /Y .\dist\windows_host_agent_uninstaller.exe .\windows_host_agent_uninstaller.exe

rmdir /S /Q __pycache__
rmdir /S /Q build
rmdir /S /Q dist
del windows_host_agent_uninstaller.spec