rd /s /q .\PEASS-ng

git clone https://github.com/carlospolop/PEASS-ng.git

copy /Y ".\PEASS-ng\winPEAS\winPEASexe\binaries\Obfuscated Releases\winPEASany.exe" .

REM upx -9 ".\winPEASany.exe"