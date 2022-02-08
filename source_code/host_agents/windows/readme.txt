the installer will setup the environment and install the agent on the system, so just compile and run the binary installer on the target system
the uninstaller will delete everything the installer created (except for installed programs [npcap, vcredist, python] and python packages because maybe other programs need them)

to get installer and uninstaller binaries run MAKE.bat which will first compile the agent, then the installer and finally the uninstaller