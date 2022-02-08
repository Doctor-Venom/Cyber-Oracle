import sys, os, traceback, types, logging


'''
the installer will run with admin priveleges to do the following:
    1.install python if it is not installed
    2.install glances and all its dependencies
    3.run visual studio 2013 redistributable installer
    4.run npcap installer
    5.copy windows agent to installation directory
    6.copy initial settings file to installation directory
    7.create a windows scheduled task that runs the agent as a background process on startup with system user priveleges
'''

#https://gist.github.com/sylvainpelissier/ff072a6759082590a4fe8f7e070a4952
def isUserAdmin():
    """@return: True if the current user is an 'Admin' whatever that means (root on Unix), otherwise False.
    Warning: The inner function fails unless you have Windows XP SP2 or higher. The failure causes a traceback to be printed and this function to return False.
    """
    if os.name == 'nt':
        import ctypes
        # WARNING: requires Windows XP SP2 or higher!
        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except:
            traceback.print_exc()
            logging.warning("Admin check failed, assuming not an admin.")
            return False
    else:
        # Check for root on Posix
        return os.getuid() == 0

def runAsAdmin(cmdLine=None, wait=True):
    """Attempt to relaunch the current script as an admin using the same command line parameters. 
    Pass cmdLine in to override and set a new command. 
    It must be a list of [command, arg1, arg2...] format.
    Set wait to False to avoid waiting for the sub-process to finish. 
    You will not be able to fetch the exit code of the process if wait is False.
    Returns the sub-process return code, unless wait is False in which case it returns None.
    @WARNING: this function only works on Windows.
    """

    if os.name != 'nt':
        raise RuntimeError("This function is only implemented on Windows.")
    
    try:
        import win32api, win32con, win32event, win32process # type: ignore
    except Exception as e:
        logging.warning(f'{e}')
        os.system('python -m pip pywin32')
        import win32api, win32con, win32event, win32process # type: ignore
    try:
        from win32com.shell.shell import ShellExecuteEx # type: ignore
        from win32com.shell import shellcon # type: ignore
    except:
        os.system('python -m pip install pywin32')
        from win32com.shell.shell import ShellExecuteEx # type: ignore
        from win32com.shell import shellcon # type: ignore
    
    python_exe = sys.executable

    if cmdLine is None:
        cmdLine = [python_exe] + sys.argv
    elif type(cmdLine) not in (types.TupleType,types.ListType):
        raise ValueError("cmdLine is not a sequence.")
    cmd = '"%s"' % (cmdLine[0],)
    # XXX TODO: isn't there a function or something we can call to massage command line params?
    params = " ".join(['"%s"' % (x,) for x in cmdLine[1:]])
    cmdDir = ''
    showCmd = win32con.SW_SHOWNORMAL
    lpVerb = 'runas'  # causes UAC elevation prompt.
    
    # print "Running", cmd, params

    # ShellExecute() doesn't seem to allow us to fetch the PID or handle
    # of the process, so we can't get anything useful from it. Therefore
    # the more complex ShellExecuteEx() must be used.

    # procHandle = win32api.ShellExecute(0, lpVerb, cmd, params, cmdDir, showCmd)

    try:
        procInfo = ShellExecuteEx(nShow=showCmd, fMask=shellcon.SEE_MASK_NOCLOSEPROCESS, lpVerb=lpVerb, lpFile=cmd, lpParameters=params)
    except:
        logging.error('USER DID NOT GRANT ADMIN PRIVELEGES - ACCESS DENIED.')
        return 1
    if wait:
        procHandle = procInfo['hProcess']    
        obj = win32event.WaitForSingleObject(procHandle, win32event.INFINITE)
        rc = win32process.GetExitCodeProcess(procHandle)
    else:
        rc = None

    return rc

def run_as_admin(function):
    """check if we're admin, and if not relaunch the script as admin.""",
    rc = 0
    if not isUserAdmin():
        logging.warning("Access Denied - Admin Priveleges Required.", os.getpid(), "params: ", sys.argv)
        rc = runAsAdmin()
        exit(0)
    else:
        #print("You are an admin!", os.getpid(), "params: ", sys.argv)
        function()
        rc = 0
    input('Press Enter to exit.')
    return rc

def download_file(url, filename):
    import shutil
    try: import urllib.request
    except:
        os.system('python -m pip install urllib')
        import urllib.request
    logging.info(f'[+] Downloading {filename}...')
    with urllib.request.urlopen(url) as response, open(filename, 'wb') as out_file:
        shutil.copyfileobj(response, out_file)
    logging.info(f'[+] {filename} downloaded.')

def resource_path(relative_path):
    #https://stackoverflow.com/questions/51060894/adding-a-data-file-in-pyinstaller-using-the-onefile-option
    """ Get absolute path to resource, works for dev and for PyInstaller """
    try:
        # PyInstaller creates a temp folder and stores path in _MEIPASS
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)

#NOTE: obfuscation and packing: pyarmor pack -e " -F --noconsole --icon icon.ico --key 8ayfoUASV93bASd --noupx --add-data './logo_YU2.png;.'" attendance_v1.py
#NOTE: https://stackoverflow.com/questions/64611207/pyinstaller-how-to-include-py-in-folder

def main():
    # ENVIRONMENT INITIALIZATION
    INSTALL_LOCATION = os.environ["ProgramFiles"]
    APP_NAME = 'Cyber_Oracle'
    SCRIPT_FILENAME = 'windows_host_agent.exe'
    SETTINGS_FILENAME = 'initial_host_settings.json'
    logging.root.setLevel(logging.INFO)
    try: os.mkdir(f'{INSTALL_LOCATION}\\{APP_NAME}')
    except: pass

    # IMPORTS
    import shutil

    # check if python is installed
    # python is required for [glances, download_file()]
    if shutil.which('python'): # shutil.which() returns the path to bin if the binary exists, and None if it doesnt
        logging.info(f'[+] PYTHON IS INSTALLED: {shutil.which("python")}')
    else:
        logging.error('[-] PYTHON IS NOT INSTALLED, STARTING PYTHON 3.8.5 INSTALLER...')
        python_installer_path = resource_path('python-3.8.5-amd64.exe')
        os.system(python_installer_path) # install python
        if not shutil.which('python'):# path will not be updated in a running program... hence the installer must be restarted, but if somehow magically it has been updated then continue execution
            logging.error('[-] Python is not found on the system... aborting installation')
            logging.info('[!] if you have just installed python, then just restart windows_host_agent_installer.exe')
            input('Press Enter to Continue...')
            exit(-1)
    
    # this is for the agent (NOTE: it is not required if the agent is statically compiled using pyinstaller)
    os.system('python -m pip install pycryptodome') 

    #download and install glances and its dependencies
    if shutil.which('glances') is None:
        logging.info(f'[+] Downloading and installing system monitoring tool.')
        os.system('python -m pip install glances[action,browser,cpuinfo,export,folders,gpu,graph,ip,raid,snmp,web,wifi]')
        os.system('python -m pip install windows-curses')
        os.system('python -m pip install bottle')
        logging.info('[+] system monitoring tool has been downloaded and installed.')
    
    # install visual studio 2013 runtime (required for nmap) 
    #TODO: check if already installed, and dont run the installer again
    logging.info(f'[+] Installing visual studio 2013 redistributable runtime.')
    vsc_redistributable_path = resource_path('vcredist_x86.exe')
    res = os.system(vsc_redistributable_path)
    if res != 0:
        logging.error(f'[+] visual studio 2013 redistributable runtime installation failed... aborting cyber oracle installation')
        input('Press Enter To Continue')
        exit(-1)
    logging.info(f'[+] visual studio 2013 redistributable runtime has been installed.')

    # install npcap (required for nmap) 
    #TODO: check if already installed, and dont run the installer again
    logging.info(f'[+] Installing Npcap.')
    npcap_path = resource_path('npcap-1.00.exe')
    res = os.system(npcap_path)
    if res != 0:
        logging.error(f'[+] Npcap installation failed... aborting cyber oracle installation')
        input('Press Enter To Continue')
        exit(-1)
    logging.info(f'[+] Npcap has been installed.')
    
    
    # copy the agent and settings file to app directory
    logging.info(f'[+] Copying agent files to installation directory...')
    windows_host_agent_path = resource_path(f'{SCRIPT_FILENAME}')
    os.system(f'copy /Y "{windows_host_agent_path}" "{INSTALL_LOCATION}\\{APP_NAME}\\{SCRIPT_FILENAME}"') # the agent is included in the installer binary
    os.system(f'copy /Y ".\\{SETTINGS_FILENAME}" "{INSTALL_LOCATION}\\{APP_NAME}\\{SETTINGS_FILENAME}"') # the settings file is not included in the installer binary, it is a separate file in the downloaded zip archive
    with open(f'{INSTALL_LOCATION}\\{APP_NAME}\\PYTHONPATH', 'wb') as f:
        f.write(shutil.which("python").encode())
    logging.info(f'[+] Agent and initial settings copied to installation directory.')
    
    logging.info(f'[+] creating local user "CyberOracleAccount" with normal user priveleges')
    os.system('net user /add CyberOracleAccount cybER0Rac13 /comment:"used to drop cyberoracle service perms" /passwordchg:no')
    logging.info(f'[+] "CyberOracleAccount" user created')

    logging.info(f'[+] Creating Scheduled Task To Run On Startup.') # this is the easy and not so good way, consider making a windows service instead see https://stackoverflow.com/questions/3582108/create-windows-service-from-executable
    # https://www.windowscentral.com/how-export-and-import-scheduled-tasks-windows-10#export_import_tasks_powershell_windows10
    cmd = f"Register-ScheduledTask -Force -Taskpath 'CyberOracle' -TaskName 'CyberOracleBackgroundService' -Description 'cyber oracle agent for collecting host data' -User 'NT AUTHORITY\SYSTEM' -Trigger (New-ScheduledTaskTrigger -AtStartup) -Action (New-ScheduledTaskAction -Execute '{INSTALL_LOCATION}\\{APP_NAME}\\{SCRIPT_FILENAME}') -RunLevel Highest -Settings (New-ScheduledTaskSettingsSet -DisallowHardTerminate -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -DontStopOnIdleEnd -ExecutionTimeLimit 0 -MultipleInstances IgnoreNew -Priority 7 -RestartCount 10 -RestartInterval (New-TimeSpan -Minutes 3))"
    os.system(f'powershell -Command "{cmd}"')
    #P = f"\\\"{INSTALL_LOCATION}\\{APP_NAME}\\{SCRIPT_FILENAME}\\\""
    #os.system(r'SCHTASKS /CREATE /F /RU "NT AUTHORITY\SYSTEM" /RL "HIGHEST" /SC ONSTART /TN "CyberOracle\BackgroundService" /TR ' + f'"{P}"') # https://stackoverflow.com/a/4439204
    logging.info('scheduled task created.')
    

    logging.info(f'[+] Setup complete! Cyber Oracle is ready for use. you can safely delete the installer and the settings file now.')
    x = input('Do You Want To Start Cyber Oracle Service Now?([Y]/N)').upper()
    if x != 'N':
        logging.warning('Starting Cyber Oracle Agent...')
        cmd="Start-ScheduledTask -TaskPath 'CyberOracle' -TaskName 'CyberOracleBackgroundService'"
        os.system(f'powershell -Command {cmd}')
        input('Press Enter To Close The Program.')
        exit(0)




if __name__ == '__main__':
    run_as_admin(main)
