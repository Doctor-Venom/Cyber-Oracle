import sys, os, traceback, types, logging, shutil


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


#NOTE: obfuscation and packing: pyarmor pack -e " -F --noconsole --icon icon.ico --key 8ayfoUASV93bASd --noupx --add-data './logo_YU2.png;.'" attendance_v1.py
#NOTE: https://stackoverflow.com/questions/64611207/pyinstaller-how-to-include-py-in-folder

def main():
    # ENVIRONMENT INITIALIZATION
    INSTALL_LOCATION = os.environ["ProgramFiles"]
    APP_NAME = 'Cyber_Oracle'
    logging.root.setLevel(logging.INFO)

    try:
        # copy the agent and settings file to app directory
        logging.info(f'[+] Deleting installation directory...')
        shutil.rmtree(f'{INSTALL_LOCATION}\\{APP_NAME}')
    except Exception as e:
        logging.warning(f'[+] failed to delete installation directory! ({e})')

    try:
        logging.info(f'[+] Deleting local user "CyberOracleAccount"...')
        os.system('net user /DELETE CyberOracleAccount')
    except Exception as e:
        logging.warning(f'[+] failed to delete "CyberOracleAccount" local account! ({e})')

    try:
        logging.info(f'[+] Deleting Scheduled Task for cyber oracle background service...')
        #cmd = f"Unregister-ScheduledTask -Confirm:$false -Taskpath '\\CyberOracle\\' -TaskName 'CyberOracleBackgroundService'"
        #os.system(f'powershell -Command "{cmd}"')
        #FIXME: powershell command doesnt work... the following command is a temporary solution
        os.system('SCHTASKS /Delete /F /TN "\\CyberOracle\\CyberOracleBackgroundService"')
    except Exception as e:
        logging.warning(f'[+] failed to delete scheduled task for cyber oracle background service! ({e})')


    logging.info(f'[+] Setup complete! Cyber Oracle Has Been Uninstalled Successfully.')




if __name__ == '__main__':
    run_as_admin(main)
