# key in the command below is generated with `openssl rand -hex 32`
# NOTE: PACK WITH: pyinstaller --key 8b54663ad18123f7533e392965b9e83792d33793e8df6b47ec906c5e8c9b8477 -F --noconsole --noupx --add-data "binaries_for_windows_host_agent/nmap_utils;nmap_utils" --add-data "binaries_for_windows_host_agent/winPEASany.exe;." windows_host_agent.py
import os
import sys
import functools
import subprocess # https://stackoverflow.com/questions/4760215/running-shell-command-and-capturing-the-output
import threading
import socket
import http.client
import json
import logging
import time
import base64
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes
import copy
import random
from typing import Final
import shutil
import signal
import tempfile

#################################### DATA PRESENTATION AND FORMATTING FUNCTIONS ###########################################╗
#region
def encode_data(data) -> str:
    try: return base64.b64encode(data.encode('utf-8')).decode('utf-8')
    except: return base64.b64encode(data).decode('utf-8')

def decode_data(data) -> str:
    return base64.b64decode(data).decode('utf-8')

def encrypt_data(data) -> str: # encrypts withh AES GCM given the key from the central monitor, you get they key after authentication with the central monitor through the API
    #return data #TODO: remove this line and implement this function properly
    # https://pycryptodome.readthedocs.io/en/latest/src/cipher/modern.html#gcm-mode
    #TODO: this is the last thing to be implemented
    def get_key():
        #get the encryption key from the central monitor
        pass
    #header = b"header" # the additional data part from the acronym AEAD (authenitcation encryption addditional data) that should be authenticated but doesnt require encryption, usually the header hence the var name
    try: data = data.encode('utf-8')
    except: pass
    key = get_key()
    cipher = AES.new(key, AES.MODE_GCM)
    #cipher.update(header)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    json_data = {
        'nonce' : encode_data(cipher.nonce), 
        #'header' : encode_data(header), 
        'ciphertext' : encode_data(ciphertext), 
        'tag' : encode_data(tag)
        }
    raw_data = json.dumps(json_data)
    return raw_data

def decrypt_data(raw_data) -> str:
    #return data#TODO: remove this line and implement this function properly
    def get_key():
        #get the encryption key from the central monitor
        pass
    try:
        json_data = json.loads(raw_data)
        for i in json_data.keys(): json_data[i] = decode_data(json_data[i])
        key = get_key()
        cipher = AES.new(key, AES.MODE_GCM, nonce=json_data['nonce'])
        #cipher.update(json_data['header'])
        plaintext = cipher.decrypt_and_verify(json_data['ciphertext'], json_data['tag'])
        return plaintext
    except (ValueError, KeyError):
        logging.error(f"Incorrect decryption: {raw_data}")
        return None
#endregion
###########################################################################################################################╝


################################################# DECORATORS ##############################################################╗
#region
def thread_spawn_daemon(func): # decorator for calling functions in a new thread
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        threading.Thread(target=func, args=args, kwargs=kwargs, daemon=True).start()
    return wrapper

def require_auth_token(func): # decorator to ensure api_auth_token is not null, and if it is then authenticate to the server to get it
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        global api_auth_token
        while api_auth_token == None:
            try:
                logging.warning('api authentication token is not available, attempting to authenticate..')
                conn = http.client.HTTPConnection(SETTINGS['CENTRAL_MONITOR_BASE_URL'])
                headers = {'Content-type': 'application/json'}
                json_data = json.dumps({'username':SETTINGS['AGENT_AUTH_USERNAME'], 'password':SETTINGS['AGENT_AUTH_PASSWORD']})
                conn.request('POST', '/api-token-auth/', json_data, headers)
                response = conn.getresponse()
                if response.getcode() == 200:
                    api_auth_token = json.loads(response.read().decode())['token']
                    logging.info('[200] authentication sucess, api token received')
            except: 
                time.sleep(60)
        func(*args, **kwargs)
    
    return wrapper
#endregion
###########################################################################################################################╝


############################################## UTILITY FUNCTIONS ##########################################################╗
#region
def calc_sha256_file_hash(filename) -> str:
    sha256_hash = hashlib.sha256()
    with open(filename,"rb") as f:
        # Read and update hash string value in blocks of 4K
        for byte_block in iter(lambda: f.read(4096),b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def verify_PDU_signature(signed_PDU): # returns true if the signatre is valid, returns false otherwise
    #TODO: not implemented yet
    signed_data, signature = signed_PDU[:-1], signed_PDU[-1]
    return True

def sign_PDU(PDU_to_be_signed): # returns the PDU with a signature added to it
    # TODO: not implemented yet
    PDU_to_be_signed.append('S1GN4TUR3')
    return PDU_to_be_signed

def update_settings():
    global SETTINGS
    with open(SETTINGS_FILE_PATH, 'w') as sf: sf.write(json.dumps(SETTINGS))

def get_central_monitor_ip():
    try: # if the CENTRAL_MONITOR_BASE_URL is and ip address then use it directly
        if ':' in SETTINGS['CENTRAL_MONITOR_BASE_URL']: cm_ip = SETTINGS['CENTRAL_MONITOR_BASE_URL'].split(':')[0]
        else: cm_ip = SETTINGS['CENTRAL_MONITOR_BASE_URL']
        socket.inet_aton(cm_ip) # checks for valid ip address string
    except socket.error: # if CENTRAL_MONITOR_BASE_URL is not an ip address, then nslookup it to get the ip
        try:
            if ':' in SETTINGS['CENTRAL_MONITOR_BASE_URL']: cm_ns = SETTINGS['CENTRAL_MONITOR_BASE_URL'].split(':')[0]
            else: cm_ns = SETTINGS['CENTRAL_MONITOR_BASE_URL']
            cm_ip = socket.gethostbyname(cm_ns)
        except:
            logging.error('Could not get central monitor IP... aborting the program')
            exit(-1)
    return cm_ip

@require_auth_token
def return_result_to_API(command_id, result):
    if result == None:
        return
    attribute = {
        2: 'program_info',
        3: 'process_info',
        4: 'password_info',
        5: 'privesc_info',
        8: 'system_info',
        9: 'network_info',
        10: 'nmap_info',
        11: 'eventlog_info',
        12: 'schedtask_info'
    }
    if command_id in [2,3,4,5,6,8,9,10,11,12]: # [0,1,6,7] dont return anything to the API
        conn = http.client.HTTPConnection(SETTINGS['CENTRAL_MONITOR_BASE_URL'])
        headers = {
            'Content-type' : 'application/json',
            'Authorization' : f'Token {api_auth_token}',
            'Connection' : 'close'
            }
        body= json.dumps({attribute[command_id] : result})
        conn.request("PATCH", f'/api/hosts/{host_id}/', body, headers) # NOTE: note the slash at the end, maybe APPEND_SLASH=False in your Django settings
        res = conn.getresponse()
        if res.getcode() == 200: logging.info(f'[200] request to update {attribute[command_id]} for host_id {host_id} was successful.')
        else: logging.error(f'[{res.getcode()}] failed to update {attribute[command_id]} for host_id {host_id}. REASON: {res.read().decode()}')
        conn.close()
    else: logging.error(f'unhandeled command {command_id} in return_result_to_API()')

@require_auth_token
def register_host():
    global api_auth_token
    set_host_ID_global_var()
    new_settings = copy.deepcopy(SETTINGS)
    registrar_user = new_settings['AGENT_AUTH_USERNAME']
    new_settings['REGISTERED'] = True
    new_settings['AGENT_AUTH_USERNAME'] = 'AGENT_'+SETTINGS['AGENT_ID']
    new_settings['AGENT_AUTH_PASSWORD'] = os.urandom(16).hex()
    conn = http.client.HTTPConnection(SETTINGS['CENTRAL_MONITOR_BASE_URL'])
    headers = {
        'Content-type': 'application/json',
        'Authorization': f'Token {api_auth_token}',
        'Connection' : 'close'
        }
    json_data = json.dumps({
        "host_os_type" : "Windows",
        "host_id" : host_id,
        "agent_id" : SETTINGS['AGENT_ID'],
        "settings" : new_settings,
        "program_info" : {"program_info":""},
        "process_info" : {"process_info":""},
        "password_info" : {"password_info":""},
        "privesc_info" : {"privesc_info":""},
        "exploit_info" : {"exploit_info":""},
        "system_info" : {"system_info":""},
        "network_info" : {"network_info":""},
        "nmap_info" : {"nmap_info":""},
        "eventlog_info" : {"eventlog_info":""},
        "schedtask_info" : {"schedtask_info":""},
    })
    conn.request('POST', '/api/hosts/', json_data, headers)
    response = conn.getresponse()
    conn.close()
    if response.getcode() == 201:
        SETTINGS['REGISTERED'] = True
        update_settings()
        logging.info(f'[201] host registered sucessfully with host_id {host_id} and agent_id {SETTINGS["AGENT_ID"]}')
        api_auth_token = None # this solved a bug: when registering the agent gets a token for registrar user, then when it actually sends patch requests, it uses the same token but it should authenticate as the agent user instead to have change_host permission
        alert = construct_alert(host_id, 3, "New host Registered.", f"""
        Host ID: {host_id}
        Registrar: {registrar_user}
        Host Owner: {SETTINGS['AGENT_AUTH_USERNAME']}""")
        COP_client(4, alert)
    else:
        logging.error(f'[{response.getcode()}] REGISTRATION FAILED! REASON: {response.read().decode()}. RETRYING AFTER 5 MINUTES...')
        time.sleep(300)
        register_host()

def get_next_PDU_ID():
    return str(time.time()).replace('.','')+str(random.getrandbits(32))

def resource_path(relative_path):
    #https://stackoverflow.com/questions/51060894/adding-a-data-file-in-pyinstaller-using-the-onefile-option
    """ Get absolute path to resource, works for dev and for PyInstaller """
    try: base_path = sys._MEIPASS # PyInstaller creates a temp folder and stores path in _MEIPASS
    except Exception: base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)

#endregion
###########################################################################################################################╝



######################################## INFORMATION GATHERING FUNCTIONS ##################################################╗
#region
def set_host_ID_global_var(): # https://stackoverflow.com/questions/37248381/how-to-generate-a-host-unique-id/41216264
    global host_id
    host_name = socket.gethostname() # https://stackoverflow.com/questions/799767/getting-name-of-windows-computer-running-python-script
    domain_name = socket.getfqdn().split(host_name, 1)[1].strip('.') # https://stackoverflow.com/questions/54325608/how-to-get-local-network-domain-name-in-python
    product_id = subprocess.run('wmic path win32_computersystemproduct get uuid', input=None , stdout=subprocess.PIPE, shell=True).stdout.decode().split('\n')[1].strip() # https://stackoverflow.com/questions/2461141/get-a-unique-computer-id-in-python-on-windows-and-linux
    host_id = f'WIN${host_name}${domain_name}${product_id}'
    logging.info(f'host id was set to {host_id}')

''' command ID = 1 ''' #FIXME: WTF ITS NOT WORKING
@thread_spawn_daemon
def get_shell(conn, addr): # this is by far the best shell i could make for windows cuz there is no pty here... i apologize for this shitcode, but i barely managed to handle it
    # TODO: consider using the ncat.exe that is included in the agent executable to get a shell, but this will be useful only if the i could open a real bash/cmd window on central monitor 
    # https://eli.thegreenplace.net/2017/interacting-with-a-long-running-child-process-in-python/
    #conn.sendall(b'Cyber Oracle Interactive Shell.\n\n')
    p = subprocess.Popen('cmd', stdout=subprocess.PIPE, stdin=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    logging.info(f'shell started')
    p.stdin.flush()
    p.stdin.write(('\r\nECHO END_OF_STDOUT\r\n').encode())
    p.stdin.flush()
    p.stdout.flush()
    
    #conn.settimeout(10800)
    while True: 
        while True:
            line = p.stdout.readline().decode()
            if 'END_OF_STDOUT' in line:
                line = p.stdout.readline()
                p.stdout.flush()
                conn.sendall(b'END_OF_STDOUT')
                break
            logging.info(f'shell line read and will be sent: "{line}"') # TODO: remove
            conn.sendall(line.encode())
        logging.info(f'reached END_OF_STDOUT.. now waiting for command')
        command = conn.recv(16384)
        #if command in  [b'\r\n', b'\n']: continue
        if command.decode().strip() in ['#TERMINATE#']:
            #conn.sendall(b'#SHELL_TERMINATED#\n')
            conn.close()
            p.terminate()
            logging.info('shell terminated')
            break
        p.stdin.flush()
        p.stdin.write(b'\r\n'+command+b'\r\n')
        p.stdin.flush()
        line = p.stdout.readline() # if fuked up, remove theis line
        line = p.stdout.readline() # if fuked up, remove theis line
        p.stdin.write(('\r\nECHO END_OF_STDOUT\r\n').encode())
        p.stdin.flush()
        logging.info(f'Command {command} issued by the central monitor with IP {addr} has been executed.')
       
''' command ID = 2 '''
def get_program_data():
    start_time = time.time()
    # COMMANDS TO COLLECT INFORMATION ABOUT PROGRAMS
    try:
        #result_programs_0 = subprocess.run('powershell -Command "Get-WmiObject -Class "Win32_Product""', input=None , stdout=subprocess.PIPE, shell=True) # this is very inefficient way (query inoptimizied) that only shows the software installed via windows installer (incomplete) (https://xkln.net/blog/please-stop-using-win32product-to-find-installed-software-alternatives-inside/)
        #result_programs_1 = subprocess.run('powershell -Command "Get-ItemProperty HKLM:\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate, UninstallString"', input=None , stdout=subprocess.PIPE, shell=True)
        #result_programs_2 = subprocess.run('reg query HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall /reg:32 /s', input=None , stdout=subprocess.PIPE, shell=True)
        #result_programs_3 = subprocess.run('reg query HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall /reg:64 /s', input=None , stdout=subprocess.PIPE, shell=True)
        #result_programs_4 = subprocess.run('wmic softwarefeature get *', input=None , stdout=subprocess.PIPE, shell=True)
        # instead of the above, i found a script that does a great job
        cmd=r'''# Check if running with Administrative privileges if required
    $RunningAsAdmin = (New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if ($RunningAsAdmin -eq $false) {
        Write-Error "Finding all user applications requires administrative privileges"
        break
    }

    # Empty array to store applications
    $Apps = @()
    $32BitPath = "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    $64BitPath = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"

    # Retreive globally insatlled applications
    #Write-Host "Processing global hive"
    $Apps += Get-ItemProperty "HKLM:\$32BitPath"
    $Apps += Get-ItemProperty "HKLM:\$64BitPath"

    # Retreive all user insatlled applications
    #Write-Host "Collecting hive data for all users"
    $AllProfiles = Get-CimInstance Win32_UserProfile | Select LocalPath, SID, Loaded, Special | Where {$_.SID -like "S-1-5-21-*"}
    $MountedProfiles = $AllProfiles | Where {$_.Loaded -eq $true}
    $UnmountedProfiles = $AllProfiles | Where {$_.Loaded -eq $false}

    #Write-Host "Processing mounted hives"
    $MountedProfiles | % {
        $Apps += Get-ItemProperty -Path "Registry::\HKEY_USERS\$($_.SID)\$32BitPath"
        $Apps += Get-ItemProperty -Path "Registry::\HKEY_USERS\$($_.SID)\$64BitPath"
    }

    #Write-Host "Processing unmounted hives"
    $UnmountedProfiles | % {

        $Hive = "$($_.LocalPath)\NTUSER.DAT"
        #Write-Host " -> Mounting hive at $Hive"

        if (Test-Path $Hive) {
        
            REG LOAD HKU\temp $Hive

            $Apps += Get-ItemProperty -Path "Registry::\HKEY_USERS\temp\$32BitPath"
            $Apps += Get-ItemProperty -Path "Registry::\HKEY_USERS\temp\$64BitPath"

            # Run manual GC to allow hive to be unmounted
            [GC]::Collect()
            [GC]::WaitForPendingFinalizers()
        
            REG UNLOAD HKU\temp

        } else {
            Write-Warning "Unable to access registry hive at $Hive"
        }
    }

    Write-Output $Apps | Select DisplayName, InstallLocation | ConvertTo-Csv'''.encode()
        result_programs_0 = subprocess.run('powershell', input=cmd , stdout=subprocess.PIPE, shell=True)
        assert(result_programs_0.returncode == 0)
        init_data = result_programs_0.stdout.decode().replace('\"','').split('\r\n')
        data=[]
        for i in init_data[13:-1]:
            data.append(i.split(','))
        data = {
            'program_info' : data,
            'fresh_info' : True
        }
        logging.info(f'retrived program data in {time.time()-start_time} seconds')
        return_result_to_API(2, data)
    except: 
        logging.warning(f'[-] failed to retrive program data.. the operation took {time.time()-start_time} seconds') # NOTE: maybe better to send cyber oracle error PDU 

''' command ID = 3 '''
def get_process_data():
    start_time = time.time()
    # COMMANDS TO COLLECT INFORMATION ABOUT PROCESSES
    try:
        # note that the following 2 commands are doing the same thing, but the first one is faster and better
        result_processes_0 = subprocess.run('powershell -Command "Get-Process * | Select-Object Path, ID | ConvertTo-Csv"', input=None , stdout=subprocess.PIPE, shell=True)
        ### result_processes_1 = subprocess.run('wmic process get ExecutablePath,ProcessID', input=None , stdout=subprocess.PIPE, shell=True)
        init_data = result_processes_0.stdout.decode().replace('\"', '')
        data = [] # [path, pid, sha256]
        for proc in init_data.split('\r\n')[2:]:
            proc_data = proc.split(',')
            if len(proc_data[0])>0:
                proc_data.append(calc_sha256_file_hash(proc_data[0]))
                data.append(proc_data)
        data = {
            'process_info' : data,
            'fresh_info' : True
        }
        logging.info(f'retrived process data in {time.time()-start_time} seconds')
        return_result_to_API(3, data)
    except:
        logging.warning(f'[-] failed to retrive process data.. the operation took {time.time()-start_time} seconds')

''' command ID = 4 '''
def get_passwd_data():
    start_time = time.time()
    # COMMANDS TO DUMP PASSWORD HASHES (https://pure.security/dumping-windows-credentials/)
    #TODO: if possible, use secretsdump on the host, because the data object returned by this function is 10MB+ in size
    try:
        result_passwd_0 = subprocess.run('mkdir temp', input=None , stdout=subprocess.PIPE, shell=True) 
        logging.info('temp directory created')
        result_passwd_1 = subprocess.run('reg.exe save hklm\\sam .\\temp\\sam.save && reg.exe save hklm\\security .\\temp\\security.save && reg.exe save hklm\\system .\\temp\\system.save', input=None , stdout=subprocess.PIPE, shell=True) #NOTE: requires admin priveleges
        logging.info('sam, security, system dumped')
        sam, security, system = open('./temp/sam.save', 'rb').read(), open('./temp/security.save', 'rb').read(), open('./temp/system.save', 'rb').read()
        logging.info('sam, security, system read into memory')
        #TODO(low priority): consider overwriting the file with /x00 before deleting it, so that it will be impossible to retrive it 
        os.system('del /f .\\temp\\sam.save')
        os.system('del /f .\\temp\\security.save')
        os.system('del /f .\\temp\\system.save')
        logging.info('sam, security, system deleted')
        logging.info('creating passwd data json object')
        data = {
            'password_info' : {
                'sam' : encode_data(sam),
                'security' : encode_data(security),
                'system' : encode_data(system)
                },
            'fresh_info' : True
            }
        logging.info('passwd data json object created, calling return_result_to_API() now')
        logging.info(f'retrived password data in {time.time()-start_time} seconds')
        return_result_to_API(4, data)
    except:
        logging.warning(f'[-] failed to retrive password data.. the operation took {time.time()-start_time} seconds')

''' command ID = 5 '''
def get_privesc_audit():
    start_time = time.time()
    #NOTE: this should be run as a basic user (not admin) to give useful results about privelege escalation
    try:
        # check the logged_in user and run with his priveleges
        #logged_in_user = subprocess.run('WMIC /NODE:127.0.0.1 COMPUTERSYSTEM GET USERNAME', stdout=subprocess.PIPE, stderr=subprocess.STDOUT).stdout.decode().split('\r\n')[-1]
        #assert('\\' in logged_in_user)
        #logged_in_user = logged_in_user.split('\\')[-1]
        # the password hash can be requested from central monitor and use pass the hash locally
        # damned psexec and powershell methods to runas spawn a new windows... i cant read its stdout. and using runas in cmd wont work because i cant supply the password
        # TODO(DONE): wait until they do https://github.com/carlospolop/PEASS-ng/issues/207 and then specify output file because there is no other way
        with tempfile.TemporaryDirectory() as tmpdir:
            result_filename = f'{tmpdir}\\privesc'
            result_filename = result_filename.replace('\\', '/')
            subprocess.run(f'"{resource_path("PsExec64.exe")}" -l -u CyberOracleAccount -p cybER0Rac13 -accepteula -nobanner ""{resource_path("winPEASany.exe")} -lolbas log="{result_filename}"""', input=None , stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True)
            with open(result_filename, 'r') as f: data = {'privesc_info': f.read(), 'fresh_info' : True}
            logging.info(f'[+] privesc audit completed successfully')
            logging.info(f'retrived privesc audit in {time.time()-start_time} seconds')
            return_result_to_API(5, data)
    except:
        logging.warning(f'[-] privesc audit failed to run as normal user.. the operation took {time.time()-start_time} seconds')

''' command ID = 7 '''
@thread_spawn_daemon
def run_system_monitor():
    try:
        global system_monitor_process, system_monitor_timer
        if system_monitor_process != None :
            logging.error('system monitor is already running, but a request to start it was received from the central monitror. starting another instance is not allowed.. request refused')
            return
        #TODO: addd --username and --password for security reasons after implementing encryption
        logging.info('system monitor is starting...')
        # FIXME: system monitor failed to run: [WinError 2] The system cannot find the file specified
        with open(f'{INSTALL_LOCATION}\\{APP_NAME}\\PYTHONPATH', 'rb') as f: PYTHONPATH = f.read().decode()
        system_monitor_process = subprocess.Popen(f'"{PYTHONPATH}" -m glances -w -p {SETTINGS.get("SYSTEM_MONITOR_PORT", 61337)}', stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        system_monitor_timer = time.time()
        logging.info('system monitor has started.')
        while True:
            if system_monitor_process != None and time.time() - system_monitor_timer >= system_monitor_timeout:
                system_monitor_process.kill()
                system_monitor_process = None
                system_monitor_timer = None
                logging.info('system monitor has terminated.')
                break
            time.sleep(1)
    except Exception as e: logging.error(f'system monitor failed to run: {e}')

''' command ID = 8 '''
def get_system_info():
    start_time = time.time()
    try:
        systeminfo_res = subprocess.run('systeminfo', input=None , stdout=subprocess.PIPE, shell=True) 
        data = {
            'system_info' : systeminfo_res.stdout.decode(),
            'fresh_info' : True
        }
        logging.info(f'retrived system info in {time.time()-start_time} seconds')
        return_result_to_API(8, data)
    except:
        logging.warning(f'[-] failed to retrive system info.. the operation took {time.time()-start_time} seconds')

''' command ID = 9 '''
def get_network_information():
    start_time = time.time()
    def get_all_local_macs():
        getmac_res = subprocess.run('getmac', input=None , stdout=subprocess.PIPE, shell=True) 
        return getmac_res.stdout

    def get_ip_info():
        ipconfig_res = subprocess.run('ipconfig /all', input=None , stdout=subprocess.PIPE, shell=True) 
        return ipconfig_res.stdout

    def get_dns_cache():
        ipconfig_res = subprocess.run('ipconfig /displaydns', input=None , stdout=subprocess.PIPE, shell=True) 
        return ipconfig_res.stdout

    def get_arp_cache():
        arp_res = subprocess.run('arp -a', input=None , stdout=subprocess.PIPE, shell=True) 
        return arp_res.stdout
    
    def get_routing_table():
        netstat_res = subprocess.run('netstat -r', input=None , stdout=subprocess.PIPE, shell=True) 
        return netstat_res.stdout

    def get_active_ports():
        netstat_res = subprocess.run('netstat -nobaq', input=None , stdout=subprocess.PIPE, shell=True) 
        return netstat_res.stdout
    
    try:
        data = {
            'network_info': {
                'all_local_mac_addresses' : get_all_local_macs().decode(),
                'ip_info' : get_ip_info().decode(),
                'dns_cache' : get_dns_cache().decode(),
                'arp_cache' : get_arp_cache().decode(),
                'routing_table' : get_routing_table().decode(),
                'active_ports' : get_active_ports().decode()
                },
        'fresh_info' : True
        }
        logging.info(f'retrived network info in {time.time()-start_time} seconds')
        return_result_to_API(9, data)
    except:
        logging.warning(f'[-] failed to retrive network information.. the operation took {time.time()-start_time} seconds')

''' command ID = 10 '''
def run_network_mapper():
    start_time = time.time()
    try:
        all_local_ips = subprocess.run('ipconfig /all', input=None , stdout=subprocess.PIPE, shell=True).stdout.decode().split('\r\n')
        ipv4s=[]
        netmasks=[]
        for i in all_local_ips:
            if 'IPv4 Address' in i: ipv4s.append(i.split()[-1].strip('(Preferred)').strip())
            elif 'Subnet Mask' in i: netmasks.append(sum(bin(int(x)).count('1') for x in (i.split()[-1].strip()).split('.')))
        interfaces = list(zip(ipv4s,netmasks))
        scans_results={}
        for interface in interfaces:
            # -Pn will show hosts that dont respond to ping, but still available on the network, but it considerably slows down the scan, hence i decided not to use it
            # TODO: consider returning html output instead (https://nmap.org/book/output-formats-output-to-html.html)
            # NOTE: excluding port 51337 so that agents dont send alerts to central monitor when a connection attempt is made on that port, but this will allow adversaries to be invisible on the network map if they have only port 51337 running
            proc = subprocess.Popen(f'{resource_path("nmap_utils/nmap.exe")} -sn -PS -PU -PY -PA -PE -PP -PM --traceroute --privileged --exclude-ports 51337 --exclude {get_central_monitor_ip()} {interface[0]}/{interface[1]}', stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True)
            try: stdout, stderr = proc.communicate(timeout=3600)
            except subprocess.TimeoutExpired:
                proc.kill()
                stdout, stderr = proc.communicate()
            scans_results[f'{interface[0]}/{interface[1]}'] = stdout.decode()
        data = {
            'nmap_info' : scans_results,
            'fresh_info' : True
        }
        logging.info(f'retrived network mapping in {time.time()-start_time} seconds')
        return_result_to_API(10, data)
    except:
        logging.warning(f'[-] failed to retrive network mapping information.. the operation took {time.time()-start_time} seconds')

''' command ID = 11 '''
def run_eventlog_collector():# must be invoked every 10 minutes to collect all logs
    start_time = time.time()
    try:
        proc_res = subprocess.run('powershell -Command "Get-WinEvent -ListLog * | ForEach-Object{ Get-WinEvent -ErrorAction SilentlyContinue -FilterHashTable @{LogName=$_.Logname; Level=1,2,3,4; StartTime=(Get-Date).AddSeconds(-600)}} | Select-Object TimeCreated,LogName,ProviderName,Id,LevelDisplayName | Sort TimeCreated | ConvertTo-Csv -Delimiter \'|\'"', input=None , stdout=subprocess.PIPE, shell=True)
        data = {
            'eventlog_info' : proc_res.stdout.decode(),
            'fresh_info' : True
            }
        logging.info(f'retrived event logs in {time.time()-start_time} seconds')
        return_result_to_API(11, data)
    except:
        logging.warning(f'[-] failed to retrive event log data.. the operation took {time.time()-start_time} seconds')

''' command ID = 12 '''
def get_scheduled_tasks():
    start_time = time.time()
    try:
        proc_res = subprocess.run('powershell -Command "Get-ScheduledTask | ConvertTo-Csv -Delimiter \'|\'"', input=None , stdout=subprocess.PIPE, shell=True)
        data = {
            'schedtask_info' : proc_res.stdout.decode(),
            'fresh_info' : True
            }
        logging.info(f'retrived scheduled tasks in {time.time()-start_time} seconds')
        return_result_to_API(12, data)
    except:
        logging.warning(f'[-] failed to retrive scheduled tasks information.. the operation took {time.time()-start_time} seconds')

@thread_spawn_daemon
def decoy_process(): # https://github.com/hposton/python-for-cybersecurity/blob/main/Part_15/15.1_Decoy_Process/DecoyProcess.py
    def handler(signum,frame):
        alert = construct_alert(host_id, 6, "an attempt was made to kill the agent", f"""
        signum: {signum}
        Not that much information available on windows.""")
        COP_client(4, alert)

    signal.signal(signal.SIGTERM, handler)
    signal.signal(signal.SIGINT, handler)
    while True:
        # unfortunately, on windows we cant get the info about the process that sent the signal 
        #siginfo = signal.sigwaitinfo({signal.SIGINT,signal.SIGTERM})
        time.sleep(1)

def network_honeypot(): # https://github.com/hposton/python-for-cybersecurity/blob/main/Part_16/16.1_PCAP_Collection/PCAPCollection.py and https://github.com/OWASP/Python-Honeypot/blob/master/core/network.py
    pass

@thread_spawn_daemon
def port_honeypot(): # TODO: get honeypot port number from settings, the user should be able to set these ports on the central monitor
    global SETTINGS

    @thread_spawn_daemon
    def open_TCP_port(port_num): # opens the port for 1 minute and closes
        port_num=int(port_num)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as hs:
            hs.bind(('0.0.0.0', port_num))
            hs.settimeout(60)
            hs.listen()
            try:
                conn, addr = hs.accept()
                alert = construct_alert(host_id, 4, "A connection was attempted on a honeypot port.", f"""
                Honeypor port number: {port_num} TCP
                Connection information: {addr}
                    """)
                COP_client(4, alert)
                conn.settimeout(3)
                conn.sendall(b'The hacker has been caught like an animal xD')
            except: pass

    @thread_spawn_daemon
    def open_UDP_port(port_num): # opens the port for 1 minute and closes
        port_num=int(port_num)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as hs:
            hs.bind(('0.0.0.0', port_num))
            hs.settimeout(60)
            try:
                data, addr = hs.recvfrom(1024)
                print(data, addr)
                alert = construct_alert(host_id, 4, "A connection was attempted on a honeypot port.", f"""
                Honeypor port number: {port_num} UDP
                Connection information: {addr}
                Received Data on port: {data}
                    """)
                COP_client(4, alert)
                hs.settimeout(3)
                hs.sendto(b'The hacker has been caught like an animal xD', addr)
            except: pass

    TCP_ports = SETTINGS.get("TCP_HONEYPOT_PORTS", [])
    UDP_ports = SETTINGS.get("UDP_HONEYPOT_PORTS", [])
    while True:
        for port_num in TCP_ports: open_TCP_port(port_num)
        for port_num in UDP_ports: open_UDP_port(port_num)
        time.sleep(60)

        

#endregion
###########################################################################################################################╝



################################################## CYBER ORACLE PROTOCOL ##################################################╗
#region
@thread_spawn_daemon
def AGENT_COP_server(): # listen for connecction from central monitor
    def connection_handler(conn, addr): # receive commands/requests from the central monitor  (TODO: add some kind of verification so than only the CM is allowed to use this)
        with conn:
            logging.info(f'{addr} connected to the socket server.')
            while True:
                try: PDU = conn.recv(16384) # timeout is set to 1800 seconds, if nothing received during that time, the connection will be closed
                except: break
                if AGENT_COP_PDU_handler(PDU, conn, addr): break # if AGENT_COP_PDU_handler() returned True, then error occured, hence close connection
    
    global ip_history

    HOST = '0.0.0.0'    # listen for connections on all interfaces
    PORT = 51337        # Port to listen on (non-privileged ports are > 1023)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        logging.info(f'Cyber Oracle protocol server started on {HOST}:{PORT}')
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))# bind host address and port together
        s.listen(1)# configure how many client the server can listen simultaneously (assuming that only one central monitor exists, then this should be 1)
        while True:
            conn, addr = s.accept()# Establish connection with client.
            conn.settimeout(1800)
            logging.info(f'[+] new connection from {addr}.')
            ip_history.append((time.time(), addr))
            #NOTE & TODO: because we know the real ip address of the central monitor, we can reject all connections from other ip addresses, but we can also accept connections and report all communications to the central monitor
            threading.Thread(target=connection_handler, args=(conn, addr)).start() # start connection handler in a new thread

@thread_spawn_daemon
def COP_client(payload_type, payload):
    cm_ip = get_central_monitor_ip()
    cm_port = 51337
    PDU = construct_COP_PDU(payload_type, payload)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as conn:
        conn.settimeout(300) # 5 minutes # TODO: set back to 300 seconds
        conn.connect((cm_ip, cm_port))
        addr = conn.getpeername()
        conn.sendall(PDU)
        response_PDU = conn.recv(16384)
        AGENT_COP_PDU_handler(response_PDU, conn, addr)

def construct_COP_PDU(payload_type, payload):
    protocol_version = 1
    PDU_ID = get_next_PDU_ID()
    timestamp = time.time()
    PDU = [protocol_version, PDU_ID, timestamp, payload_type, payload]
    PDU = sign_PDU(PDU)
    PDU = json.dumps(PDU).encode()
    return PDU

def AGENT_COP_PDU_handler(PDU, conn, addr):
    global PDU_history, central_monitor_online, central_monitor_last_online, SETTINGS, system_monitor_process, system_monitor_timer, last_system_info_update, last_network_information_update, last_scheduled_tasks_update, last_event_logs_update, last_process_data_update, last_program_data_update, last_privesc_audit_update, last_network_mapper_update, last_passwd_data_update
    if not PDU_history.get(addr, None): PDU_history[addr] = []
    protocol_role: Final = 0 # agent
    PDU = json.loads(PDU.decode())
    protocol_version, PDU_ID, timestamp, payload_type, payload, signature = PDU
    
    assert(protocol_version == 1)
    if PDU_ID in [i[0] for i in PDU_history[addr]]: # NOTE: this is too expensive to compute, is it worth of it?
        alert = construct_alert(host_id, 6, "Host Agent received COP PDU with previously used PDU_ID.", f"""
        Received COP PDU contents:
            protocol_version    : {protocol_version}
            PDU_ID              : {PDU_ID}
            timestamp           : {timestamp}
            payload_type        : {payload_type}
            payload             : {payload}
            signature           : {signature}
        Sender information:
            {addr}
            """)
        COP_client(4, alert)
        return True
    PDU_history[addr].append((PDU_ID, timestamp)) 
    if -60 >= time.time() - int(timestamp) >= 60: # +- 60 seconds
        alert = construct_alert(host_id, 6, "Host Agent received COP PDU with expired timestamp.", f"""
        Received COP PDU contents:
            protocol_version    : {protocol_version}
            PDU_ID              : {PDU_ID}
            timestamp           : {timestamp}
            payload_type        : {payload_type}
            payload             : {payload}
            signature           : {signature}
        Sender information:
            {addr}
            """)
        COP_client(4, alert)
        return True
    if not verify_PDU_signature(PDU):
        alert = construct_alert(host_id, 6, "Host Agent received COP PDU with invalid signature.", f"""
        Received COP PDU contents:
            protocol_version    : {protocol_version}
            PDU_ID              : {PDU_ID}
            timestamp           : {timestamp}
            payload_type        : {payload_type}
            payload             : {payload}
            signature           : {signature}
        Sender information:
            {addr}
            """)
        COP_client(4, alert)
        return True
    if addr[0] != get_central_monitor_ip():
        alert = construct_alert(host_id, 6, "Host Agent received COP PDU from ip address that does not belon to the central monitor.", f"""
        Received COP PDU contents:
            protocol_version    : {protocol_version}
            PDU_ID              : {PDU_ID}
            timestamp           : {timestamp}
            payload_type        : {payload_type}
            payload             : {payload}
            signature           : {signature}
        Sender information:
            {addr}
            """)
        COP_client(4, alert)
        return True

    if payload_type == 0:#keepalive
        code = payload['code']
        if code == 0: # general keepalive echo
            # not implemented on controller, because controller sends only keepalive echo, and agents only send keepalive replys
            if protocol_role == 0:
                if central_monitor_online == False:
                    logging.info('central monitor status: ONLINE.')
                    central_monitor_online = True
                central_monitor_last_online = time.time()
                logging.info(f'received keepalive echo from {addr}, it is assumed that this ip address belongs to the central monitor ({SETTINGS["CENTRAL_MONITOR_BASE_URL"]}), but is it??.')
                payload_type = 0
                payload = {'code': 1, 'host': host_id}
                PDU=construct_COP_PDU(payload_type, payload)
                conn.sendall(PDU)
                conn.close()
        elif code == 1:
            if protocol_role == 0:
                logging.info(f'received keepalive echo reply from {addr}, it is assumed that this ip address belongs to the central monitor ({SETTINGS["CENTRAL_MONITOR_BASE_URL"]}), but is it??.')
                central_monitor_last_online = time.time()
                if central_monitor_online == False:
                    logging.info('central monitor status: ONLINE.')
                    central_monitor_online = True
                conn.close()
        elif code == 2: # keep system monitor running for more 5 minutes
            if protocol_role == 0: # not implemented on controller because only agents run the system monitor
                logging.info(f'received keepalive keepup from {addr}, system monitor termination countdown was reset to 5 minutes')
                if system_monitor_process != None and system_monitor_timer != None: system_monitor_timer = time.time()
                else: run_system_monitor()
        elif code == 3: # terminate system monitor
            if protocol_role == 0: # not implemented on controller because only agents run the system monitor
                logging.info(f'received system monitor termination request from {addr}, system monitor will be terminated now')
                try:
                    system_monitor_process.kill()
                    system_monitor_process = None
                    system_monitor_timer = None
                except: pass
    elif payload_type == 1:#command
        if protocol_role == 0: # only agents should receive command and process it
            command_id = int(payload['command_id'])
            alert = construct_alert(host_id, 5 if command_id == 1 else 1, "Command received thorugh Cyberoracle protocol", f"""
            Received COP PDU contents:
                protocol_version    : {protocol_version}
                PDU_ID              : {PDU_ID}
                timestamp           : {timestamp}
                payload_type        : {payload_type}
                payload             : {payload}
                signature           : {signature}
            Sender information:
                {addr}
                """)
            COP_client(4, alert)
            if command_id == 1:   logging.info('command received from central monitor to start get_shell()')                    ; threading.Thread(target=get_shell, args=(conn, addr), daemon=True).start() # provide an interactive shell
            elif command_id == 2: logging.info('command received from central monitor to start get_program_data()')             ; get_program_data()               ; last_program_data_update = time.time()            ; conn.close()
            elif command_id == 3: logging.info('command received from central monitor to start get_process_data()')             ; get_process_data()               ; last_process_data_update = time.time()            ; conn.close()
            elif command_id == 4: logging.info('command received from central monitor to start get_passwd_data()')              ; get_passwd_data()                ; last_passwd_data_update = time.time()             ; conn.close()
            elif command_id == 5: logging.info('command received from central monitor to start get_privesc_audit()')            ; get_privesc_audit()              ; last_privesc_audit_update = time.time()           ; conn.close()
            elif command_id == 6: None # get_exploit_suggest() NOTE: DEPRECATED
            elif command_id == 7: logging.info('command received from central monitor to start run_system_monitor()')           ; run_system_monitor()
            elif command_id == 8: logging.info('command received from central monitor to start get_system_info()')              ; get_system_info()                ; last_system_info_update = time.time()             ; conn.close()
            elif command_id == 9: logging.info('command received from central monitor to start get_network_information()')      ; get_network_information()        ; last_network_information_update = time.time()     ; conn.close()
            elif command_id == 10: logging.info('command received from central monitor to start run_network_mapper()')          ; run_network_mapper()             ; last_network_mapper_update = time.time()          ; conn.close()
            elif command_id == 11: logging.info('command received from central monitor to start run_eventlog_collector()')      ; run_eventlog_collector()         ; last_event_logs_update = time.time()              ; conn.close()
            elif command_id == 12: logging.info('command received from central monitor to start get_scheduled_tasks()')         ; get_scheduled_tasks()            ; last_scheduled_tasks_update = time.time()         ; conn.close()
    elif payload_type == 2:#settings
        action = payload['action']
        if action == 1: #settings reply
            if protocol_role == 0: # only agents should receive settings reply and process it
                alert = construct_alert(host_id, 0, "Received settings update through Cyberoracle protocol", f"""
                Received COP PDU contents:
                    protocol_version    : {protocol_version}
                    PDU_ID              : {PDU_ID}
                    timestamp           : {timestamp}
                    payload_type        : {payload_type}
                    payload             : {payload}
                    signature           : {signature}
                Sender information:
                    {addr}
                    """)
                COP_client(4, alert)
                SETTINGS = payload['settings']
                update_settings()
            conn.close()
    elif payload_type == 3:#authenticate
        action = payload['action']
        if action == 0: # authentication request
            # TODO: not implemented yet
            pass
        elif action == 1: # authentication response
            # TODO: not implemented yet
            pass
    else:#error (not handeled PDU)
        #TODO: not implemented yet - return error code to the sender
        error_code = payload['error_code']
        pass

def construct_alert(source_id, severity_score, general_info, detail_info):
    return {
        'source_id' : source_id,
        'severity_score' : severity_score,
        'data' : {
            'general_info' : general_info,
            'detail_info' : detail_info,
        }
    }

#endregion
###########################################################################################################################╝



#################################################### GLOBAL CONSTANTS #####################################################╗
#region
INSTALL_LOCATION = os.environ["ProgramFiles"]
APP_NAME = 'Cyber_Oracle'
SETTINGS_FILE_PATH = f'{INSTALL_LOCATION}\\{APP_NAME}\\initial_host_settings.json'
try:
    with open(SETTINGS_FILE_PATH, 'r') as sf:
        SETTINGS = json.loads(sf.read())
        update_settings()
except:
    logging.error('settings file not found, or no permission to read it... failed to initialize, aborting.')
    exit(-1)
#endregion
###########################################################################################################################╝

################################################ GLOBAL VARIABLES #########################################################╗
#region
host_id = None
api_auth_token = None
system_monitor_process = None
system_monitor_timer = None # 5 minutes idle (nothing received from the central monitor) will terminate the system monitor
system_monitor_timeout = 300
central_monitor_online = False
central_monitor_last_online = 0
ip_history = []
PDU_history = {}

#TODO: for now all updates are done on regular basis, consider adding triggers or something better to keep the data up to date and be efficient (like sending updates only when certain data was changed)
last_network_information_update = 0
last_event_logs_update = 0
last_process_data_update = 0
last_network_mapper_update = 0
last_system_info_update = 0
last_program_data_update = 0
last_scheduled_tasks_update = 0
last_passwd_data_update = 0
last_privesc_audit_update = 0
#last_exploit_suggest_update = 0
#endregion
###########################################################################################################################╝

############################################### LOGGING CONFIGURATION #####################################################╗
#region
# TODO: https://stackoverflow.com/questions/24505145/how-to-limit-log-file-size-in-python
logfile_path = f'{INSTALL_LOCATION}\\{APP_NAME}\\logs.txt'
logging.basicConfig(filename=logfile_path, filemode='a', format='[%(asctime)s] - %(levelname)s - %(funcName)s - (%(thread)d) : %(message)s')
logging.root.setLevel(logging.INFO)
#endregion
###########################################################################################################################╝





def main():
    global central_monitor_online, central_monitor_last_online, host_id, last_network_information_update, last_event_logs_update, last_process_data_update, last_network_mapper_update, last_system_info_update, last_program_data_update, last_scheduled_tasks_update, last_passwd_data_update, last_privesc_audit_update
    set_host_ID_global_var()
    AGENT_COP_server() # start socket server in a daemon thread to enable the communication using cyber oracle protocol
    logging.warning('waiting for central monitor to become online before starting.')
    while central_monitor_online == False:
        COP_client(payload_type=0, payload={'code': 0, 'host_id': "NOT_REGISTRED_YET"}) # NOTE at this time the host may not be registered, seding the host ID is just to follow the protocol
        time.sleep(5)
    
    # tun decoys and honeypots
    decoy_process()
    network_honeypot()
    port_honeypot()

    if SETTINGS['REGISTERED'] == False: register_host() # if not registered, then it is the first time this agent is launched, hence perform registration pprocess and get settings from central monitor
    COP_client(payload_type=2, payload={'action' : 0, 'host_id' : host_id}) # send COP PDU of type settings request to get the settings from the CM

    logging.info('initialization complete. entering normal flow.')
    
    # NOTE: if the *_UPDATES_FREQ is set to 10**8 it will only run once (at least once every 1157 days), if it is set to 10**10 it will never run 
    # TODO: WTF why there were 100500 child processes running and taking 100% CPU and couple gigas of RAM???? 
    while not time.sleep(1):
        current_time = time.time()
        if int(current_time)%10 == 0: COP_client(payload_type=0, payload={'code': 0, 'host_id': host_id}) # send keepalive echo request to the CM (if CM is online it will respond with a reply and central_monitor_last_online will be updated)
        if central_monitor_online and current_time - central_monitor_last_online >= 180: central_monitor_online = False ; logging.warning('central monitor status: OFFLINE.')
        if central_monitor_online == False: continue
        if current_time - last_system_info_update >= int(SETTINGS.get('SYSTEM_INFO_UPDATES_FREQ', float('inf'))):              get_system_info()           ; last_system_info_update = current_time           ; logging.info('get_system_info() finished execution')
        if current_time - last_network_information_update >= int(SETTINGS.get('NETWORK_INFO_UPDATES_FREQ', float('inf'))):     get_network_information()   ; last_network_information_update = current_time   ; logging.info('get_network_information() finished execution')
        if current_time - last_scheduled_tasks_update >= int(SETTINGS.get('SCHEDULED_TASKS_UPDATES_FREQ', float('inf'))):      get_scheduled_tasks()       ; last_scheduled_tasks_update = current_time       ; logging.info('get_scheduled_tasks() finished execution')
        if current_time - last_event_logs_update >= int(SETTINGS.get('EVENT_LOGS_UPDATES_FREQ', float('inf'))):                run_eventlog_collector()    ; last_event_logs_update = current_time            ; logging.info('run_eventlog_collector() finished execution')
        if current_time - last_process_data_update >= int(SETTINGS.get('PROC_DATA_UPDATES_FREQ', float('inf'))):               get_process_data()          ; last_process_data_update = current_time          ; logging.info('get_process_data() finished execution')
        if current_time - last_program_data_update >= int(SETTINGS.get('PROG_DATA_UPDATES_FREQ', float('inf'))):               get_program_data()          ; last_program_data_update = current_time          ; logging.info('get_program_data() finished execution')
        if current_time - last_privesc_audit_update >= int(SETTINGS.get('PRIVESC_UPDATES_FREQ', float('inf'))):                get_privesc_audit()         ; last_privesc_audit_update = current_time         ; logging.info('get_privesc_audit() finished execution')
        if current_time - last_network_mapper_update >= int(SETTINGS.get('NMAP_UPDATES_FREQ', float('inf'))):                  run_network_mapper()        ; last_network_mapper_update = current_time        ; logging.info('run_network_mapper() finished execution')
        if current_time - last_passwd_data_update >= int(SETTINGS.get('PASSWD_DATA_UPDATES_FREQ', float('inf'))):              get_passwd_data()           ; last_passwd_data_update = current_time           ; logging.info('get_passwd_data() finished execution')
        #if current_time - last_exploit_suggest_update >= EXPLOIT_UPDATES_FREQ:             get_exploit_suggest()       ; last_exploit_suggest_update = current_time


if __name__ == '__main__':
    main()



'''
cyber oracle network protocol [CLIENT_SIDE]: *note that v1 uses JSON to carry the data, which takes more bandwidth that it is required to carry the information, can be optimized by using struct
required fields:
0: protocol version == 1            # the PDU structure of this protocol may change in future updates, and this is used to ensure compatability and distinction 
1: PDU_ID                            # to prevent replay attacks
2: timestamp                        # additional techneque to prevent replay attacks
3: central monitor signature        # the signature is applied to the struct formed by all fields except the signature itself
4: payload_type
    0: #keepalive
        code = {
            0 : general keepalive echo              # the host informs the central monitor that the host is still alive, and vice versa
            1 : general keepalive reply
            2 : system_monitor_keepalive,           # sent from central monitor to the host to keep glances system monitor running for the next 5 minutes
            3 : system_monitor_terminate,           # sent from the central monitor to the host to terminate glances system monitor
        }
    1: #command
        command = {
            1  : get_shell,                         # open a shell for issuing system commands
            2  : get_program_data,                  # get data about programs and apps on this host
            3  : get_process_data,                  # get data about processes running on this host
            4  : get_passwd_data,                   # dump the hashes of local user passowrds on this host
            5  : get_privesc_audit,                 # run system audit for privelege escalation vectors on this host
            6  : get_exploit_suggest,               # get available system exploits for this host
            7  : run_system_monitor,                # run glances system monitor web server on port 61337 on this host
            8  : get_system_info,                   # get system information of this host
            9  : get_network_information,           # get networking information on this host
            10 : run_network_mapper                 # run nmap on this host to scan all neighboring hosts and return the result
        }
    2: #settings
        action = {
            0 : settings request,                   # register host and request settings from central monitor
            1 : settings reply                      # received settings from central monitor
        }
    3: #authenticate (follows TLS 1.3 protocol)
        action = {
            0 : authentication_request
            1 : authentication_response
        }
    4: #alert
        data = {
        'source_id' : source_id,
        'severity_score' : severity_score,
        'data' : {
            'general_info' : general_info,
            'detail_info' : detail_info,
        }
    }
    5: #error
        error_code = {
            0 : general/unknown failure while processing the PDU,
        }
        
'''







'''
what happens in the agent when windows agents runs for the first time:
1.start CO protocol server
2.wait for central monitor to become online
3.send host_id to API to register the host and create an entry in the database
4.on success write to the settings file that the host is registered
5.collect information and send it to the central monitor to the API with PATCH request to update the entry in the database with host_id
'''


'''
GENERAL USE CASE
-the central monitor is installed on a server and launched
-each host that needs to be monitored downloads the agent installer from the central monitor
    -the downloaded agent can only communicate with the central monitor that it was downloaded from: this is accomplished by including (hardcoding)4 a unique id for the central monitor in the installer which is then copied to the agent and used for each communication between the agent and central monitor
-the downloaded installer is ran and the agent gets installed on the host
-when it runs for the first time, the agent registers its host_id on the central mon
-after registering, the agent requests the settings file from the central mon through COP (cyber oracle protocol) which is sent back in json and saved in storage then loaded each time
    -the settings file will be sent to all registered agents whenever the settings are modified on the central monitor
-after registering and receiving the settings, the agent will collect all information and send it to the central monitor

-now the agent enters the normal routine flow, where based on the settings the information is collected and sent to the central monitor, and the COP server is running

'''
