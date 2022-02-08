from django.db import models
from django.utils import timezone
from django.urls import reverse
import uuid
from pathlib import Path
import json
import time
from django.contrib.auth.models import User, Permission
from django.conf import settings
import uuid
import subprocess
import os
from ipaddress import ip_network, IPv4Interface
from netifaces import interfaces, ifaddresses
import re
import threading
import requests
import logging
from functools import lru_cache, wraps
from alerts.models import Alert
import traceback
from typing import Callable


# Create your models here.
def get_initial_host_settings() -> dict:
    '''generates initial_host_settings dict using the parameters specified on central monitor settings page'''

    with open(f'{settings.BASE_DIR}/config_files/CMConfig.json' , 'r') as f:
        conf = json.loads(f.read())
        return {
            'AGENT_ID' : str(uuid.uuid4().hex),
            'REGISTERED' : False,
            'CENTRAL_MONITOR_ID'            :   conf['CENTRAL_MONITOR_ID'],
            'CENTRAL_MONITOR_BASE_URL'      :   conf['CENTRAL_MONITOR_BASE_URL'],
            'AGENT_AUTH_USERNAME'           :   conf['AGENT_AUTH_USERNAME'],# NOTE: when host registers, he uses the conf['AGENT_AUTH_USERNAME'] to register (add a host). during registration, host will provide new creds (username,passowrd) that will be used to create a user that can access only his instance of host in the DB
            'AGENT_AUTH_PASSWORD'           :   conf['AGENT_AUTH_PASSWORD'],
            'SYSTEM_MONITOR_PORT'           :   conf['SYSTEM_MONITOR_PORT'],
            'TCP_HONEYPOT_PORTS'            :   conf['TCP_HONEYPOT_PORTS'],
            'UDP_HONEYPOT_PORTS'            :   conf['UDP_HONEYPOT_PORTS'],
            'NETWORK_INFO_UPDATES_FREQ'     :   conf['NETWORK_INFO_UPDATES_FREQ'],
            'EVENT_LOGS_UPDATES_FREQ'       :   conf['EVENT_LOGS_UPDATES_FREQ'],
            'PROC_DATA_UPDATES_FREQ'        :   conf['PROC_DATA_UPDATES_FREQ'],
            'SYSTEM_INFO_UPDATES_FREQ'      :   conf['SYSTEM_INFO_UPDATES_FREQ'],
            'NMAP_UPDATES_FREQ'             :   conf['NMAP_UPDATES_FREQ'],
            'PROG_DATA_UPDATES_FREQ'        :   conf['PROG_DATA_UPDATES_FREQ'],
            'SCHEDULED_TASKS_UPDATES_FREQ'  :   conf['SCHEDULED_TASKS_UPDATES_FREQ'],
            'PASSWD_DATA_UPDATES_FREQ'      :   conf['PASSWD_DATA_UPDATES_FREQ'],
            'PRIVESC_UPDATES_FREQ'          :   conf['PRIVESC_UPDATES_FREQ'],
            'EXPLOIT_UPDATES_FREQ'          :   conf['EXPLOIT_UPDATES_FREQ'],
        }


def get_default_program_info(): return {"fresh_info":False, "program_info":""}
def get_default_process_info(): return {"fresh_info":False, "process_info":""}
def get_default_password_info(): return {"fresh_info":False, "password_info":""}
def get_default_privesc_info(): return {"fresh_info":False, "privesc_info":""}
def get_default_exploit_info(): return {"fresh_info":False, "exploit_info":""}
def get_default_system_info(): return {"fresh_info":False, "system_info":""}
def get_default_network_info(): return {"fresh_info":False, "network_info":""}
def get_default_nmap_info(): return {"fresh_info":False, "nmap_info":""}
def get_default_eventlog_info(): return {"fresh_info":False, "eventlog_info":""}
def get_default_schedtask_info(): return {"fresh_info":False, "schedtask_info":""}

class Host(models.Model):
    host_os_type = models.CharField(max_length=10, choices=[('Windows','Windows'), ('Linux','Linux')])
    host_id = models.CharField(max_length=255, primary_key=True)
    agent_id = models.CharField(max_length=255)
    date_registered = models.DateTimeField(auto_now=False, auto_now_add=False, blank=True, null=True) # note that logically null=False, because the save function will set this value on save, but api gives error when passing null
    date_modified = models.DateTimeField(auto_now=False, auto_now_add=False, blank=True, null=True) # note that logically null=False, because the save function will set this value on save, but api gives error when passing null
    settings = models.JSONField(default=get_initial_host_settings)
    owner_user = models.ForeignKey(User, null=True, blank=True, on_delete=models.CASCADE)

    program_info = models.JSONField(default=get_default_program_info, null=True, blank=True)
    process_info = models.JSONField(default=get_default_process_info, null=True, blank=True)
    password_info = models.JSONField(default=get_default_password_info, null=True, blank=True)
    privesc_info = models.JSONField(default=get_default_privesc_info, null=True, blank=True)
    exploit_info = models.JSONField(default=get_default_exploit_info, null=True, blank=True)
    system_info = models.JSONField(default=get_default_system_info, null=True, blank=True)
    network_info = models.JSONField(default=get_default_network_info, null=True, blank=True)
    nmap_info = models.JSONField(default=get_default_nmap_info, null=True, blank=True)
    eventlog_info = models.JSONField(default=get_default_eventlog_info, null=True, blank=True)
    schedtask_info = models.JSONField(default=get_default_schedtask_info, null=True, blank=True)

    last_online = models.DateTimeField(auto_now=False, auto_now_add=False, blank=True, null=True)
    host_health = models.IntegerField(null=True, blank=True)

    @property
    def online_status(self):
        if self.last_online == None: return False
        if time.time() - self.last_online.timestamp() >= 60:
            return False
        return True


    def save(self, *args, **kwargs): # FIXME: this code must be placed in other place, here it blocks the whole Host model when processing (because it is synchronous)
        ''' On save, update timestamps and create owner_user if the object is saved for the first time (registration process), and run other data preprocessing functions'''
        
        if not Host.objects.filter(pk=self.host_id).exists():
            # REGISTRATION PROCESS
            new_usr = User.objects.create(username=self.settings['AGENT_AUTH_USERNAME'])
            new_usr.set_password(self.settings['AGENT_AUTH_PASSWORD'])
            new_usr.user_permissions.clear()
            new_usr.user_permissions.add(Permission.objects.get(codename='change_host').id)
            new_usr.user_permissions.add(Permission.objects.get(codename='view_host').id)
            new_usr.save()
            self.owner_user = new_usr
            self.date_registered = timezone.now()
        self.date_modified = timezone.now()


        if self.host_os_type == 'Windows':
            if self.program_info.get('fresh_info', False):      self.program_info['fresh_info'] = False; prog_hash_check_VTAPI(self.host_id, self.program_info)
            if self.process_info.get('fresh_info', False):      self.process_info['fresh_info'] = False; proc_hash_check_VTAPI(self.host_id, self.process_info)
            if self.password_info.get('fresh_info', False):     self.password_info['fresh_info'] = False; sam_security_system_decode(self.host_id, self.password_info)
            if self.privesc_info.get('fresh_info', False):      self.privesc_info['fresh_info'] = False; # TODO: not implemented yet
            if self.system_info.get('fresh_info', False):       self.system_info['fresh_info'] = False; system_exploit_search(self.host_id, self.system_info)
            if self.network_info.get('fresh_info', False):      self.network_info['fresh_info'] = False; # TODO: not implemented yet
            if self.nmap_info.get('fresh_info', False):         self.nmap_info['fresh_info'] = False; # TODO: not implemented yet
            if self.eventlog_info.get('fresh_info', False):     self.eventlog_info['fresh_info'] = False; # TODO: not implemented yet # TODO: preprocessing function to generate alerts based on certain events
            if self.schedtask_info.get('fresh_info', False):    self.schedtask_info['fresh_info'] = False; # TODO: not implemented yet
        elif self.host_os_type =='Linux':
            pass # TODO: not implemented yet
        
        return super(Host, self).save(*args, **kwargs) # NOTE: maybe add update_fields to increase the efficiency



def thread_spawn_daemon(func: Callable) -> Callable:
    '''decorator for calling functions in a new thread'''

    @wraps(func)
    def wrapper(*args, **kwargs):
        threading.Thread(target=func, args=args, kwargs=kwargs, daemon=True).start()
    return wrapper


def determine_host_ip(host_id: str, host_obj: Host = None) -> None or str:
    '''determines the ipv4 address that can be used to communicate with a host'''

    if host_obj == None:
        if host_id == None: return None
        host_obj = Host.objects.get(host_id=host_id)
    #if host_obj.online_status == False: return None # this may not be needed, if host cant contact the server, the server may be able to contact the host (in one way) this can happen when server changes IP address
    host_ipv4_addresses=[]
    if host_obj.host_os_type == 'Windows':
        ipv4 = ''
        netmask = ''
        for line in host_obj.network_info['network_info']['ip_info'].split('\r\n'):
            ipv4_regex = r"((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"
            if 'IPv4 Address' in line:
                ipv4_matches = re.search(ipv4_regex, line)
                if ipv4_matches != None: ipv4=ipv4_matches.group()
            if 'Subnet Mask' in line:
                subnetmask_matches = re.search(ipv4_regex, line)
                if subnetmask_matches != None:
                    netmask = subnetmask_matches.group()
                    host_ipv4_addresses.append(IPv4Interface(f'{ipv4}/{netmask}').with_prefixlen)
    elif host_obj.host_os_type == 'Linux':
        pass # TODO: not implemented yet

    central_monitor_ip_addresses=[]
    for ifaceName in interfaces():
        try: local_ipv4_int = ifaddresses(ifaceName)[2]
        except: continue
        central_monitor_ip_addresses.append(f'{local_ipv4_int[0]["addr"]}/{local_ipv4_int[0]["netmask"]}')

    for central_monitor_int in central_monitor_ip_addresses:
        for host_int in host_ipv4_addresses:
            if ip_network(central_monitor_int, strict = False).network_address == ip_network(host_int, strict = False).network_address:
                return host_int.split('/')[0]
    return None

@thread_spawn_daemon
def sam_security_system_decode(host_id: str, password_info: dict) -> dict:
    '''runs secretsdump.py (from impacket) to extract password hashes from sam/system/security files'''

    try:
        import base64
        import os
        password_info = password_info['password_info']
        working_dir = f'{settings.BASE_DIR}\\static\\app_utilities'
        sam, security, system = base64.b64decode(password_info['sam']), base64.b64decode(password_info['security']), base64.b64decode(password_info['system'])
        sam_fname, security_fname, system_fname, dump_fname = f'{uuid.uuid4().hex}sam', f'{uuid.uuid4().hex}security', f'{uuid.uuid4().hex}system', f'{uuid.uuid4().hex}dump'
        with open(f'{working_dir}\\temp\\{sam_fname}', 'wb') as sam_f, open(f'{working_dir}\\temp\\{security_fname}', 'wb') as security_f, open(f'{working_dir}\\temp\\{system_fname}', 'wb') as system_f:
            sam_f.write(sam)
            security_f.write(security)
            system_f.write(system)
        os.system(f'python {working_dir}\\secretsdump.py -sam {working_dir}\\temp\\{sam_fname} -security {working_dir}\\temp\\{security_fname} -system {working_dir}\\temp\\{system_fname} LOCAL > {working_dir}\\temp\\{dump_fname}') # NOTE: antivirus wont allow you to pip install impacket which is a dependency of secretsdump.py.. if it is fuked up by an AV run pip install --upgrade --no-deps --force-reinstall impacket
        with open(f'{working_dir}\\temp\\{dump_fname}', 'r') as dump_f: dump_content = dump_f.read()
        os.remove(f'{working_dir}\\temp\\{sam_fname}') ; os.remove(f'{working_dir}\\temp\\{security_fname}') ; os.remove(f'{working_dir}\\temp\\{system_fname}') ; os.remove(f'{working_dir}\\temp\\{dump_fname}')
        
        host_obj = Host.objects.get(host_id=host_id)
        host_obj.password_info = {'password_info': dump_content, 'fresh_info' : False}
        host_obj.save(update_fields=['password_info'])
    except Exception as e:
        logging.error(e)
        host_obj = Host.objects.get(host_id=host_id)
        host_obj.password_info = {'password_info': '', 'fresh_info' : False}
        host_obj.save(update_fields=['password_info'])

@thread_spawn_daemon
def system_exploit_search(host_id: str, systeminfo: dict):
    '''runs wesng to get exploits for the host system. systeminfo from the host is required for wesng.'''

    try:
        systeminfo_filename = f'{settings.BASE_DIR}\\static\\app_utilities\\temp\\systeminfo_{uuid.uuid4().hex}.txt'
        with open(systeminfo_filename, 'wb') as f: f.write((systeminfo['system_info']).encode())
        exploit_info = subprocess.run(f'python "{settings.BASE_DIR}\\static\\app_utilities\\wesng\\wes.py" "{systeminfo_filename}" --muc-lookup', stdout=subprocess.PIPE, stderr=subprocess.STDOUT, cwd=f"{settings.BASE_DIR}\\static\\app_utilities\\wesng\\").stdout.decode()
        host_obj = Host.objects.get(host_id=host_id)
        host_obj.exploit_info = {'exploit_info': 'Windows Exploit Suggester 0.98 ( https://github.com/bitsadmin/wesng/ )\n' + '\n'.join(exploit_info.split('\n')[3:])}
        systeminfo['fresh_info']=False
        host_obj.system_info = systeminfo
        host_obj.save(update_fields=['system_info', 'exploit_info']) # just imagine what would happen if i did not set systeminfo['fresh_info']=False, it will blow up!
        os.remove(systeminfo_filename)
    except Exception as e: print(f'failed to get exploit suggestions using the systeminfo provided by the host due to an exception: {e}')

@thread_spawn_daemon
def prog_hash_check_VTAPI(host_id: str, program_info: dict):
    # TODO: not implemented yet
    pass

@thread_spawn_daemon
def proc_hash_check_VTAPI(host_id: str, process_info: dict) -> None: # TODO: speedup this function using https://stackoverflow.com/questions/2632520/what-is-the-fastest-way-to-send-100-000-http-requests-in-python
    '''for each process on the host, get a scan report from virustotal API, parse the report and put useful information in host.process_info'''
    
    def parse_VTAPI_file_report(proc: list, file_report: dict) -> list:
        '''this function parses the JSON file report from VTAPI to extract the information about file scans'''

        if file_report:
            data = file_report['data']
            VT_file_report_link = f'https://www.virustotal.com/gui/file/{data["id"]}'
            total_analysis_cnt = len(data['attributes']['last_analysis_results'])
            analysis_stats = data['attributes']['last_analysis_stats']
            harmless_cnt = analysis_stats['harmless']
            suspicious_cnt = analysis_stats['suspicious']
            malicious_cnt = analysis_stats['malicious']
            undetected_cnt = analysis_stats['undetected']

            severity_score = -1
            # NOTE: adjust the following 2 divisor values if needed
            severity_score += -(-suspicious_cnt//12) # the minus signs is just to get the ceil
            severity_score += -(-malicious_cnt//5) # the minus signs is just to get the ceil
            if severity_score >= 0:
                Alert.objects.create(source_type='Local', source_id=None, severity_score=severity_score, data={'data':{
                    'general_info': 'A suspicious/malicious process was detected on a host.',
                    'detail_info': f"""
                        Host ID: {host_id}
                        Link to Virustotal report: {VT_file_report_link}
                        File Hash: {data['id']}
                        Analysis stats:
                            harmless:          {analysis_stats['harmless']}
                            type-unsupported:  {analysis_stats['type-unsupported']}
                            suspicious:        {analysis_stats['suspicious']}
                            confirmed-timeout: {analysis_stats['confirmed-timeout']}
                            timeout:           {analysis_stats['timeout']}
                            failure:           {analysis_stats['failure']}
                            malicious:         {analysis_stats['malicious']}
                            undetected:        {analysis_stats['undetected']}

                        Full VirusTotal API report content:
                            {file_report}
                        """
                }}).save()
            return [VT_file_report_link, total_analysis_cnt, harmless_cnt, suspicious_cnt, malicious_cnt, undetected_cnt]
        else:
            Alert.objects.create(source_type='Local', source_id=None, severity_score=-2, data={'data':{
                'general_info': 'An unknown process was detected on a host.',
                'detail_info': f"""
                    Host ID: {host_id}
                    Proc Info: {proc}
                    """
            }}).save()
            return ['unknown', 'unknown', 'unknown', 'unknown', 'unknown', 'unknown']

    @lru_cache(maxsize=1000)
    def make_VTAPI_GetFileReport_request(file_hash: str) -> dict:
        '''Receives a file hash and makes a request to the Virustotal API at /api/v3/files endpoint to get file scan report'''

        with open(f'{settings.BASE_DIR}/config_files/CMConfig.json' , 'r') as sf: current_settings = json.load(sf)
        VTAPI_KEY = current_settings.get('VIRUSTOTAL_API_KEY', '')

        if VTAPI_KEY and len(VTAPI_KEY) == 64 and all(i in 'abcdefghijklmnopqrstuvwxyz0123456789' for i in VTAPI_KEY.lower()): # NOTE: is this a good check?
            if file_hash:
                url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
                headers = {
                    "Accept": "application/json",
                    "x-apikey": f"{VTAPI_KEY}"
                }
                response = requests.request("GET", url, headers=headers)
                if response.status_code == 200:
                    return response.json()
                elif response.status_code == 404:
                    # TODO: if virustotal didnt see this file before, get it from the host and upload to virustotal
                    return {}
                else:
                    logging.warning(f'VTAPI returned status code {response.status_code} for file_hash: {file_hash}')
                    return {}
            else:
                logging.warning(f'didnt receive a file report from VTAPI for file_hash: {file_hash}')
                return {}
        else:
            logging.warning(f'VTAPIKEY ({VTAPI_KEY}) cannot be used')
            return {}

    #load cache file
    VTAPI_cache_filename = f'{settings.BASE_DIR}/static/app_utilities/temp/VTAPI_cache.json' # TODO: use a relational database to make it faster and more efficient
    if os.path.exists(VTAPI_cache_filename):
        with open(VTAPI_cache_filename, 'r') as f: VTAPI_cache = json.load(f) 
    else: VTAPI_cache = {}

    proclist = process_info.get('process_info', [])
    new_proclist = []
    for i, proc in enumerate(proclist):
        try:
            file_hash = proc[2] 
            if not VTAPI_cache.get(file_hash, None): # if result not in cache then fetch results from the API
                file_report = make_VTAPI_GetFileReport_request(file_hash=file_hash)
                # if no report was returned then either an error occured or the file is unknown to VTAPI
                if file_report:
                    VTAPI_cache[file_hash] = file_report
            file_analysis = parse_VTAPI_file_report(proc, VTAPI_cache.get(file_hash, {}))
            new_proclist.append(proc+file_analysis)
            #logging.info(f'process {proc} passed - [{i}/{len(proclist)}]')
        except:
            logging.warning(f'error occured while processing process ({proc})')
            new_proclist.append(proc+['error', 'error', 'error', 'error', 'error', 'error'])
    
    #after analyzing all processes, save the results into the databe in the host object
    host_obj = Host.objects.get(host_id=host_id)
    host_obj.process_info = { 'process_info' : new_proclist, 'fresh_info' : False }
    host_obj.save(update_fields=['process_info'])

    #save cache file
    with open(VTAPI_cache_filename, 'w') as f: json.dump(VTAPI_cache, f)