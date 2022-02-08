from django.http.response import HttpResponse
from django.shortcuts import render
from central_monitor.my_decorators import superuser_required
from django.views.decorators.clickjacking import xframe_options_exempt
from api.models import Host, determine_host_ip
from django.conf import settings
import re
import json
import os
import subprocess
import uuid
from ipaddress import ip_network, IPv4Interface
from django.http import Http404, HttpResponseBadRequest, JsonResponse
from api.management.commands.COP_server import verify_PDU_signature, sign_PDU, get_next_PDU_ID, construct_COP_PDU, CENTRAL_MONITOR_COP_PDU_handler
import socket

# Create your views here.

@superuser_required
def home_view(request, *args, **kwargs):
    return render(request=request, template_name='home_template.html', context={})


@superuser_required
def dashboard_view(request, *args, **kwargs):
    # TODO: NOT IMPLEMENTED YET
    return render(request=request, template_name='home_dashboard_template.html', context={})


@superuser_required
def host_monitor_view(request, *args, **kwargs):
    host_table_rows_data=[]
    for host in Host.objects.all().iterator(): # The iterator() method ensures only a few rows are fetched from the database at a time, saving memory.
        os, host_name, domain_name, ID = host.host_id.split('$')
        register_date = host.date_registered
        status = host.online_status
        health = host.host_health # TODO: host health not implemented yet

        #parse and get ipv4 addresses
        ipv4_addresses=[]
        if os == 'WIN':
            ipv4 = ''
            netmask = ''
            for line in host.network_info['network_info']['ip_info'].split('\r\n'):
                ipv4_regex = r"((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"
                if 'IPv4 Address' in line:
                    ipv4_matches = re.search(ipv4_regex, line)
                    if ipv4_matches != None: ipv4=ipv4_matches.group()
                if 'Subnet Mask' in line:
                    subnetmask_matches = re.search(ipv4_regex, line)
                    if subnetmask_matches != None:
                        netmask = subnetmask_matches.group()
                        ipv4_addresses.append(IPv4Interface(f'{ipv4}/{netmask}').with_prefixlen)
        elif os == 'LIN':
            pass # TODO: not implemented yet

        #parse and get mac addresses
        mac_addresses=[]
        if os == 'WIN':
            for line in host.network_info['network_info']['all_local_mac_addresses'].split('\r\n'):
                mac_regex = r"([0-9a-f]{2}(?:-[0-9a-f]{2}){5})"
                mac_matches = re.search(mac_regex, line, re.IGNORECASE)
                if mac_matches != None: mac_addresses.append(mac_matches.group())
        elif os == 'LIN':
            pass # TODO: not implemented yet
        host_table_rows_data.append([host.host_id, os, host_name, domain_name, register_date, ipv4_addresses, mac_addresses, health, status])


    ctx={'host_table_rows_data' : host_table_rows_data}
    return render(request=request, template_name='home_host_monitor_template.html', context=ctx)


@superuser_required
def network_monitor_view(request, *args, **kwargs): # TODO: refactor this shitcode
    nodes=[]
    edges=[]
    node_map = {}
    network_map = {}
    i=1
    net_id = 1
    for host in Host.objects.all().iterator(): # The iterator() method ensures only a few rows are fetched from the database at a time, saving memory.
        for local_int, scan_result in host.nmap_info['nmap_info'].items():
            local_int_ip = local_int
            local_int_map_ip = ip_network(local_int_ip, strict = False).network_address
            if not network_map.get(local_int_map_ip, None):
                network_map[local_int_map_ip]=net_id
                local_int_net_id = net_id
                net_id+=1
            else: local_int_net_id = network_map['local_int_map_ip']
            local_hostname = '.'.join(host.host_id.split('$')[1:3])
            if node_map.get(local_hostname, None): # NOTE: to spearate networks in the graph, use local_int_ip.split('/')[0] instead of local_hostname
                local_host_node_idx = node_map[local_hostname] # NOTE: to spearate networks in the graph, use local_int_ip.split('/')[0] instead of local_hostname
                nodes[local_host_node_idx-1][2]+=f'||{local_int_ip}' # NOTE: this line could mess things up...
            else:
                nodes.append([i, local_hostname, local_int_ip, local_int_net_id])
                local_host_node_idx = i
                node_map[local_hostname] = local_host_node_idx # NOTE: to spearate networks in the graph, use local_int_ip.split('/')[0] instead of local_hostname
                i+=1
            scan_result = scan_result.split('\r\n')
            for line in scan_result:
                if 'Nmap scan report for' in line:
                    remote_int_ip = line.split(' ')[-1].strip('(').strip(')')
                    remote_int_title = line.replace(f'({remote_int_ip})', '').replace('Nmap scan report for','').strip()
                    remote_int_net_id = 0
                    if local_int_ip.split('/')[0] == remote_int_ip: continue
                    for _net_ip, _net_id in network_map.items():
                        if _net_ip == ip_network(remote_int_ip+'/'+local_int_ip.split('/')[1], strict = False).network_address:
                            remote_int_net_id = _net_id
                    if node_map.get(remote_int_ip, None):
                        remote_host_node_idx = node_map[remote_int_ip]
                        if local_host_node_idx != remote_host_node_idx and local_int_ip != remote_int_ip:
                            edges.append([local_host_node_idx, remote_host_node_idx])
                    else:
                        node_map[remote_int_ip] = i
                        nodes.append([i, remote_int_title, remote_int_ip+'/'+local_int_ip.split('/')[1], remote_int_net_id])
                        edges.append([local_host_node_idx, i])
                        i+=1
    ctx={'nodes':nodes, 'edges':edges}
    return render(request=request, template_name='home_network_monitor_template.html', context=ctx)


@superuser_required
def password_cracker_view(request, *args, **kwargs):
    password_hash_matrix_filename = f'{settings.BASE_DIR}\\static\\app_utilities\\temp\\password_hash_matrix.json'
    if os.path.exists(password_hash_matrix_filename):
        with open(password_hash_matrix_filename, 'r') as f: password_hash_matrix=json.loads(f.read()) 
    else: password_hash_matrix = {}

    #TODO: implement hashes_filename for each type of possible hashes (currently only NTLM implemented)
    NTLM_hashes_filename = f'{settings.BASE_DIR}\\static\\app_utilities\\temp\\NTLM.hashes'
    if os.path.exists(NTLM_hashes_filename):
        with open(NTLM_hashes_filename, 'r') as f: NTLM_hashes=set(f.read().split('\n'))
    else: NTLM_hashes = set()

    for host in Host.objects.all().iterator(): # The iterator() method ensures only a few rows are fetched from the database at a time, saving memory.
        if host.host_os_type == 'Windows':
            secretsdump = [i.split('\n') for i in host.password_info['password_info'].split('[*]')]
            for dump_part in secretsdump:
                if 'Dumping local SAM hashes (uid:rid:lmhash:nthash)' in dump_part[0]: # collect all local NTLM hashes
                    for line in dump_part[1:]:
                        line = line.strip()
                        if line == '':continue
                        NTLM_hashes.add(f'{line.strip(":").split(":")[-1]}')
                        if not password_hash_matrix.get('NTLM', None): password_hash_matrix['NTLM']={}
                        if not password_hash_matrix['NTLM'].get(host.host_id, None): password_hash_matrix['NTLM'][host.host_id]={}
                        if not password_hash_matrix['NTLM'][host.host_id].get(line, None): password_hash_matrix['NTLM'][host.host_id][line]=None
                elif 'Dumping cached domain logon information (domain/username:hash)' in dump_part[0]:
                    pass # TODO: not implemented yet
                else:
                    pass # TODO: not implemented yet
        if host.host_os_type == 'Linux':
            pass # TODO: not implemented yet
    with open(password_hash_matrix_filename, 'w') as f: f.write(json.dumps(password_hash_matrix))
    with open(NTLM_hashes_filename, 'w') as f: f.write('\n'.join(NTLM_hashes))
    ctx={'password_hash_matrix' : password_hash_matrix}
    with open(f'{settings.BASE_DIR}\\config_files\\CMConfig.json', 'r') as f: ctx['CENTRAL_MONITOR_BASE_URL'] = json.loads(f.read())['CENTRAL_MONITOR_BASE_URL'].split(':')[0]
    return render(request=request, template_name='home_password_cracker_template.html', context=ctx)


@superuser_required
def log_analyzer_view(request, *args, **kwargs):
    # TODO: NOT IMPLEMENTED YET
    # IDEA: maybe make an agent for servers that will collect predetermined logs, like web-server logs
    # https://github.com/JeffXue/web-log-parser
    # https://github.com/allinurl/goaccess
    return render(request=request, template_name='home_log_analyzer_template.html', context={})


@superuser_required
def active_directory_view(request, *args, **kwargs):
    is_ajax = request.headers.get('X-Requested-With') == 'XMLHttpRequest' # https://testdriven.io/blog/django-ajax-xhr/
    if is_ajax:
        if request.method == 'POST':
            data = json.load(request)
            option = data.get('option', '')
            if option == 'healthcheck':
                target = data.get('target', '')
                if target: 
                    p = subprocess.run([f'{settings.BASE_DIR}/static/app_utilities/PingCastle.exe', '--server', target, '--healthcheck'])
                    if p.returncode == 0:
                        # TODO: if current scan fails and an existing report file exist, it will be used, fix that in some way
                        with open(f'{settings.BASE_DIR}/static/app_utilities/ad_hc_{target}.html', 'r', encoding ="utf8") as res_f:
                            return JsonResponse({'success': True, 'status_code': 200, 'msg': res_f.read()}, status=200)
                    else:
                        return JsonResponse({'success': False, 'status_code': 500, 'msg': f'unknown error occured while attempting to scan {target}...'}, status=500)
                else: return JsonResponse({'success': False, 'status_code': 400, 'msg': f'invalid target {target}'}, status=400)
            elif option == 'scanner':
                target = data.get('target', '')
                if target:
                    scanner = data.get('scanner', '')
                    if scanner in list('123456789abcdefg'):
                        scanner = {'1' : 'aclcheck', '2' : 'antivirus', '3' : 'computerversion', '4' : 'foreignusers', '5' : 'laps_bitlocker', '6' : 'localadmin', '7' : 'nullsession', '8' : 'nullsession-trust', '9' : 'oxidbindings', 'a' : 'remote', 'b' : 'share', 'c' : 'smb', 'd' : 'smb3querynetwork', 'e' : 'spooler', 'f' : 'startup', 'g' : 'zerologon'}[scanner]
                        p = subprocess.run([f'{settings.BASE_DIR}/static/app_utilities/PingCastle.exe', '--server', target, '--scanner', scanner])
                        if p.returncode == 0:
                            # TODO: if current scan fails and an existing report file exist, it will be used, fix that in some way
                            with open(f'{settings.BASE_DIR}/static/app_utilities/ad_scanner_{scanner}_{target}.txt', 'r', encoding ="utf8") as res_f:
                                return JsonResponse({'success': True, 'status_code': 200, 'msg': f'<pre>{res_f.read()}</pre>'}, status=200)
                        else:
                            return JsonResponse({'success': False, 'status_code': 500, 'msg': f'unknown error occured while attempting to scan {target}...'}, status=500)
                    else: return JsonResponse({'success': False, 'status_code': 400, 'msg': f'invalid scanner {scanner}'}, status=400)
                else: return JsonResponse({'success': False, 'status_code': 400, 'msg': f'invalid target {target}'}, status=400)
            else: return JsonResponse({'success': False, 'status_code': 400, 'msg': f'invalid option {option}'}, status=400)
    else:
        if request.method == 'GET':
            return render(request=request, template_name='home_active_directory_template.html', context={})


@superuser_required
def host_detail_view(request, *args, **kwargs):
    is_ajax = request.headers.get('X-Requested-With') == 'XMLHttpRequest' # https://testdriven.io/blog/django-ajax-xhr/
    if is_ajax:
        if request.method == 'POST':
            data = json.load(request)
            host_id = data.get('host_id', None)
            try: host_obj = Host.objects.get(host_id=host_id)
            except Host.DoesNotExist: return JsonResponse({'success': False, 'status_code': 404, 'msg': f'No host with host_id={host_id} was found.'}, status=404)
            
            new_settings = data['settings']
            #host_obj.settings['CENTRAL_MONITOR_ID'] = new_settings['CENTRAL_MONITOR_ID']
            host_obj.settings['CENTRAL_MONITOR_BASE_URL'] = new_settings['CENTRAL_MONITOR_BASE_URL']
            #host_obj.settings['AGENT_AUTH_USERNAME'] = new_settings['AGENT_AUTH_USERNAME']
            #host_obj.settings['AGENT_AUTH_PASSWORD'] = new_settings['AGENT_AUTH_PASSWORD']
            host_obj.settings['SYSTEM_MONITOR_PORT'] = new_settings['SYSTEM_MONITOR_PORT']
            host_obj.settings['NETWORK_INFO_UPDATES_FREQ'] = new_settings['NETWORK_INFO_UPDATES_FREQ']
            host_obj.settings['EVENT_LOGS_UPDATES_FREQ'] = new_settings['EVENT_LOGS_UPDATES_FREQ']
            host_obj.settings['PROC_DATA_UPDATES_FREQ'] = new_settings['PROC_DATA_UPDATES_FREQ']
            host_obj.settings['SYSTEM_INFO_UPDATES_FREQ'] = new_settings['SYSTEM_INFO_UPDATES_FREQ']
            host_obj.settings['NMAP_UPDATES_FREQ'] = new_settings['NMAP_UPDATES_FREQ']
            host_obj.settings['PROG_DATA_UPDATES_FREQ'] = new_settings['PROG_DATA_UPDATES_FREQ']
            host_obj.settings['SCHEDULED_TASKS_UPDATES_FREQ'] = new_settings['SCHEDULED_TASKS_UPDATES_FREQ']
            host_obj.settings['PASSWD_DATA_UPDATES_FREQ'] = new_settings['PASSWD_DATA_UPDATES_FREQ']
            host_obj.settings['PRIVESC_UPDATES_FREQ'] = new_settings['PRIVESC_UPDATES_FREQ']
            host_obj.settings['EXPLOIT_UPDATES_FREQ'] = new_settings['EXPLOIT_UPDATES_FREQ']

            # send settings update to host agent through COP protocol
            host_ip = determine_host_ip(host_id=None, host_obj=host_obj)
            PDU = construct_COP_PDU(payload_type=2, payload={'action': 1, 'settings' : new_settings})
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as conn:
                conn.connect((host_ip, 51337))
                conn.settimeout(10) # 10 seconds timeout
                conn.sendall(PDU)
                conn.close()

            host_obj.save()
            return JsonResponse({'success': True, 'status_code': 200, 'msg': f'Settings for host with host_id={host_id} were updated.'}, status=200)
    else:
        if request.method == 'GET' and request.GET.get('host_id', None):
            host_id = request.GET.get('host_id', None)
            try: host_obj = Host.objects.get(host_id=host_id)
            except Host.DoesNotExist: raise Http404('Host Does Not Exist')
            
            program_info = host_obj.program_info['program_info']
            process_info = host_obj.process_info['process_info']
            password_info_plain = host_obj.password_info['password_info']
            password_info_processed = {}
            try:
                with open(f'{settings.BASE_DIR}\\static\\app_utilities\\temp\\password_hash_matrix.json', 'r') as f:
                    password_hash_matrix = json.loads(f.read())
                    for _hash_type, _hosts in password_hash_matrix.items():
                        if host_id in _hosts.keys():
                            password_info_processed[_hash_type]=_hosts[host_id]
            except:
                print('password_hash_matrix.json file does not exist for this host')
            privesc_info_filename = f'{settings.BASE_DIR}\\static\\app_utilities\\{uuid.uuid4().hex}_privesc.txt'
            with open(privesc_info_filename, 'wb') as f: f.write(host_obj.privesc_info['privesc_info'].encode())
            privesc_info = subprocess.run(f'"{settings.BASE_DIR}\\static\\app_utilities\\aha.exe" -b -n -f "{privesc_info_filename}"', input=None , stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True).stdout.decode()
            os.remove(privesc_info_filename)
            exploit_info = host_obj.exploit_info['exploit_info']
            system_info = host_obj.system_info['system_info']
            network_info = host_obj.network_info['network_info']
            all_local_mac_addresses = network_info['all_local_mac_addresses']
            ip_info = network_info['ip_info']
            dns_cache = network_info['dns_cache']
            arp_cache = network_info['arp_cache']
            routing_table = network_info['routing_table']
            active_ports = network_info['active_ports'].split('\r\n')
            parsed_active_ports = '\r\n'.join(active_ports[:4])
            for line in active_ports[4:]:
                if line.strip().startswith("TCP") or line.strip().startswith("UDP"):parsed_active_ports+=("\r\n"+line)
                else: parsed_active_ports+=f" - {line.strip()}"
            active_ports = parsed_active_ports

            nmap_info = {'nodes' : [], 'edges' : []}
            i=2
            net_id = 0
            for local_int, scan_result in host_obj.nmap_info['nmap_info'].items():
                local_int_ip = f"{local_int.split('/')[0]}"
                try: nmap_info['nodes'][0][2]+=f", {local_int_ip}"
                except: nmap_info['nodes'].append([1, '[THIS HOST]||'+'.'.join(host_obj.host_id.split('$')[1:3]), local_int_ip, True])
                local_int_ip_idx = 1
                scan_result = scan_result.split('\r\n')
                for line in scan_result:
                    if 'Nmap scan report for' in line:
                        remote_int_ip = line.split(' ')[-1].strip('(').strip(')')
                        remote_int_title = line.replace(f'({remote_int_ip})', '').replace('Nmap scan report for','').strip()
                        if remote_int_ip == local_int_ip: continue
                        nmap_info['nodes'].append([i, f'[net-{net_id}]||{remote_int_title}', remote_int_ip, False])
                        nmap_info['edges'].append([local_int_ip_idx, i])
                        i+=1
                net_id+=1

            eventlog_info = [eventloginfo.replace('\"', '').split('|') for eventloginfo in host_obj.eventlog_info['eventlog_info'].split('\r\n')[2:-1]]
            schedtask_info = [task_info.replace('\"', '').split('|') for task_info in host_obj.schedtask_info['schedtask_info'].split('\r\n')[2:-1]]
            
            ctx={
                'host_id' : host_id,
                'host_os_type' : host_obj.host_os_type,
                'agent_id' : host_obj.agent_id,
                'date_registered' : host_obj.date_registered,
                'date_modified' : host_obj.date_modified,
                'last_online' : host_obj.last_online,
                'online_status' : host_obj.online_status,
                'host_health' : host_obj.host_health,
                'system_info' : system_info,
                'settings' : host_obj.settings,
                'program_info' : program_info,
                'process_info' : process_info,
                'password_info_plain' : password_info_plain,
                'password_info_processed' : password_info_processed,
                'privesc_info' : privesc_info,
                'exploit_info' : exploit_info,
                'all_local_mac_addresses' : all_local_mac_addresses,
                'ip_info' : ip_info,
                'dns_cache' : dns_cache,
                'arp_cache' : arp_cache,
                'routing_table' : routing_table,
                'active_ports' : active_ports,
                'nmap_info' : nmap_info,
                'eventlog_info' : eventlog_info,
                'schedtask_info' : schedtask_info,
            }
        with open(f'{settings.BASE_DIR}\\config_files\\CMConfig.json', 'r') as f: ctx['CENTRAL_MONITOR_BASE_URL'] = json.loads(f.read())['CENTRAL_MONITOR_BASE_URL'].split(':')[0]
        return render(request=request, template_name='host_details_template.html', context=ctx)
