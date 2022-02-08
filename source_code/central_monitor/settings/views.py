from django.shortcuts import render
from central_monitor.my_decorators import superuser_required
import json
from pathlib import Path
from django.contrib.auth.models import User, Permission
from django.http import Http404, HttpResponseBadRequest, JsonResponse
from django.conf import settings

# Create your views here.

@superuser_required
def settings_view(request, *args, **kwargs):
    is_ajax = request.headers.get('X-Requested-With') == 'XMLHttpRequest' # https://testdriven.io/blog/django-ajax-xhr/
    if is_ajax:
        if request.method == 'POST':
            with open(f'{settings.BASE_DIR}/config_files/CMConfig.json', 'r') as sf: current_settings = json.load(sf)
            try:
                data = json.load(request)
                action = data.get('action')
                settings_updates = data.get('settings')

                # parse comma separated settings that were supplied as string and convert them to list
                if type(settings_updates.get('TCP_HONEYPOT_PORTS', None)) == str: settings_updates['TCP_HONEYPOT_PORTS'] = list(set(settings_updates['TCP_HONEYPOT_PORTS'].replace(' ', '').split(',')))
                if type(settings_updates.get('UDP_HONEYPOT_PORTS', None)) == str: settings_updates['UDP_HONEYPOT_PORTS'] = list(set(settings_updates['UDP_HONEYPOT_PORTS'].replace(' ', '').split(',')))
                if type(settings_updates.get('ADMIN_EMAIL_ADDRESSES', None)) == str: settings_updates['ADMIN_EMAIL_ADDRESSES'] = list(set(settings_updates['ADMIN_EMAIL_ADDRESSES'].replace(' ', '').split(',')))

                new_settings = {**current_settings, **settings_updates} # merge 2 dictionaries and the second dictionary's values overwriting those from the first # https://stackoverflow.com/questions/38987/how-do-i-merge-two-dictionaries-in-a-single-expression-take-union-of-dictionari
                with open(f'{settings.BASE_DIR}/config_files/CMConfig.json', 'w') as sf: json.dump(new_settings, sf)
                
                if action == 'CMSU':
                    return JsonResponse({'success': True, 'status_code': 200, 'msg': f'central monitor settings were updated.'}, status=200)
                elif action == 'HASU':
                    if User.objects.filter(username=new_settings['AGENT_AUTH_USERNAME']).exists():
                        if current_settings['AGENT_AUTH_PASSWORD'] != new_settings['AGENT_AUTH_PASSWORD']:
                            registrar_usr = User.objects.get(username=new_settings['AGENT_AUTH_USERNAME'])
                            registrar_usr.set_password(new_settings['AGENT_AUTH_PASSWORD'])
                            registrar_usr.save()
                    else:
                        registrar_usr = User.objects.create(username=new_settings['AGENT_AUTH_USERNAME'])
                        registrar_usr.set_password(new_settings['AGENT_AUTH_PASSWORD'])
                        registrar_usr.user_permissions.clear()
                        registrar_usr.user_permissions.add(Permission.objects.get(codename='add_host').id)
                        registrar_usr.save()
                    return JsonResponse({'success': True, 'status_code': 200, 'msg': f'host agent settings were updated.'}, status=200)
            except:
                with open(f'{settings.BASE_DIR}/config_files/CMConfig.json', 'w') as sf: json.dump(current_settings, sf)
                return JsonResponse({'success': False, 'status_code': 500, 'msg': f'internal server error.'}, status=500)

    else:
        if request.method == 'GET':
            try:
                with open(f'{settings.BASE_DIR}/config_files/CMConfig.json' , 'r') as sf:
                    conf = json.load(sf)
                    ctx = {
                        ########## CENTRAL MONITOR SETTINGS ##########
                        'ADMIN_EMAIL_ADDRESSES'                     :   ', '.join(conf.get('ADMIN_EMAIL_ADDRESSES', '')),
                        'NOTIFICATION_SERVICE_EMAIL'                :   conf.get('NOTIFICATION_SERVICE_EMAIL', ''),
                        'NOTIFICATION_SERVICE_PASSWORD'             :   conf.get('NOTIFICATION_SERVICE_PASSWORD', ''),
                        'NOTIFICATOIN_MINIMUM_ALERT_SEVERITY_SCORE' :   conf.get('NOTIFICATOIN_MINIMUM_ALERT_SEVERITY_SCORE', ''),
                        'EMAIL_ALERT_NOTIFICATION'                  :   conf.get('EMAIL_ALERT_NOTIFICATION', False),
                        'VIRUSTOTAL_API_KEY'                        :   conf.get('VIRUSTOTAL_API_KEY', ''),
                        'PROJECT_HONEYPOT_API_KEY'                  :   conf.get('PROJECT_HONEYPOT_API_KEY', ''),
                        'SHODAN_API_KEY'                            :   conf.get('SHODAN_API_KEY', ''),
                        
                        ############ HOST AGENT SETTINGS #############
                        'CENTRAL_MONITOR_ID'            :   conf.get('CENTRAL_MONITOR_ID', ''),
                        'CENTRAL_MONITOR_BASE_URL'      :   conf.get('CENTRAL_MONITOR_BASE_URL', ''),
                        'AGENT_AUTH_USERNAME'           :   conf.get('AGENT_AUTH_USERNAME', ''),
                        'AGENT_AUTH_PASSWORD'           :   conf.get('AGENT_AUTH_PASSWORD', ''),
                        'SYSTEM_MONITOR_PORT'           :   conf.get('SYSTEM_MONITOR_PORT', ''),
                        'TCP_HONEYPOT_PORTS'            :   ', '.join(conf.get('TCP_HONEYPOT_PORTS', '')),
                        'UDP_HONEYPOT_PORTS'            :   ', '.join(conf.get('UDP_HONEYPOT_PORTS', '')),
                        'NETWORK_INFO_UPDATES_FREQ'     :   conf.get('NETWORK_INFO_UPDATES_FREQ', ''),
                        'EVENT_LOGS_UPDATES_FREQ'       :   conf.get('EVENT_LOGS_UPDATES_FREQ', ''),
                        'PROC_DATA_UPDATES_FREQ'        :   conf.get('PROC_DATA_UPDATES_FREQ', ''),
                        'SYSTEM_INFO_UPDATES_FREQ'      :   conf.get('SYSTEM_INFO_UPDATES_FREQ', ''),
                        'NMAP_UPDATES_FREQ'             :   conf.get('NMAP_UPDATES_FREQ', ''),
                        'PROG_DATA_UPDATES_FREQ'        :   conf.get('PROG_DATA_UPDATES_FREQ', ''),
                        'SCHEDULED_TASKS_UPDATES_FREQ'  :   conf.get('SCHEDULED_TASKS_UPDATES_FREQ', ''),
                        'PASSWD_DATA_UPDATES_FREQ'      :   conf.get('PASSWD_DATA_UPDATES_FREQ', ''),
                        'PRIVESC_UPDATES_FREQ'          :   conf.get('PRIVESC_UPDATES_FREQ', ''),
                        'EXPLOIT_UPDATES_FREQ'          :   conf.get('EXPLOIT_UPDATES_FREQ', ''),
                    }
            except: ctx = {}
            return render(request=request, template_name='settings_template.html', context=ctx)
