from django.apps import AppConfig
from django.conf import settings
import os.path
from uuid import uuid4
import json

class SettingsConfig(AppConfig):
    name = 'settings'

    def ready(self):
        # on app ready, check if CMConfig.json exists, if not then create one with default value
        CMConfig_filename = f'{settings.BASE_DIR}/config_files/CMConfig.json'
        if not os.path.exists(CMConfig_filename):
            central_monitor_default_config = {
                ########## CENTRAL MONITOR SETTINGS ##########
                'ADMIN_EMAIL_ADDRESSES'                     :   [],
                'NOTIFICATION_SERVICE_EMAIL'                :   '',
                'NOTIFICATION_SERVICE_PASSWORD'             :   '',
                'NOTIFICATOIN_MINIMUM_ALERT_SEVERITY_SCORE' :   '6',
                'EMAIL_ALERT_NOTIFICATION'                  :   False,
                'VIRUSTOTAL_API_KEY'                        :   '',
                'PROJECT_HONEYPOT_API_KEY'                  :   '',
                'SHODAN_API_KEY'                            :   '',
                
                ############ HOST AGENT DEFAULT SETTINGS #############
                'CENTRAL_MONITOR_ID'            :   '[[[ MANDATORY OPTION NOT SET!!! ]]]',
                'CENTRAL_MONITOR_BASE_URL'      :   '[[[ MANDATORY OPTION NOT SET!!! ]]]',
                'AGENT_AUTH_USERNAME'           :   '[[[ MANDATORY OPTION NOT SET!!! ]]]',
                'AGENT_AUTH_PASSWORD'           :   '[[[ MANDATORY OPTION NOT SET!!! ]]]',
                'SYSTEM_MONITOR_PORT'           :   '61337',
                'TCP_HONEYPOT_PORTS'            :   [],
                'UDP_HONEYPOT_PORTS'            :   [],
                'NETWORK_INFO_UPDATES_FREQ'     :   '300',
                'EVENT_LOGS_UPDATES_FREQ'       :   '600',
                'PROC_DATA_UPDATES_FREQ'        :   '300',
                'SYSTEM_INFO_UPDATES_FREQ'      :   '3600',
                'NMAP_UPDATES_FREQ'             :   '1800',
                'PROG_DATA_UPDATES_FREQ'        :   '3600',
                'SCHEDULED_TASKS_UPDATES_FREQ'  :   '3600',
                'PASSWD_DATA_UPDATES_FREQ'      :   '10800',
                'PRIVESC_UPDATES_FREQ'          :   '86400',
                'EXPLOIT_UPDATES_FREQ'          :   '86400',
            }
            with open(CMConfig_filename, 'w') as sf: sf.write(json.dumps(central_monitor_default_config))
