# https://stackoverflow.com/questions/19475955/using-django-models-in-external-python-script

from django_daemon_command.management.base import DaemonCommand
from django.utils import timezone
from api.models import Host
from alerts.models import Alert
import threading, socket, json, time
from typing import Final
import random
import logging
from django.conf import settings

############################################### LOGGING CONFIGURATION #####################################################╗
#region
logfile_path = f'{settings.BASE_DIR}\\api\\management\\commands\\COP_server_logs.txt'
logging.basicConfig(filename=logfile_path, filemode='a', format='[%(asctime)s] - %(levelname)s - %(funcName)s - (%(thread)d) : %(message)s')
logging.root.setLevel(logging.INFO)
#endregion
###########################################################################################################################╝


class Command(DaemonCommand):
    help = 'Start Cyber Oracle Protocol Server As A Daemon Process'

    def process(self, *args, **options):
        """ Do your work here """
        # to see logs logged by self.log() use `SELECT * FROM daemon_command_log;` NOTE: i am no longer using the DB to store logs, i use logging instead to write logs to a file
        CENTRAL_MONITOR_COP_server(self)


PDU_history = {}
ip_history = []

def verify_PDU_signature(signed_PDU): # returns true if the signatre is valid, returns false otherwise
    signed_data, signature = signed_PDU[:-1], signed_PDU[-1]
    #TODO: note implemented yet
    return True

def sign_PDU(PDU_to_be_signed):
    # TODO: not implemented yet
    PDU_to_be_signed.append('S1GN4TUR3')
    return PDU_to_be_signed
    
def get_next_PDU_ID():
    return str(time.time()).replace('.','')+str(random.getrandbits(32))

def construct_COP_PDU(payload_type, payload):
    protocol_version = 1
    PDU_ID = get_next_PDU_ID()
    timestamp = time.time()
    PDU = [protocol_version, PDU_ID, timestamp, payload_type, payload]
    PDU = sign_PDU(PDU)
    PDU = json.dumps(PDU).encode()
    return PDU

def CENTRAL_MONITOR_COP_PDU_handler(PDU, conn, addr):
    if not PDU : return
    protocol_role: Final = 1 # central monitor
    global PDU_history
    if not PDU_history.get(addr, None): PDU_history[addr] = []
    logging.info(f'received PDU from {addr}: {PDU}') # TODO: remove
    PDU = json.loads(PDU.decode())
    protocol_version, PDU_ID, timestamp, payload_type, payload, signature = PDU
    
    assert(protocol_version == 1)
    if PDU_ID in [i[0] for i in PDU_history[addr]]: # NOTE: this is too expensive to compute, is it worth of it?
        logging.error('PDU PDU_ID error')
        Alert.objects.create(source_type='Local', source_id=None, severity_score=6, data={'data':{
            'general_info': 'Central Monitor received COP PDU with previously used PDU_ID.',
            'detail_info': f"""
                Received COP PDU contents:
                    protocol_version    : {protocol_version}
                    PDU_ID              : {PDU_ID}
                    timestamp           : {timestamp}
                    payload_type        : {payload_type}
                    payload             : {payload}
                    signature           : {signature}
                Sender information:
                    {addr}"""
        }}).save()
        return True
    PDU_history[addr].append((PDU_ID, timestamp)) 
    if -60 >= time.time() - int(timestamp) >= 60: # NOTE: time on monitored hosts must be same as the time on COP server, max difference is 1 minute
        Alert.objects.create(source_type='Local', source_id=None, severity_score=6, data={'data':{
            'general_info': 'Central Monitor received COP PDU with expired timestamp.',
            'detail_info': f"""
                Received COP PDU contents:
                    protocol_version    : {protocol_version}
                    PDU_ID              : {PDU_ID}
                    timestamp           : {timestamp}
                    payload_type        : {payload_type}
                    payload             : {payload}
                    signature           : {signature}
                Sender information:
                    {addr}"""
        }}).save()
        logging.error('PDU timestamp error')
        return True
    if not verify_PDU_signature(PDU):
        Alert.objects.create(source_type='Local', source_id=None, severity_score=6, data={'data':{
            'general_info': 'Central Monitor received COP PDU with invalid signature.',
            'detail_info': f"""
                Received COP PDU contents:
                    protocol_version    : {protocol_version}
                    PDU_ID              : {PDU_ID}
                    timestamp           : {timestamp}
                    payload_type        : {payload_type}
                    payload             : {payload}
                    signature           : {signature}
                Sender information:
                    {addr}"""
        }}).save()
        logging.error('invalid PDU signature')
        return True

    if payload_type == 0:#keepalive
        logging.info(f'received keepalive echo from {payload["host_id"]}-{addr}')
        code = payload['code']
        host_id = payload['host_id']
        if host_id != 'NOT_REGISTRED_YET':
            host_obj = Host.objects.get(host_id=host_id)
            host_obj.last_online = timezone.now()
            host_obj.save(update_fields=['last_online'])
        if code == 0:
            if protocol_role == 1:
                PDU = construct_COP_PDU(payload_type=0, payload={'code' : 1})
                conn.sendall(PDU)
                conn.close()
        elif code == 1: # general keepalive reply
            # not implemented on agent, because controller sends only keepalive echo, and agents only send keepalive replys
            if protocol_role == 1:
                logging.info(f'received keepalive reply from {payload["host_id"]}-{addr}')
                conn.close()
    elif payload_type == 2:#settings
        action = payload['action']
        if action == 0: #settings request
            if protocol_role == 1: # only central monitor should receive settings request and process it
                host_obj = Host.objects.get(host_id=payload['host_id'])
                host_settings = host_obj.settings
                host_obj.save(update_fields=['settings'])
                PDU = construct_COP_PDU(payload_type=2, payload={'action': 1, 'settings' : host_settings})
                conn.sendall(PDU)
                conn.close()
    elif payload_type == 3:#authenticate
        action = payload['action']
        if action == 0: # authentication request
            # TODO: not implemented yet
            pass
        elif action == 1: # authentication response
            # TODO: not implemented yet
            pass
    elif payload_type == 4:#alert
        if protocol_role == 1: # only the central monitor should receive alerts and process it
            
            alert = payload
            source_type = 'Host-Agent'
            source_id = alert['source_id']
            severity_score = alert['severity_score']
            data = {'data': alert['data']}
            try: # NOTE: there are some alerts that are recieved from agents before host registration is complete, so here we catch that and wait for 1 minute then try to create alert again
                Alert.objects.create(source_type=source_type, source_id=Host.objects.get(host_id=source_id), severity_score=severity_score, data=data).save()
            except:
                time.sleep(60)
                Alert.objects.create(source_type=source_type, source_id=Host.objects.get(host_id=source_id), severity_score=severity_score, data=data).save()
    else:#error
        #TODO: not implemented yet - return error code to the sender
        error_code = payload['error_code']
        pass

def connection_handler(conn, addr):
    with conn:
        logging.info(f'{addr} has connected to the socket server.')
        while True:
            try: PDU = conn.recv(65535) # timeout is set to 3 seconds, if nothing received during that time, the connection will be closed, won't it???
            # NOTE: is 65535 bytes enough for all kinds of outputs that can be received from the agents ???
            except: break
            CENTRAL_MONITOR_COP_PDU_handler(PDU, conn, addr)
        logging.info(f'{addr} has disconnected from the socket server.')

    
def CENTRAL_MONITOR_COP_server(self): # listen for connection from agents
    HOST = '0.0.0.0'    # listen for connections on all interfaces
    PORT = 51337        # Port to listen on (non-privileged ports are > 1023)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        logging.info(f'Cyber Oracle protocol server started on {HOST}:{PORT}')
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))# bind host address and port together
        s.listen(1024)# configure how many clients the server can simultaneously communicate with
        while True:
            conn, addr = s.accept()# Establish connection with client.
            logging.info(f'[+] new connection from {addr}.')
            conn.settimeout(3)
            ip_history.append((time.time(), addr))
            PDU_history[addr] = []
            threading.Thread(target=connection_handler, args=(conn, addr)).start() # start connection handler in a new thread


