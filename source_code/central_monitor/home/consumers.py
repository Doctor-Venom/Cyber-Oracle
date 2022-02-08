#THIS IS FOR DJANGO CHANNELS
import json
from channels.generic.websocket import WebsocketConsumer
import subprocess
from sys import platform
from django.conf import settings
import re
import threading
import os
from api.models import Host, determine_host_ip
from api.management.commands.COP_server import verify_PDU_signature, sign_PDU, get_next_PDU_ID, construct_COP_PDU, CENTRAL_MONITOR_COP_PDU_handler
import socket

# https://github.com/pexpect/ptyprocess
# https://stackoverflow.com/questions/45228395/error-no-module-named-fcntl 
# would be great to use the following to make curses interaction with hashcat to pause, quit, reasume, etc... but it is not available on windows platform
# from ptyprocess import PtyProcessUnicode 


class xterm_terminal_consumer(WebsocketConsumer):
    def connect(self):
        self.accept()
        if platform == "linux":
            self.shell_instance = subprocess.Popen('bash', stdout=subprocess.PIPE, stdin=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        elif platform == "win32":
            self.shell_instance = subprocess.Popen('cmd', stdout=subprocess.PIPE, stdin=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
            self.shell_instance.stdin.write((f'\r\ncd "{settings.BASE_DIR}\\static\\app_utilities\\hashcat\\"\r\ncls\r\n').encode()) # https://hashcat.net/forum/thread-7953.html
            self.shell_instance.stdin.flush()
            self.shell_instance.stdout.flush()
        elif platform == "darwin":
            pass

    def disconnect(self, close_code):
        self.close()

    def receive(self, text_data):
        args = json.loads(text_data)['arguments']
        if platform == "linux":
            args = args.replace('#hashcat#', f'"{settings.BASE_DIR}/static/app_utilities/hashcat/hashcat.bin"')
            args = args.replace('#rockyou.txt#', f'"{settings.BASE_DIR}/static/wordlists/rockyou.txt"')
            try:
                hash_filename_match = re.search(r"#[\S]*#", args).group()
                args = args.replace(hash_filename_match, f'"{settings.BASE_DIR}\\static\\app_utilities\\temp\\{hash_filename_match.strip("#")}"')
            except: pass
        elif platform == "win32":
            args = args.replace('#hashcat#', f'"{settings.BASE_DIR}\\static\\app_utilities\\hashcat\\hashcat.exe"')
            args = args.replace('#rockyou.txt#', f'"{settings.BASE_DIR}\\static\\wordlists\\rockyou.txt"')
            try:
                hash_filename_match = re.search(r"#[\S]*#", args).group()
                args = args.replace(hash_filename_match, f'"{settings.BASE_DIR}\\static\\app_utilities\\temp\\{hash_filename_match.strip("#")}"')
            except: pass
        elif platform == "darwin": pass

        self.shell_instance.stdin.flush()
        self.shell_instance.stdin.write(('\r\n'+args+'\r\n').encode())
        self.shell_instance.stdin.write(('\r\nECHO END_OF_STDOUT\r\n').encode())
        self.shell_instance.stdin.flush()

        while True:
            line = self.shell_instance.stdout.readline().decode().strip()
            if 'END_OF_STDOUT' in line:
                line = self.shell_instance.stdout.readline()
                self.shell_instance.stdout.flush()
                break
            self.send(text_data=json.dumps({'data': line}))
        self.send(text_data=json.dumps({'data': 'HASHCAT_TERMINATED'}))
        threading.Thread(target=self.on_hashcat_terminated, args=(hash_filename_match.strip('#'),), daemon=True).start()

    def on_hashcat_terminated(self, hashes_filename):
        if platform == "linux":
            pass # TODO: not implemented yet
        elif platform == "win32":
            hashcat_dir=f'{settings.BASE_DIR}\\static\\app_utilities\\hashcat'
            password_hash_matrix_filename = f'{settings.BASE_DIR}\\static\\app_utilities\\temp\\password_hash_matrix.json'
            if os.path.exists(password_hash_matrix_filename):
                with open(password_hash_matrix_filename, 'r') as f: password_hash_matrix=json.loads(f.read()) 
            else: return
            if 'NTLM' in hashes_filename:
                cracked_hashes = subprocess.run(f'"{hashcat_dir}\\hashcat.exe" --show -m 1000 "{settings.BASE_DIR}\\static\\app_utilities\\temp\\{hashes_filename}"', input=None , stdout=subprocess.PIPE, shell=True, cwd=hashcat_dir).stdout.decode()
                for cracked_hash in cracked_hashes.split('\r\n'):
                    for host, hashes in password_hash_matrix['NTLM'].items():
                        for hashed_passwd, plain_passwd in hashes.items():
                            if len(cracked_hash.split(':')[0]) >= 32 and cracked_hash.split(':')[0] in hashed_passwd.strip(":").split(":")[-1]:
                                if cracked_hash.split(':')[-1] == '':
                                    password_hash_matrix['NTLM'][host][hashed_passwd] = "NO PASSWORD! (Empty)"
                                    # self.send(text_data=json.dumps({'cracked_hash': "NO PASSWORD! (Empty)"})) # TODO: send back cracked hash, and somehow dynamically update the bootstrap tree view with it
                                else:
                                    password_hash_matrix['NTLM'][host][hashed_passwd] = cracked_hash.split(':')[-1]
                                    # self.send(text_data=json.dumps({'cracked_hash': cracked_hash.split(':')[-1]})) # TODO: send back cracked hash, and somehow dynamically update the bootstrap tree view with it
            elif "SOME_OTHER_HASH" in hashes_filename:
                pass # TODO: not implemented yet
            with open(password_hash_matrix_filename, 'w') as f: f.write(json.dumps(password_hash_matrix))
        elif platform == "darwin":
            pass

class host_control_consumer(WebsocketConsumer):
    def connect(self):
        self.accept()
        self.host_ip = None

    def disconnect(self, close_code):
        try:
            self.conn.sendall('#TERMINATE#'.encode())
            self.conn.close()
            self.conn = None
        except: pass
        self.close()

    def receive(self, text_data):
        ws_data = json.loads(text_data)
        self.host_id = ws_data['host_id']
        if self.host_ip == None:
            self.host_ip = determine_host_ip(host_id=self.host_id, host_obj=None)
            if self.host_ip == None:
                self.send(text_data=json.dumps({'success': False, 'data': 'UNKNOWN IP ADDRESS. HOST IS UNREACHABLE'}))
                return
            # NOTE: the check below is not necessary
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as conn:
                    conn.connect((self.host_ip, 51337))
                    conn.settimeout(10) # 10 seconds timeout
                    conn.sendall(construct_COP_PDU(0, {'code': 0, 'host_id': self.host_id}))
                    data = conn.recv(16384).decode()
                    if data: self.send(text_data=json.dumps({'success': True, 'data': 'HOST IS REACHABLE'}))
            except: self.send(text_data=json.dumps({'success': False, 'data': 'HOST IS UNREACHABLE'}))


        action = ws_data['action']
        if action == 'command':
            self.send_command_to_host(ws_data['command_id'])
        elif action == 'shell':
            self.shell_manager(ws_data)
        elif action == 'system_monitor':
            self.system_monitor_manager(ws_data)


    def send_COP_PDU_close(self, PDU):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as conn:
                conn.connect((self.host_ip, 51337))
                conn.settimeout(10) # 10 seconds timeout
                conn.sendall(PDU)
                conn.close()
            return True
        except:
            self.send(text_data=json.dumps({'success': False, 'data': 'COMMUNICATION ERROR DESTINATION UNREACHABLE'}))
            return False

    def shell_manager(self, ws_data):
        shell_manager_action = ws_data['shell_manager_action']
        if shell_manager_action == 'start':
            self.conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.conn.settimeout(10)
            try:
                self.conn.connect((self.host_ip, 51337))
                PDU = construct_COP_PDU(1, {'command_id': 1, 'host_id': self.host_id})
                self.conn.sendall(PDU)
                self.send(text_data=json.dumps({'success': True, 'shell_line': '\rDONT USE "exit" TO TERMINATE THE MAIN SHELL! TYPE "#TERMINATE#" OR USE THE BUTTON INSTEAD.\r\n'}))
                self.send(text_data=json.dumps({'success': True, 'shell_manager_action': 'start'}))
            except:
                self.send(text_data=json.dumps({'success': False, 'shell_manager_action': 'start'}))
        elif shell_manager_action == 'stop':
            self.conn.sendall('#TERMINATE#'.encode())
            self.conn.close()
            self.conn = None
            self.send(text_data=json.dumps({'success': True, 'shell_line': '#SHELL_TERMINATED#\n'}))
            self.send(text_data=json.dumps({'success': True, 'shell_manager_action': 'stop'}))
            return
        elif shell_manager_action == 'send_cmd':
            self.conn.sendall(ws_data['cmd'].encode())
            self.send(text_data=json.dumps({'success': True, 'shell_manager_action': 'send_cmd'}))

        blank_count = 0
        while True:
            try:
                line = self.conn.recv(16384).decode()
                if line == "": blank_count+=1
                else: blank_count = 0
                if blank_count >= 10: raise Exception("Received Too Many Blank Lines... Something Went Wrong.")
                if 'END_OF_STDOUT' in line:
                    self.send(text_data=json.dumps({'success': True, 'shell_line': line.strip('END_OF_STDOUT\r\n')}))
                    break
                self.send(text_data=json.dumps({'success': True, 'shell_line': line}))
            except:
                self.send(text_data=json.dumps({'success': True, 'shell_line': "READLINE TIMED OUT!!!"}))
                self.conn.sendall('#TERMINATE#'.encode())
                self.conn.close()
                self.conn = None
                self.send(text_data=json.dumps({'success': True, 'shell_line': '#SHELL_TERMINATED#\n'}))
                self.send(text_data=json.dumps({'success': True, 'shell_manager_action': 'stop'}))
                return

    def system_monitor_manager(self, ws_data):
        sysmon_manager_action = ws_data['sysmon_manager_action']
        if sysmon_manager_action == 'start':
            PDU=construct_COP_PDU(1, {'command_id': 7, 'host_id': self.host_id})
            res = self.send_COP_PDU_close(PDU)
        elif sysmon_manager_action == 'keep_up':
            PDU=construct_COP_PDU(0, {'code': 2, 'host_id': self.host_id})
            res = self.send_COP_PDU_close(PDU)
        elif sysmon_manager_action == 'stop':
            PDU=construct_COP_PDU(0, {'code': 3, 'host_id': self.host_id})
            res = self.send_COP_PDU_close(PDU)
        if res: self.send(text_data=json.dumps({'success': True, 'sysmon_manager_action': sysmon_manager_action, 'host_ip': self.host_ip}))

    def send_command_to_host(self, command_id):
        PDU=construct_COP_PDU(1, {'command_id':command_id, 'host_id':self.host_id})
        res = self.send_COP_PDU_close(PDU)
        if res: self.send(text_data=json.dumps({'success': True, 'command_id': command_id}))
    
    
