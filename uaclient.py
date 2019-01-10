#!/usr/bin/python3
# -*- coding: utf-8 -*-

import sys
import os
import socket
from xml.sax import make_parser
from xml.sax.handler import ContentHandler
from proxy_registrar import XMLHandler, digest_response, Log_Writer

usage_error = 'usage: python3 uaclient.py config method option'
method_allowed = ['register', 'invite', 'bye']


class SIPMessages:

    def __init__(self, username, ip, port, rtp_audio):

        self.user = username
        self.address = [ip, port]
        self.rtp_audio = rtp_audio

    def get_message(self, method, option, digest=''):
        if method.lower() == 'register':
            mess = self.register(option, digest)
        elif method.lower() == 'invite':
            mess = self.invite(option)
        elif method.lower() == 'bye':
            mess = self.bye(option)
        elif method.lower() == 'ack':
            mess = self.ack(option)
        else:
            mess = method.upper() + ' ' + self.user + ' SIP/2.0\r\n'

        return mess

    def register(self, option, digest=''):

        mess = 'REGISTER sip:' + self.user + ':' + self.address[1]
        mess += ' SIP/2.0\r\nExpires: ' + option
        if digest != '':
            mess += '\r\nAuthorization: Digest response="' + digest + '"'

        return mess + '\r\n'

    def invite(self, option):

        mess = 'INVITE sip:' + option + ' SIP/2.0\r\n'
        mess += 'Content-Type: application/sdp\r\n\r\n'
        mess += 'v=0\r\no=' + self.user + ' ' + self.address[0]
        mess += '\r\ns=sesionnueva\r\nt=0\r\n'
        mess += 'm=audio ' + self.rtp_audio + ' RTP'

        return mess + '\r\n'

    def bye(self, option):

        mess = 'BYE sip:' + option + ' SIP/2.0'

        return mess + '\r\n'

    def ack(self, option):

        mess = 'ACK sip:' + option + ' SIP/2.0'

        return mess + '\r\n'


if len(sys.argv) != 4:
    sys.exit(usage_error)
else:
    xml_file = sys.argv[1]
    method = sys.argv[2]
    if method.lower() == 'register':
        try:
            option = int(sys.argv[3])
        except ValueError:
            sys.exit(usage_error)
    else:
        option = sys.argv[3]

config = {'account': ['username', 'passwd'],
          'uaserver': ['ip', 'puerto'],
          'rtpaudio': ['puerto'],
          'regproxy': ['ip', 'puerto'],
          'log': ['path'],
          'audio': ['path']}


parser = make_parser()
xmlhandler = XMLHandler(config)
parser.setContentHandler(xmlhandler)
parser.parse(open(xml_file))
tags = xmlhandler.get_tags()
log = Log_Writer(tags['log_path'], '%Y%m%d%H%M%S')
acc_user = tags['account_username']
s_ip = tags['uaserver_ip']
s_puerto = tags['uaserver_puerto']
rtp_puerto = tags['rtpaudio_puerto']
sip_mess = SIPMessages(acc_user, s_ip, s_puerto, rtp_puerto)

log.starting()
pr_ip = tags['regproxy_ip']
pr_port = tags['regproxy_puerto']

with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as my_socket:
    my_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    my_socket.connect((pr_ip, int(pr_port)))
    line = sip_mess.get_message(method, str(option))
    print("Enviando: " + line)
    log.sent_to(pr_ip, pr_port, line.replace('\r\n', ' '))
    my_socket.send(bytes(line, 'utf-8') + b'\r\n')
    try:
        data = my_socket.recv(1024).decode('utf-8')
    except ConnectionRefusedError:
        log.error('No server listening at ' + pr_ip + ' port ' + pr_port)
        sys.exit('Conection refused')
    if data != '':
        log.received_from(pr_ip, pr_port, data.replace('\r\n', ' '))
        if '401' in data:
            # enviar digest response
            passwd = tags['account_passwd']
            nonce = data.split('"')[1]
            digest_response = digest_response(nonce, passwd)
            line = sip_mess.get_message(method, str(option), digest_response)
            log.sent_to(pr_ip, pr_port, line.replace('\r\n', ' '))
            my_socket.send(bytes(line, 'utf-8') + b'\r\n')
            try:
                data = my_socket.recv(1024).decode('utf-8')
                print(data)
                log.received_from(pr_ip, pr_port, data.replace('\r\n', ' '))
            except ConnectionRefusedError:
                no_ser_list = 'No server listening at '
                log.error(no_ser_list + pr_ip + ' port ' + pr_port)
                sys.exit('Conection refused')
        elif '200' in data:
            if '100' in data:
                if '180' in data:
                    # envia ack
                    line = sip_mess.get_message('ack', option)
                    my_socket.send(bytes(line, 'utf-8') + b'\r\n')
                    log.sent_to(pr_ip, pr_port, line.replace('\r\n', ' '))
                    ip = data.split('\r\n')[8].split()[-1]
                    port = data.split('\r\n')[11].split()[1]
                    cvlc = './mp32rtp -i ' + ip + ' -p ' + port + ' & '
                    cvlc += 'cvlc rtp://@' + ip + ':' + port
                    cvlc += ' < ' + tags['audio_path']
                    os.system(cvlc)
                    print('ejecutando: ' + cvlc)
            else:
                print(data.replace('\r\n', ' '))
        else:
            print(data.replace('\r\n', ' '))

log.finishing()
