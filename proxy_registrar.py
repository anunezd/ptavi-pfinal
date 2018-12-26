#!/usr/bin/python3
# -*- coding: utf-8 -*-

import sys
import os
import json
import socket
import socketserver
import time as time_log
from datetime import datetime, date, time, timedelta
from hashlib import sha1
from xml.sax import make_parser
from xml.sax.handler import ContentHandler

FORMATO = '%Y%m%d%H%M%S'

config = {'server': ['name', 'ip', 'puerto'],
          'database': ['path','passwdpath'],
          'log': ['path']}

def digest_nonce(username):
    digest = sha1()
    digest.update(bytes(username,'utf-8'))
    digest.digest()
    return digest.hexdigest()

def digest_response(nonce,passwd):
    digest = sha1()
    digest.update(bytes(nonce,'utf-8'))
    digest.update(bytes(passwd,'utf-8'))
    digest.digest()
    return digest.hexdigest()

class Log_Writer:

    def __init__(self, log_file, date_format):

        if not os.path.exists(log_file):
            os.system('touch ' + log_file)
        self.file = log_file
        self.date_format= date_format

    def get_date(self):

        return time_log.strftime((self.date_format),time_log.gmtime(time_log.time() + 3600))

    def write(self,line):

        with open(self.file, 'a') as log:
            log.write(line + '\n')

    def starting(self):

        line = self.get_date() + ' Starting...'
        self.write(line)

    def sent_to(self,ip,port,mess):

        line = self.get_date() + ' Sent to '
        line += ip + ':' + port + ': ' + mess.replace('\r\n',' ')
        self.write(line)

    def received_from(self,ip,port,mess):

        line = self.get_date() + ' Received from '
        line += ip + ':' + port + ': ' + mess.replace('\r\n',' ')
        self.write(line)

    def error (self,type_error):

        line = self.get_date() + ' Error: ' + type_error
        self.write(line)

    def finishing(self):

        line = self.get_date() + ' Finishing.'
        self.write(line)


class XMLHandler(ContentHandler):

    def __init__(self,conf):

        self.list = {}
        self.dtd = conf

    def startElement(self, name, attrs):
        if name in self.dtd:
            for att in self.dtd[name]:
                id = name + '_' + att
                self.list[id] = attrs.get(att, '')

    def get_tags(self):
        return self.list

class SIPRegisterHandler(socketserver.DatagramRequestHandler):

    dicc = {}
    lista = []
    passwd = {}

    def handle(self):
        self.json2registered()
        line = self.rfile.read().decode('utf-8')
        ip = self.client_address[0]
        port_src = self.client_address[1]
        log.received_from(ip,str(port_src),line.replace('\r\n',' '))
        doc = line.split('\r\n')
        print(line)
        if not 'SIP/2.0' in line:
            bad_request = True
        else:
            bad_request = False
        if 'REGISTER' in doc[0] and not bad_request:
            user = doc[0].split(':')[1]
            port = doc[0].split(':')[2].split()[0]
            tiempo = datetime.now()
            expires = doc[1].split(':')[1]
            if user in self.dicc:
                if int(expires) == 0:
                    try:
                        del self.dicc[user]
                        self.wfile.write(b"SIP/2.0 200 OK\r\n\r\n")
                        log.sent_to(ip,str(port_src),'SIP/2.0 200 OK')
                    except KeyError:
                        pass
                else:
                    expired = tiempo + timedelta(seconds=int(expires))
                    address = str(self.client_address[0]) + ":" + port
                    fecha = expired.strftime(FORMATO)
                    self.dicc[user] = {'Address': address, 'Expires': fecha}
                    self.wfile.write(b"SIP/2.0 200 OK\r\n\r\n")
                    log.sent_to(ip,str(port_src),'SIP/2.0 200 OK')
            else:
                #401 unathorized
                if not 'Digest response' in line:
                    line = 'SIP/2.0 401 Unathorized\r\nWWW Authenticate: '
                    line += 'Digest nonce="' + digest_nonce(user) + '"\r\n\r\n'
                    self.wfile.write(bytes(line,'utf-8'))
                    log.sent_to(ip,str(port_src), line.replace('\r\n',' '))
                else:
                    dig_response = digest_response(digest_nonce(user),self.passwd[user])
                    dig_response_user = line.split('"')[1]
                    if dig_response == dig_response_user:
                        expired = tiempo + timedelta(seconds=int(expires))
                        address = str(self.client_address[0]) + ":" + port
                        fecha = expired.strftime(FORMATO)
                        self.dicc[user] = {'Address': address, 'Expires': fecha}
                        self.wfile.write(b"SIP/2.0 200 OK\r\n\r\n")
                        log.sent_to(ip,str(port_src),'SIP/2.0 200 OK')
                    else:
                        pass
        elif 'INVITE' or 'BYE' or 'ACK' in doc[0] and not bad_request:
            user_dst = line.split('\r\n')[0].split()[1].split(':')[1]
            if user_dst in self.dicc:
                ip = self.dicc[user_dst]['Address'].split(':')[0]
                puerto = self.dicc[user_dst]['Address'].split(':')[1]
                res = self.resent(ip, puerto, line)
                print(res)
                if res != '':
                    print('upsie')
                    self.wfile.write(bytes(res,'utf-8'))
                    log.sent_to(ip,str(port_src),res.replace('\r\n',' '))
                    print('upsie')
        else:
            if not bad_request:
                #405 method not allowed
                self.wfile.write(b"SIP/2.0 405 Method not Allowed\r\n\r\n")
                log.sent_to(ip,str(port_src),'SIP/2.0 405 Method not Allowed')
            else:
                # enviar 400 Bad Request
                self.wfile.write(b"SIP/2.0 400 Bad Request\r\n\r\n")
                log.sent_to(ip,str(port_src),'SIP/2.0 400 Bad Request')

        self.register2json()

    def resent(self, ip, puerto, line):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as my_socket:
            my_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            my_socket.connect((ip, int(puerto)))
            print("Enviando: " + line)
            log.sent_to(ip,puerto,line.replace('\r\n', ' '))
            my_socket.send(bytes(line, 'utf-8'))
            try:
                data = my_socket.recv(1024).decode('utf-8')
                log.received_from(ip,str(puerto),data.replace('\r\n', ' '))
            except:
                data = ''
        return data

    def register2json(self):
        with open(tags['database_path'], 'w') as outfile_json:
            json.dump(self.dicc, outfile_json, indent=3)

    def json2registered(self):
        try:
            with open(tags['database_path'], 'r') as reg_json:
                self.dicc = json.load(reg_json)
            with open(tags['database_passwdpath'], 'r') as passwd_json:
                self.passwd = json.load(passwd_json)
        except:
            pass

if __name__ == "__main__":

    if len(sys.argv) != 2:
        sys.exit(usage_error)
    else:
        xml_file = sys.argv[1]
    parser = make_parser()
    xmlhandler = XMLHandler(config)
    parser.setContentHandler(xmlhandler)
    parser.parse(open(xml_file))
    tags = xmlhandler.get_tags()
    log = Log_Writer(tags['log_path'],FORMATO)
    ip = tags['server_ip']
    puerto = int(tags['server_puerto'])
    serv = socketserver.UDPServer((ip, puerto), SIPRegisterHandler)
    log.starting()
    print("Lanzando servidor UDP de eco...\n")
    try:
        serv.serve_forever()
    except KeyboardInterrupt:
        print("Finalizado servidor")
        log.finishing()
