#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""
Clase (y programa principal) para un servidor de eco en UDP simple
"""

import sys
import os
import socketserver
from xml.sax import make_parser
from xml.sax.handler import ContentHandler
from proxy_registrar import XMLHandler, Log_Writer

FORMATO = '%Y%m%d%H%M%S'


class EchoHandler(socketserver.DatagramRequestHandler):
    mp32rtp = []

    def handle(self):
        line = self.rfile.read().decode('utf-8')
        ip = self.client_address[0]
        port = self.client_address[1]
        log.received_from(ip, str(port), line.replace('\r\n', ' '))
        print(line)
        if 'INVITE' in line:
            ip_dst = line.split('\r\n')[4].split()[-1]
            port_dst = line.split('\r\n')[7].split()[1]
            self.mp32rtp.append(ip_dst)
            self.mp32rtp.append(port_dst)
            mess = 'SIP/2.0 100 Trying\r\n\r\n'
            mess += 'SIP/2.0 180 Ringing\r\n\r\n'
            mess += 'SIP/2.0 200 OK\r\n'
            mess += 'Content-Type: application/sdp\r\n\r\n'
            mess += 'v=0\r\no=' + tags['account_username'] + ' '
            mess += tags['uaserver_ip']
            mess += '\r\ns=sesionnueva\r\nt=0\r\n'
            mess += 'm=audio ' + tags['rtpaudio_puerto'] + ' RTP\r\n\r\n'
        elif 'ACK' in line:
            ip = self.mp32rtp[0]
            puerto = self.mp32rtp[1]
            cvlc = 'cvlc rtp://@ ' + ip + ':' + puerto + ' & '
            cvlc += './mp32rtp -i ' + ip + ' -p ' + puerto
            cvlc += ' < ' + tags['audio_path']
            os.system(cvlc)
            if self.mp32rtp != '':
                print('ejecutando: ' + cvlc)
                self.mp32rtp = []
        elif 'BYE' in line:
            mess = 'SIP\2.0 200 OK\r\n\r\n'
        else:
            mess = 'SIP\2.0 405 Method Not Allowed\r\n\r\n'
        if 'ACK' not in line:
            self.wfile.write(bytes(mess, 'utf-8'))
            log.sent_to(ip, str(port), mess.replace('\r\n', ' '))


if __name__ == "__main__":
    config = {'account': ['username', 'passwd'],
              'uaserver': ['ip', 'puerto'],
              'rtpaudio': ['puerto'],
              'regproxy': ['ip', 'puerto'],
              'log': ['path'],
              'audio': ['path']}
    # Creamos servidor de eco y escuchamos
    if len(sys.argv) != 2:
        sys.exit('Usage: python3 uaserver.py config')
    else:
        xml_file = sys.argv[1]
    parser = make_parser()
    xmlhandler = XMLHandler(config)
    parser.setContentHandler(xmlhandler)
    parser.parse(open(xml_file))
    tags = xmlhandler.get_tags()
    log = Log_Writer(tags['log_path'], FORMATO)
    ip = tags['uaserver_ip']
    puerto = int(tags['uaserver_puerto'])
    serv = socketserver.UDPServer((ip, puerto), EchoHandler)

    print("Lanzando servidor UDP de eco...\n")
    log.starting()
    try:
        serv.serve_forever()
    except KeyboardInterrupt:
        print("Finalizado servidor")
        log.finishing()
