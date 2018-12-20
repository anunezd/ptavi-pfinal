#!/usr/bin/python3
# -*- coding: utf-8 -*-

import sys
import os
from xml.sax import make_parser
from xml.sax.handler import ContentHandler
from proxy_registrar import XMLHandler

usage_error = 'usage: python3 uaclient.py config method option'
method_allowed = ['register', 'invite', 'bye']

if len(sys.argv) != 4:
    sys.exit(usage_error)
else:
    xml_file = sys.argv[1]
    method = sys.argv[2]
    option = sys.argv[3]

config = {'account': ['username', 'passwd'],
          'username': ['ip', 'puerto'],
          'rtaudio:': ['puerto'],
          'regproxy': ['ip', 'puerto'],
          'log': ['path'],
          'audio': ['path']}


class Log_Writer:

    def __init__(self, log_file, date_format):

        if not os.path.exists(log_file):
            os.system('touch ' + log_file)
        self.file = log_file
        self.date_format= date_format

    def get_date(self):

        return time.strftime((self.date_format),time.gmtime(time.time() + 3600))

    def write(self,line):

        with open(self.file, 'a') as log:
            log.write(line)

    def starting(self):

        line = self.get_date + ' Starting...'
        self.write(line)

    def sent_to(self,ip,port,mess):

        line = self.get_date + ' Sent to '
        line += ip + ':' + port + ': ' + mess.replace('\r\n',' ')
        self.write(line)

    def received_from(self,ip,port,mess):

        line = self.get_date + ' Received from '
        line += ip + ':' + port + ': ' + mess.replace('\r\n',' ')
        self.write(line)

    def error (self,type_error):

        line = self.get_date + ' Error: ' + type_error
        self.write(line)

    def finishing(self):

        line = self.get_date + ' Finishing...'
        self.write(line)

parser = make_parser()
xmlhandler = XMLHandler(config)
parser.setContentHandler(xmlhandler)
parser.parse(open(xml_file))
tags = xmlhandler.get_tags()
log = Log_Writer(tags['log_path'], '%Y%m%d%H%M%S')
