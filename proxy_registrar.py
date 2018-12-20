#!/usr/bin/python3
# -*- coding: utf-8 -*-

from xml.sax import make_parser
from xml.sax.handler import ContentHandler

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
