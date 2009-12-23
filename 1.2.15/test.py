#!/usr/bin/env python
# -*- coding: UTF-8 -*-

import os
from time import strftime
from math import sqrt, pow
from subprocess import Popen, PIPE
from commons import PrintClass, GetSIPHeader, Search, GetTimeClass, GetIPfromSIP, GetExtensionfromSIP, RemoveComments, GetCPTmatrix,ResolveDNS
from modules.ip2country.ip2country import IP2Country # Downloaded from http://www.freenet.org.nz/python/ip2country/
from modules.IPy.IPy import *       # Module to deal with IPs
from logs import log                # Import class log from logs.py
import random                       # Random number generator
import ConfigParser                 # Read configuration files

from mail import Email
from htmlresults import get_results_html

print ResolveDNS("pole-nord.fr")
print GetIPfromSIP("From: \"3001\" asd@wea#~<asidpa:3s001@wdsww.ubp.edue231>1.ar>;tag=tn231@3xzl")
print GetIPfromSIP("Contact: <sip:52.81.12.209:9>")
print GetExtensionfromSIP("Contact: <sip:152.81.12.209:9>")

Output = PrintClass()

nSeq = 2
nSeq += 1

Output.Print("Duplicated INVITE arrived. Seq: " + str(nSeq))
Output.Print("Duplicated INVITE arrived. Seq: " + str(nSeq))
Output.Print("Duplicated INVITE arrived. Seq: " + str(nSeq))
Output.Print("Duplicated INVITE arrived. Seq: " + str(nSeq))
Output.Print("Duplicated INVITE arrived. Seq: " + str(nSeq))
Output.Print("Duplicated INVITE arrived. Seq: " + str(nSeq))
Output.Print("Duplicated INVITE arrived. Seq: " + str(nSeq))
Output.Print("Duplicated INVITE arrived. Seq: " + str(nSeq))