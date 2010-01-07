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

print ResolveDNS(GetIPfromSIP("Via: SIP/2.0/UDP 192.168.10.4:1587;rport;branch=z9hG4bK44FE55FBBCC449A9A4BEB71869664AEC"))
print ResolveDNS(GetIPfromSIP("From: test <sip:test@338763>;tag=325602560"))
print ResolveDNS(GetIPfromSIP("To: <192.168.10.4>"))
print GetIPfromSIP("Contact: <sip:test@sip:thisisthecanary@192.168.10.7:192.168.10.4>")
print ResolveDNS(GetIPfromSIP("o=test 6909118 8715513 IN IP4 192.168.10.4"))
print IP("338763").strNormal()

Process = Popen("traceroute -4 -I -N 1 -n -q 1 -w 2 192.168.10.4 | wc -l", shell=True, stdout=PIPE)
Process.wait()
print (int(Process.communicate()[0].strip()) - 1)