# -*- coding: UTF-8 -*-

# This is part of Artemisa.
# 
# Artemisa is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# 
# Artemisa is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with Artemisa. If not, see <http://www.gnu.org/licenses/>.

import sys
from commons import PrintClass
from subprocess import Popen, PIPE
from libs.IPy.IPy import *       # Module to deal with IPs

# def CheckPort
#
# This function checks a given IP:port and it's used for both SIP and media ports analysis

def CheckPort(strIP, strPort, strTransport):

    if strIP == "" or strPort == "": return -1
    
    try:        
        if strTransport == "udp":
            Process = Popen("nmap -sU " + strIP + " -p " + strPort, shell=True, stdout=PIPE)
        elif strTransport == "tcp":
            Process = Popen("nmap -sS " + strIP + " -p " + strPort, shell=True, stdout=PIPE)
        
        Process.wait()
        
        strData = Process.communicate()[0].strip().split("\n")
        
        strState = ""
        
        # FIXME: The following lines parse the output returned by nmap. This part can be modified
        # in order to do a better parsing such as parsing the XML file. This will be for the future.
        for line in strData:
            if line.find(strPort + "/" + strTransport) != -1:
                strState = line.split(" ")[1]
                break
                
        if strState != "":
            return "Port state: " + strState
        else:
            return -1
            
                
    except OSError:
        print "WARNING nmap is not installed."
        return -1

        
    
    
if __name__ == '__main__':
    if len(sys.argv) == 4:
        print CheckPort(sys.argv[1], sys.argv[2], sys.argv[3])
    else:
        print "Arguments are required!"
        sys.exit(1)