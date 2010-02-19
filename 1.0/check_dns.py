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

# def CheckDNS

def CheckDNS(strIP, verbose):

    if strIP == "": return 0
    
    Output = PrintClass()
    
    # Check if strIP is an IP or a host name
    bDNS = False
    try:
        temp = IP(strIP)
    except:
        bDNS = True
            
    if bDNS == False: # It's an IP
        try:        
            strCommand = "dig -x " + strIP + " +short"
            Process = Popen(strCommand, shell=True, stdout=PIPE)
            Process.wait()
            strData = Process.communicate()[0].strip().split("\n")
                
            if verbose == True:
                Output.Print("| | Tool employed: " + strCommand)
                Output.Print("| |")
                
                Output.Print("| | + Tool output:")
                for line in strData:
                    Output.Print("| | | " + line)
                Output.Print("| |")
                
            strIP = strData[0]
            
            if strData == "": return 0
            
            return "Domain name resolved: " + strIP
                
        except OSError:
            print "WARNING dig command is not installed."
            return -1
    else:
            
        try:      
            strCommand = "dig " + strIP + " A +noall +answer +short"  
            Process = Popen(strCommand, shell=True, stdout=PIPE)
            Process.wait()
            strData = Process.communicate()[0].strip().split("\n")
            strIP = strData[len(strData)-1]
                            
            if verbose == True:
                Output.Print("| | Tool employed: " + strCommand)
                Output.Print("| |")
                
                Output.Print("| | + Tool output:")
                for line in strData:
                    Output.Print("| | | " + line)
                Output.Print("| |")
                            
            if strData == "": return 0
            
            return "IP resolved: " + strIP
                
        except OSError:
            print "WARNING dig command is not installed."
            return -1
        
    
    
if __name__ == '__main__':
    if len(sys.argv) > 2:
         print CheckDNS(sys.argv[1], sys.argv[2])
    else:
        print "Arguments are required!"
        sys.exit(1)