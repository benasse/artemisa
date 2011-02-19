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

# Set a path to the main root
sys.path.append("../")

from subprocess import Popen
from subprocess import PIPE

from libs.IPy.IPy import *       # Module to deal with IPs

from modules.logger import logger

def CheckDNS(strIP, verbose):

    if strIP == "": return 0
    
    DataToSend = ""
    
    # Check if strIP is an IP or a host name
    bDNS = False
    try:
        IP(strIP)
    except:
        bDNS = True
            
    if not bDNS: # It's an IP
        # If the address passed is an IP address we will not analyze it with reverse techniques (by now).
        # TODO: Future implementations my consider this.
        return "not DNS"
        
        
        #try:        
        #    Command = "dig -x " + strIP + " +short"
        #    Process = Popen(Command, shell=True, stdout=PIPE)
        #    Process.wait()
        #    Data = Process.communicate()[0].strip().split("\n")
        #        
        #    if verbose:
        #        DataToSend = "+ Verbose" + "\n"
        #        DataToSend = DataToSend + "| Tool employed: " + Command + "\n"
        #        DataToSend = DataToSend + "|" + "\n"
        #        
        #        DataToSend = DataToSend + "| Tool output:" + "\n"
        #        for line in Data:
        #            DataToSend = DataToSend + "| " + line + "\n"
        #        DataToSend = DataToSend + "\n"
        #        
        #    strIP = Data[0]
        #    
        #    if strIP == "": 
        #        return DataToSend + "Domain name resolved: none"
        #    else:
        #        return DataToSend + "Domain name resolved: " + strIP
        #        
        #except OSError:
        #    print "WARNING dig command is not installed."
        #    return -1
    else:
         
        # The DNS analysis consists of a DNS lookup and a WHOIS search.
            
        try:      
            Command = "dig " + strIP + " A +noall +answer +short"  
            Process = Popen(Command, shell=True, stdout=PIPE)
            Process.wait()
            Data = Process.communicate()[0].strip().split("\n")
            IPResolved = Data[len(Data)-1]
                            
            if verbose:
                DataToSend = "+ Verbose" + "\n"
                DataToSend = DataToSend + "| Tool employed: " + Command + "\n"
                DataToSend = DataToSend + "|" + "\n"
                
                DataToSend = DataToSend + "| Tool output:" + "\n"
                for line in Data:
                    DataToSend = DataToSend + "| " + line + "\n"
                DataToSend = DataToSend + "\n"
                            
        except OSError:
            logger.warning("dig command is not installed.")
            return -1

        # Try to use the whois command. If it fails, perhaps the command is not installed.
        try:
            # Store the whois' return in a variable.
            Command = "whois " + strIP
            Process = Popen(Command, shell=True, stdout=PIPE)
            Process.wait()
            Data = Process.communicate()[0]
            
            if verbose:
                DataToSend = DataToSend + "+ Verbose" + "\n"
                DataToSend = DataToSend + "| Tool employed: " + Command + "\n"
                DataToSend = DataToSend + "|" + "\n"
                DataToSend = DataToSend + "| Tool output: -too large to show here-" + "\n"
                DataToSend = DataToSend + "\n"
                
            # TODO: this parsing is weak and could be improved.
            if Data.find("NOT FOUND") != -1 or Data.find("No match for domain") != -1:
                WhoisDataFound = False
            else:
                WhoisDataFound = True
                
        except OSError:
            logger.warning("whois is not installed.")
            return -1   
    
        if IPResolved == "": 
            return DataToSend + "IP resolved: none"
        else:
            if WhoisDataFound:
                return DataToSend + "IP resolved: " + IPResolved + "\n" + "WHOIS data found."
            else:
                return DataToSend + "IP resolved: " + IPResolved + "\n" + "WHOIS data not found."
    
if __name__ == '__main__':
    if len(sys.argv) > 2:
        print CheckDNS(sys.argv[1], sys.argv[2])
    else:
        print "Arguments are required!"
        sys.exit(1)
