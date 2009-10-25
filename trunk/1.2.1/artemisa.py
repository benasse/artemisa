#!/usr/bin/env python
# -*- coding: UTF-8 -*-

# Artemisa v1.2
# Copyright (C) 2009 Rodrigo do Carmo <rodrigodocarmo@gmail.com> 
# and Pablo Masri <pablomasri87@gmail.com>
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
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import sys
import os

import ConfigParser # Read configuration files.

from time import strftime, sleep, time
import sched
from logs import * # Import functions from logs.py
from commons import * # Import functions from commons.py
from inference import InferenceAnalysis # Inference engine (core of the honeypot).
import threading # Use of threads.

from subprocess import Popen, PIPE

try:
    import pjsua as pj
except ImportError:
    print ""
    print "Critical error:"
    print "Python SIP module MUST be installed!"
    print ""
    print "Download it from:"
    print "http://www.pjsip.org/download.htm"
    print ""
    print "Installation steps:"
    print "http://trac.pjsip.org/repos/wiki/Python_SIP/Build_Install"
    print ""
    sys.exit(0)


# Variables

strLocal_IP = ""                # Local IP
strLocal_port = ""              # Local port
strRegistrar_IP = ""            # Registrar server IP (Asterisk, SER, etc.)
strRegistrar_port = ""          # Registrar server port
intRegistrar_time = 10		# Time in minutes between REGISTRAR messeges sent to the server.
strSIPdomain = ""		# Local SIP domain
strUserAgent = ""		# User-Agent field
verbose = False
Sessions = []
RegSchedule = ""

thrAnalyzeCall = threading.Thread() # Thread used to analyze the received messages.

Extensions = [] # Store the extensions registered to the SIP server in order to pass them to the inference engine.

# Constants

current_call = None

intBuffer = 1024




# class Session
#
# Object created in order to keep the user data which an unique extension and related with one profile

class Session():

    Extension = ""
    Username = ""
    Password = ""

    Header_Register = ""            # Store the SIP header of REGISTER message
    Header_Register_auth = ""       # Same with credentials
    Header_Options_ok = ""          # Same for OPTIONS message
    
    Branch = ""
    BranchNum = 0
    MaxForwards = ""
    Tag = ""
    TagNum = 0
    CallID = ""
    CallIDNum = 0
    CSeq = 0
    Nonce = ""               
    Realm = ""
    Response = ""
"""
    def GetProfile(self,strFile):
  
        global strLocal_IP
        global strLocal_port
        global strRegistrar_IP
        global strRegistrar_port
    
        reading_register = False # Flag to know which part is being read
        reading_register_auth = False # Same
        reading_options_ok = False # Same
        
        f = open("./profiles/" + strFile, "r")
                
        for line in f:

            if line.find("}") != -1:
                reading_register = False
                reading_register_auth = False
                
            # Each variable must be replaced by its value
            # Python has a method to replace strings!!!
            line = line.replace("$registrar_ip$", strRegistrar_IP)
            line = line.replace("$registrar_port$", strRegistrar_port)
            line = line.replace("$local_ip$", strLocal_IP)
            line = line.replace("$local_port$", strLocal_port)
            line = line.replace("$user$", self.Username)
            line = line.replace("$extension$", self.Extension)

            if reading_register == True:
                self.Header_Register += line.strip() + "\r\n"

            if reading_register_auth == True:
                self.Header_Register_auth += line.strip() + "\r\n" 

            if reading_options_ok == True:
                self.Header_Options_ok += line.strip() + "\r\n"
                           
            if line[0:7] == "branch=":
                self.BranchNum = int(line.partition("=")[2])
                # The 7 first characters of the branch value must be z9hG4bK as is specified in the RFC 3261
                self.Branch = "z9hG4bK" +  hashlib.md5(str(random.randint(10000,99999)) + strLocal_IP + "SIP/2.0" + strRegistrar_IP + self.Username).hexdigest()[0:self.BranchNum]
            if line[0:4] == "tag=":
                self.TagNum = int(line.partition("=")[2])
                self.Tag = GenerateRandomString()[0:self.TagNum]
            if line[0:8] == "call-id=":
                self.CallIDNum = int(line.partition("=")[2])
                self.CallID = GenerateRandomString()[0:self.CallIDNum] 
            if line[0:5] == "cseq=":
                self.CSeq = int(line.partition("=")[2])
            
            if line.find("register{") <> -1:
                reading_register = True
                reading_register_auth = False
                reading_options_ok = False
                
            if line.find("register_auth{") <> -1:
                reading_register = False
                reading_register_auth = True   
                reading_options_ok = False
                
            if line.find("options_ok{") <> -1:
                reading_register = False
                reading_register_auth = False
                reading_options_ok = True
        
        f.close()
"""                
    

        
"""
class thrSocket(threading.Thread):
    
    global intBuffer
    
    def __init__(self):
        
        threading.Thread.__init__(self)
        
        self.Stop = False # Flag to stop the thread when neccesary
        
    def run(self):
        
        while not self.Stop:
            strData,(strRecServer,intRecPort) = UDPSock.recvfrom(intBuffer)
            
            TrafficLog(strData)

            # The content of the packet is analyzed
            
            if strData.find("401 Unauthorized") != -1:
                AnswerUnauthorized(strData)
                
            if GetSIPHeader("CSeq",strData).find("OPTIONS") != -1:
                AnswerOPTIONS(strData)  

            if GetSIPHeader("CSeq",strData).find("INVITE") != -1:
                AnalyzeINVITE(strData)

            if strData.find("200 OK") != -1:
                AnalyzeOK(strData)              
"""            

# def lob_cb
#
# This function saves the data returned by PJSUA module. This shows also the SIP paquete, so it's possible
# to analyse it directly from here, and there is no need to use some capturing packet function.
# This function is very important.

def log_cb(level, str, len):
    
    global thrAnalyzeCall

    PJSUA_Log(str)
    
    strTemp = str.strip().splitlines(True)
    for line in strTemp:
        if line.find("INVITE") != -1 and line.find("SIP/2.0") != -1:
            InviteLog(str)
	    # Convert function AnalyzeCall in a thread and call it.

 	    #if thrAnalyzeCall.isAlive() == True:
		#thrAnalyzeCall.join()

    	    thrAnalyzeCall = threading.Thread(target = AnalyzeCall, args = (str,))
            thrAnalyzeCall.start()

	    break


# Callback to receive events from account
class MyAccountCallback(pj.AccountCallback):

    def __init__(self, account=None):
        pj.AccountCallback.__init__(self, account)

    # Notification on incoming call
    def on_incoming_call(self, call):
        global current_call 
        if current_call:
            call.answer(486, "Busy")
            return
            
        print GetTime() + " NOTICE Incoming call from ", call.info().remote_uri

        current_call = call

        call_cb = MyCallCallback(current_call)
        current_call.set_callback(call_cb)

        current_call.answer(180)

        current_call.answer(200)
        
        #current_call.hangup()
        
        
# Callback to receive events from Call
class MyCallCallback(pj.CallCallback):

    def __init__(self, call=None):
        pj.CallCallback.__init__(self, call)

    # Notification when call state has changed
    def on_state(self):
        global current_call
        print GetTime() + " NOTICE Call with", self.call.info().remote_uri,
        print "is", self.call.info().state_text,
        print "last code =", self.call.info().last_code, 
        print "(" + self.call.info().last_reason + ")"
        
        if self.call.info().state == pj.CallState.DISCONNECTED:
            current_call = None
            print GetTime() + " NOTICE Current call is", current_call

    # Notification when call's media state has changed.
    def on_media_state(self):
        if self.call.info().media_state == pj.MediaState.ACTIVE:
            # Connect the call to sound device
            call_slot = self.call.info().conf_slot
            pj.Lib.instance().conf_connect(call_slot, 0)
            pj.Lib.instance().conf_connect(0, call_slot)
            print GetTime() + " NOTICE Media is now active"
        else:
            print GetTime() + " NOTICE Media is inactive"
                

# def LoadConfiguration
#
# Load configurations from file artemisa.conf

def LoadConfiguration():
    
    global strLocal_IP
    global strLocal_port
    global strRegistrar_IP
    global strRegistrar_port
    global intRegistrar_time
    global strSIPdomain
    global strUserAgent
    global Sessions
    
    config = ConfigParser.ConfigParser()
    strTemp = config.read("./artemisa.conf")
    
    if strTemp == []:
        print GetTime() + " CRITICAL The configuration file artemisa.conf cannot be read."
        Log("CRITICAL The configuration file artemisa.conf cannot be read.")
        EndConnection()
        sys.exit(0)
    else:
        try:
            strLocal_IP = config.get("environment", "local_ip")
            strLocal_port = config.get("environment", "local_port")
            strRegistrar_IP = config.get("environment", "registrar_ip")
            strRegistrar_port = config.get("environment", "registrar_port")
            intRegistrar_time = int(config.get("environment", "registrar_time"))
            strSIPdomain = config.get("environment", "sip_domain")
	    strUserAgent = config.get("environment", "user_agent")
                            
            # Now it reads each user stored in the file and generates a Session object for each one,
            # and they have at the same time a Profile object wich the profile settings        
                    
            for item in config.sections():
                if item <> "environment":
                    Sessions.append(Session())
                    Sessions[len(Sessions)-1].Extension = item
                    Sessions[len(Sessions)-1].Username = config.get(item, "username")
                    Sessions[len(Sessions)-1].Password = config.get(item, "password")
                    #Sessions[len(Sessions)-1].GetProfile(config.get(item, "profile"))           
            
        except:
            print "The configuration file cannot be correctly read. Check it out carefully."
            EndConnection()
            sys.exit(0)

    del config


# def AnalyzeCall
#
# Core of the program. Here is where the honeypot concludes if the packet received is trusted or not.

def AnalyzeCall(strData):    

    global verbose
    global Extensions

    print GetTime() + " NOTICE INVITE detected."
    Log("NOTICE INVITE detected.")

    InferenceAnalysis(strData, verbose, Extensions)


# def Register
#
# This function registers the honeypot at the SIP server, and keep it alive sending REGISTRAR
# messages within the time specified in the configuration file.

def Register():

    global strRegistrar_IP
    global strRegistrar_port
    global intRegistrar_time
    global strSIPdomain
    global Sessions
    global Extensions
    global lib
    global acc

    Extensions = []

    for i in range(len(Sessions)):
        Extensions.append(Sessions[i].Extension)

        acc_cfg = pj.AccountConfig(strRegistrar_IP, Sessions[i].Extension, Sessions[i].Password, Sessions[i].Username)
        acc_cfg.reg_timeout = intRegistrar_time * 60
	acc = lib.create_account(acc_cfg)

        acc_cb = MyAccountCallback(acc)
        acc.set_callback(acc_cb)

        print GetTime() + " NOTICE Extension " + str(Sessions[i].Extension) + " successfully registered, status=" + str(acc.info().reg_status) + " (" + str(acc.info().reg_reason) + ")"
        
        Log("NOTICE Extension " + str(Sessions[i].Extension) + " successfully registered, status=" + str(acc.info().reg_status) + " (" + str(acc.info().reg_reason) + ")")


# def EndConnection
#
# Finalizes PJSUA.

def EndConnection():

    global lib
    global acc
    
    try:
        acc.delete()
        lib.destroy()
    except:
        pass
    
    
def main():

    global verbose
    global lib
    global strUserAgent

    #if not os.geteuid()==0:
    #    sys.exit("\nRun Artemisa as root only!\n")

    print "Artemisa v1.2.1  Copyright (C) 2009 Rodrigo do Carmo and Pablo Masri"
    print ""
    print "This program comes with ABSOLUTELY NO WARRANTY; for details type `show warranty'."
    print "This is free software, and you are welcome to redistribute it under certain"
    print "conditions; type `show license' for details."
    print ""
    print ""
    print "Type \"help\" for help."
    print ""
    
    # Check if some arguments has been passed
    if (len(sys.argv) == 2):
        if sys.argv[1] == "-v":
            verbose = True
        
    # Read the configuration file artemisa.conf
    LoadConfiguration()
    
    ua_cfg = pj.UAConfig()
    ua_cfg.user_agent = strUserAgent

    # Starts PJSUA library
    lib = pj.Lib()
    lib.init(ua_cfg, log_cfg = pj.LogConfig(level=5, callback=log_cb, console_level=5))
    try:
        lib.create_transport(pj.TransportType.UDP, pj.TransportConfig(int(strLocal_port)))
    except:
        print ""
        print "Critical error:"
        print "Port " + strLocal_port + " is already in use by another process. Please close that process or change the port number in the configuration file."
        print ""
        sys.exit(0)

    lib.start()
    
    Log("Honeypot started.")

    print GetTime() + " Starting extensions registration process..."
    Log("Starting extensions registration process...")
    
    # The sessions defined in artemisa.conf are registered to the SIP server.
    Register()

    # The keyboard is read:
    while True:
        
        s = sys.stdin.readline().rstrip("\r\n")
        
        if s == "help":
            print "Usage: artemisa [-v]"
            print "-v               Verbose mode (it shows more information)."
            print ""
            print "Commands list:"
	    print ""
            print "verbose on       Turn verbose mode on (it shows more information)."
            print "verbose off      Turn verbose mode off."
            print ""
            print "show warranty    Shows the program warrany."
            print "show license     Shows the program license."
            print "s                Exit"
            print "quit             Exit"
            print "exit             Exit"
            print "q                Exit"
        
        if s.find("verbose") != -1 and s.find("on") != -1:

            verbose = True
            
        if s.find("verbose") != -1 and s.find("off") != -1:
            
            verbose = False
                        
        if s == "show warranty":
            print ""
            print "THERE IS NO WARRANTY FOR THE PROGRAM, TO THE EXTENT PERMITTED BY"
            print "APPLICABLE LAW.  EXCEPT WHEN OTHERWISE STATED IN WRITING THE COPYRIGHT"
            print "HOLDERS AND/OR OTHER PARTIES PROVIDE THE PROGRAM \"AS IS\" WITHOUT WARRANTY"
            print "OF ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING, BUT NOT LIMITED TO,"
            print "THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR"
            print "PURPOSE.  THE ENTIRE RISK AS TO THE QUALITY AND PERFORMANCE OF THE PROGRAM"
            print "IS WITH YOU.  SHOULD THE PROGRAM PROVE DEFECTIVE, YOU ASSUME THE COST OF"
            print "ALL NECESSARY SERVICING, REPAIR OR CORRECTION."
            print ""
            print "IN NO EVENT UNLESS REQUIRED BY APPLICABLE LAW OR AGREED TO IN WRITING"
            print "WILL ANY COPYRIGHT HOLDER, OR ANY OTHER PARTY WHO MODIFIES AND/OR CONVEYS"
            print "THE PROGRAM AS PERMITTED ABOVE, BE LIABLE TO YOU FOR DAMAGES, INCLUDING ANY"
            print "GENERAL, SPECIAL, INCIDENTAL OR CONSEQUENTIAL DAMAGES ARISING OUT OF THE"
            print "USE OR INABILITY TO USE THE PROGRAM (INCLUDING BUT NOT LIMITED TO LOSS OF"
            print "DATA OR DATA BEING RENDERED INACCURATE OR LOSSES SUSTAINED BY YOU OR THIRD"
            print "PARTIES OR A FAILURE OF THE PROGRAM TO OPERATE WITH ANY OTHER PROGRAMS),"
            print "EVEN IF SUCH HOLDER OR OTHER PARTY HAS BEEN ADVISED OF THE POSSIBILITY OF"
            print "SUCH DAMAGES."
            print ""
            
        if s == "show license":
            print ""
            print "This program is free software: you can redistribute it and/or modify"
            print "it under the terms of the GNU General Public License as published by"
            print "the Free Software Foundation, either version 3 of the License, or"
            print "(at your option) any later version."
            print ""
            print "This program is distributed in the hope that it will be useful,"
            print "but WITHOUT ANY WARRANTY; without even the implied warranty of"
            print "MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the"
            print "GNU General Public License for more details."
            print ""
            print "You should have received a copy of the GNU General Public License"
            print "along with this program.  If not, see <http://www.gnu.org/licenses/>."
            print ""
            
        if s == "q" or s == "s" or s == "quit" or s == "exit":
            print ""
            print "Good bye!"
            print ""
            break
    
    Log("Honeypot ended.")
       
    EndConnection()
    sys.exit(0)
    
try:
    main()
except KeyboardInterrupt:
    print ""
    print "Good bye!"
    print ""
    Log("Honeypot ended.")
    EndConnection()
    sys.exit(0)
    
    
