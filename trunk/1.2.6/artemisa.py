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

VERSION = "1.2.6"

import sys
import os

import ConfigParser                 # Read configuration files.

from time import strftime, sleep, time
import sched
from logs import log                # Import class log from logs.py
from commons import *               # Import functions from commons.py
from inference import InferenceAnalysis # Inference engine (core of the honeypot).
import threading                    # Use of threads.

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
    sys.exit(1)


strLocal_IP = ""                    # Local IP
strLocal_port = ""                  # Local port
strSIPdomain = ""                   # Local SIP domain
strUserAgent = ""                   # User-Agent name used by Artemisa 
intMaxCalls = 0

current_call = None
intBuffer = 1024

verbose = False                     # verbose mode

Servers = []                        # SIP REGISTRAR servers
Extensions = []                     # Extensions

thrAnalyzeCall = threading.Thread() # Thread used to analyze the received messages.

Output = PrintClass()
logging = log()

Unregister = False                  # Used to know when Artemisa is performing an un-registration

Audiocapture = True                     # Flag to know when audio capture is enabled

# class Extensions
#
# Object created in order to keep the user data which an unique extension.

class Extension():

    Extension = ""
    Username = ""
    Password = ""
   
      
# class Server
#
# Manage registration information.

class Server():
    
    Name = ""
    Registrar_IP = ""               # Registrar server IP (Asterisk, SER, etc.)
    Registrar_port = ""             # Registrar server port
    Registrar_time = 10             # Time in minutes between REGISTRAR messeges sent to the server.
    RegSchedule = ""                # Time between registrations
    NAT_ka_inverval = 0             # Time between NAT keep alive messages
    behaviour_mode = ""             # Artemisa behaviour mode

    Extensions = []                 # Store the extensions registered to the SIP server

    acc = None
    acc_cfg = None
    acc_cb = None
    
    def __init__(self):
        self.Extensions = []
        self.acc = None
        self.acc_cfg = None
        self.acc_cb = None
        
    # def Register
    #
    # This function registers the honeypot at the SIP server, and keep it alive sending REGISTRAR
    # messages within the time specified in the configuration file.
    
    def Register(self):

        global lib 
        
        if len(self.Extensions) == 0:
            Output.Print("WARNING There are no extensions configured with server " + self.Name)
            return

        for i in range(len(self.Extensions)):
            self.acc_cfg = pj.AccountConfig(self.Registrar_IP, self.Extensions[i].Extension, self.Extensions[i].Password, self.Extensions[i].Username)
            self.acc_cfg.reg_timeout = self.Registrar_time * 60
            self.acc_cfg.ka_interval = self.NAT_ka_inverval
            self.acc = lib.create_account(self.acc_cfg)
    
            self.acc_cb = MyAccountCallback(self.acc)
            self.acc.set_callback(self.acc_cb)
    
            Output.Print("NOTICE Extension " + str(self.Extensions[i].Extension) + " registration sent. Status: " + str(self.acc.info().reg_status) + " (" + str(self.acc.info().reg_reason) + ")")

    def Unregister(self):
        self.acc.delete()
        del self.acc


# def lob_cb
#
# This function saves the data returned by PJSUA module. This shows also the SIP packet, so it's possible
# to analyse it directly from here, and there is no need to use some capturing packet function.
# This function is very important.

def log_cb(level, str, len):
    
    global thrAnalyzeCall
    global behaviour_mode
    
    logging.PJSUA_Log(str)
    
    strTemp = str.strip().splitlines(True)
    for line in strTemp:
        if line.find("INVITE") != -1 and line.find("SIP/2.0") != -1:
            
            Output.Print("INVITE message detected and logged.")
            
            logging.InviteLog(str)

            # In passive mode the messages are not analysed.
            if behaviour_mode != "passive":
                # Convert function AnalyzeCall in a thread and call it.
    	        thrAnalyzeCall = threading.Thread(target = AnalyzeCall, args = (str,))
                thrAnalyzeCall.start()

            break


# Callback to receive events from account
class MyAccountCallback(pj.AccountCallback):

    global Unregister

    def __init__(self, account=None):
        pj.AccountCallback.__init__(self, account)

    def on_reg_state(self):
        if Unregister == False:
            if self.account.info().reg_status >= 200 and self.account.info().reg_status < 300:
                Output.Print("NOTICE Extension " + str(self.account.info().uri) + " registered, status=" + str(self.account.info().reg_status) + " (" + str(self.account.info().reg_reason) + ")")    
            elif (self.account.info().reg_status >= 400 and self.account.info().reg_status < 500) or self.account.info().reg_status > 700:
                Output.Print("NOTICE Extension " + str(self.account.info().uri) + " registration failed, status=" + str(self.account.info().reg_status) + " (" + str(self.account.info().reg_reason) + ")")
            else:
               Output.Print("NOTICE Extension " + str(self.account.info().uri) + " registration status=" + str(self.account.info().reg_status) + " (" + str(self.account.info().reg_reason) + ")")
        else:
            # It's necessary to use a variable as flag to know then a registration or unregistration
            # process is taking place, because both SIP messages are REGISTER but with different 
            # "expire" time. So, there is no way to determine if it's a registration or an unregistration
            # in other way.  
            if self.account.info().reg_status >= 200 and self.account.info().reg_status < 300:
                Output.Print("NOTICE Extension " + str(self.account.info().uri) + " unregistered, status=" + str(self.account.info().reg_status) + " (" + str(self.account.info().reg_reason) + ")")    
            elif (self.account.info().reg_status >= 400 and self.account.info().reg_status < 500) or self.account.info().reg_status > 700:
                Output.Print("NOTICE Extension " + str(self.account.info().uri) + " unregistration failed, status=" + str(self.account.info().reg_status) + " (" + str(self.account.info().reg_reason) + ")")
            else:
               Output.Print("NOTICE Extension " + str(self.account.info().uri) + " unregistration status=" + str(self.account.info().reg_status) + " (" + str(self.account.info().reg_reason) + ")")
                           
    # Notification on incoming call
    def on_incoming_call(self, call):

        global current_call
        global behaviour_mode
        global lib
        
        Output.Print("NOTICE Incoming call from " + str(call.info().remote_uri))

        current_call = call

        call_cb = MyCallCallback(current_call)
        current_call.set_callback(call_cb)

        current_call.answer(180)
        current_call.answer(200)
        
        
        #current_call.hangup()
        
        
# Callback to receive events from Call
class MyCallCallback(pj.CallCallback):

    rec_id = None
    rec_slot = None

    def __init__(self, call=None):
        pj.CallCallback.__init__(self, call)
        self.rec_slot = None
        self.rec_id = None

    # Notification when call state has changed
    def on_state(self):
        
        global current_call
        global lib
        
        Output.Print("NOTICE Call from " + str(self.call.info().remote_uri) +  " is " + str(self.call.info().state_text) + ", last code = " + str(self.call.info().last_code) + " (" + str(self.call.info().last_reason) + ")")
        
        if self.call.info().state == pj.CallState.DISCONNECTED:
            
            if Audiocapture == True:
                try:
                    
                    call_slot = self.call.info().conf_slot
                        
                    # Disconnect the call with the WAV recorder
                    lib.conf_disconnect(call_slot, self.rec_slot)
                    
                    lib.recorder_destroy(self.rec_id)
                    
                except Exception, e:
                    Output.Print("WARNING Error: " + str(e))
                    
                current_call = None
                Output.Print("NOTICE Current call is " + str(current_call))
        
    # Notification when call's media state has changed.
    def on_media_state(self):
        
        global lib
        global Audiocapture
        
        if Audiocapture == False: return
        
        if self.call.info().media_state == pj.MediaState.ACTIVE: 
            try:
                # Connect the call to the recorder 
                call_slot = self.call.info().conf_slot 
                
                if self.rec_id < 0: 
                    
                    a = 0
                    while 1:
                        
                        strFilename = "./recorded_calls/" + strftime("%Y-%m-%d") + "_call_from_" + str(self.call.info().remote_uri).split(" ")[1].split("@")[0].split(":")[1] + "_" + str(a) + ".wav"
                        
                        if os.path.isfile(strFilename) == True:
                            a += 1
                        else:
                            break
                    
                    self.rec_id = lib.create_recorder(strFilename)
                    self.rec_slot = lib.recorder_get_slot(self.rec_id)
                
                # Connect the call with the WAV recorder
                lib.conf_connect(call_slot, self.rec_slot)
                
                Output.Print("NOTICE Audio is now being recorded.")
                
            except Exception, e:
                Output.Print("WARNING Error while trying to record the call. Error: " + str(e))
  

        else:

            try:
                call_slot = self.call.info().conf_slot
                
                # Disconnect the call with the WAV recorder
                pj.Lib.instance().conf_disconnect(call_slot, lib.recorder_get_slot(self.rec_id))

            except Exception, e:
                Output.Print("WARNING Error: " + str(e))
            
            Output.Print("NOTICE Audio is inactive.") 

                
                
# def LoadExtensions
#
# Load configurations from file extensions.conf

def LoadExtensions():
    
    global Extensions

    config = ConfigParser.ConfigParser()
    strTemp = config.read("./conf/extensions.conf")
    
    if strTemp == []:
        Output.Print("CRITICAL The configuration file extensions.conf cannot be read.")
        EndConnection()
        sys.exit(1)
    else:
        try:
            for item in config.sections():

                Extensions.append(Extension())
                    
                i = len(Extensions)-1
                    
                Extensions[i].Extension = item
                Extensions[i].Username = config.get(item, "username")
                Extensions[i].Password = config.get(item, "password")
                    
        except:
            print "The configuration file extensions.conf cannot be correctly read. Check it out carefully."
            EndConnection()
            sys.exit(1)

    del config
    
    

# def LoadServers
#
# Load configurations from file servers.conf

def LoadServers():
    
    global Servers
    global Extentions
    
    config = ConfigParser.ConfigParser()
    strTemp = config.read("./conf/servers.conf")
    
    if strTemp == []:
        Output.Print("CRITICAL The configuration file servers.conf cannot be read.")
        EndConnection()
        sys.exit(1)
    else:
        try:
            for item in config.sections():
    
                Servers.append(Server())
                        
                i = len(Servers)-1
                        
                Servers[i].Name = item
                Servers[i].Registrar_IP = config.get(item, "registrar_ip")
                Servers[i].Registrar_port = config.get(item, "registrar_port")
                Servers[i].Registrar_time = int(config.get(item, "registrar_time"))
                    
                Servers[i].NAT_ka_inverval = int(config.get(item, "nat_keepalive_interval"))
                #Servers[i].behaviour_mode = config.get(item, "behaviour_mode")          
                #
                #if Servers[i].behaviour_mode != "active" and Servers[i].behaviour_mode != "passive" and Servers[i].behaviour_mode != "aggressive":
                #    Servers[i].behaviour_mode = "passive"
                #    Output.Print("WARNING behaviour_mode value in server " + Servers[i].Name + " is invalid. Changed to passive.")
                    
                strTemp2 = config.get(item, "exten")
                strTemp2 = strTemp2.split(",")

                for x in range(len(strTemp2)):
                    for j in range(len(Extensions)):
                        if strTemp2[x] == Extensions[j].Extension:
                            Servers[i].Extensions.append(Extension())
                            Servers[i].Extensions[len(Servers[i].Extensions)-1] = Extensions[j]
                            break
            
        except :
            print "The configuration file servers.conf cannot be correctly read. Check it out carefully."
            EndConnection()
            sys.exit(1)

    del config
    
    
# def LoadConfiguration
#
# Load configurations from file artemisa.conf

def LoadConfiguration():
    
    global strLocal_IP
    global strLocal_port
    global strSIPdomain
    global strUserAgent
    global intMaxCalls
    global behaviour_mode
    
    config = ConfigParser.ConfigParser()
    strTemp = config.read("./conf/artemisa.conf")
    
    if strTemp == []:
        Output.Print("CRITICAL The configuration file artemisa.conf cannot be read.")
        EndConnection()
        sys.exit(1)
    else:
        try:
            strLocal_IP = config.get("environment", "local_ip")
            strLocal_port = config.get("environment", "local_port")
            strSIPdomain = config.get("environment", "sip_domain")
            strUserAgent = config.get("environment", "user_agent")
            behaviour_mode = config.get("environment", "behaviour_mode")
            intMaxCalls  = int(config.get("environment", "max_calls"))
            
            
            
            if behaviour_mode != "active" and behaviour_mode != "passive" and behaviour_mode != "aggressive":
                behaviour_mode = "passive"
                Output.Print("WARNING behaviour_mode value is invalid. Changed to passive.")
                    
        except:
            print "The configuration file artemisa.conf cannot be correctly read. Check it out carefully."
            EndConnection()
            sys.exit(1)

    del config


# def AnalyzeCall
#
# Core of the program. Here is where the honeypot concludes if the packet received is trusted or not.

def AnalyzeCall(strData):    

    global verbose
    global Extensions

    inference_instance = InferenceAnalysis()
    inference_instance.Message = strData
    inference_instance.verbose = verbose
    inference_instance.Extensions = Extensions
    inference_instance.Start()



# def EndConnection
#
# Finalizes PJSUA.

def EndConnection():

    global lib
    global Unregister
    
    Unregister = True    

    try:
        for i in range(len(Servers)):
            Servers[i].Unregister()
        
        lib.destroy()
        del lib
    except:
        pass
    
    
def main():

    global verbose
    global lib
    global strLocal_port
    global strUserAgent
    global intMaxCalls
    global behaviour_mode
    global Unregister
    global Audiocapture
    
    if not os.geteuid()==0:
        sys.exit("\nRun Artemisa as root only!\n")

    print "Artemisa v" + VERSION + " Copyright (C) 2009 Rodrigo do Carmo and Pablo Masri"
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
        else:
            print Output.Print("WARNING Invalid argument: " + sys.argv[1])
        
    # Read the configuration file artemisa.conf
    LoadConfiguration()

    # Read the extensions configuration in extensions.conf
    LoadExtensions()

    # Read the registrar servers configuration in servers.conf
    LoadServers()
                
    # Initialize the PJSUA library
    lib = pj.Lib() # Starts PJSUA library
    ua_cfg = pj.UAConfig()
    ua_cfg.user_agent = strUserAgent
    ua_cfg.max_calls = intMaxCalls
            
    # The value console_level MUST be 5 since it's used to analyse the messages
    lib.init(ua_cfg, log_cfg = pj.LogConfig(level=5, callback=log_cb, console_level=5))
    try:
        lib.create_transport(pj.TransportType.UDP, pj.TransportConfig(int(strLocal_port)))
    except:
        print ""
        print "Critical error:"
        print "Port " + strLocal_port + " is already in use by another process. Please close that process or change the port number in the configuration file."
        print ""
        sys.exit(1)
    
    # Create a record object in order to record calls
    #lib.create_recorder("./record.wav")
            
    lib.start()

    
    # Configure the audio device 
    try:
        if len(lib.enum_snd_dev()) > 0:
            lib.set_snd_dev(0,0)
            Audiocapture = True
        else:
            Output.Print("WARNING Audio device not found. Calls will not be recorded.")
            Audiocapture = False
    except:
        Output.Print("WARNING Audio device not found. Calls will not be recorded.")
        Audiocapture = False



    if behaviour_mode != "passive":
        Output.Print("Behaviour mode: " + behaviour_mode)
    else:
        Output.Print("Behaviour mode: passive (inference analysis is disabled)")
                
    Unregister = False

    Output.Print("-------------------------------------------------------------------------------------------------", False)
    Output.Print("Artemisa started.", False)

    Output.Print("Starting extensions registration process...")
        
    # Register each account
    for i in range(len(Servers)):
        Servers[i].Register()
   
    # The keyboard is read:
    while True:
        
        s = sys.stdin.readline().rstrip("\r\n")
        
        if s == "help":
            print "Usage: artemisa [-v]"
            print "-v               Verbose mode (it shows more information)"
            print ""
            print "Commands list:"
            print ""
            print "mode active      Change behaviour mode to active"
            print "mode passive     Change behaviour mode to passive"
            print "mode aggressive  Change behaviour mode to aggressive"
            print ""
            print "verbose on       Turn verbose mode on (it shows more information)"
            print "verbose off      Turn verbose mode off"
            print ""
            print "clean historical Removes the historical database."
            print "clean logs       Removes all log files."
            print "clean results    Removes all results files."
            print "clean alarms     Removes all alarm files."
            print "clean calls      Removes all the recorded calls."
            print "clean all        Removes all files."
            print "                 Use these commands carefully."
            print ""
            print "show warranty    Shows the program warrany"
            print "show license     Shows the program license"
            print "s                Exit"
            print "quit             Exit"
            print "exit             Exit"
            print "q                Exit"
        
        elif s == "clean historical":
            Process = Popen("rm -f ./historical/*", shell=True, stdout=PIPE)
            Process.wait()
            
        elif s == "clean logs":
            Process = Popen("rm -f ./logs/*.log", shell=True, stdout=PIPE)
            Process.wait()
            Process = Popen("rm -f ./logs/invite_msgs/*.log", shell=True, stdout=PIPE)
            Process.wait()
            
        elif s == "clean results":
            Process = Popen("rm -f ./results/*", shell=True, stdout=PIPE)                        
            Process.wait()
                        
        elif s == "clean alarms":
            Process = Popen("rm -f ./alarms/*", shell=True, stdout=PIPE)
            Process.wait()

        elif s == "clean calls":
            Process = Popen("rm -f ./recorded_calls/*", shell=True, stdout=PIPE)
            Process.wait()
                        
        elif s == "clean all":
            Process = Popen("rm -f ./historical/*", shell=True, stdout=PIPE)
            Process.wait()
            Process = Popen("rm -f ./logs/*.log", shell=True, stdout=PIPE)
            Process.wait()
            Process = Popen("rm -f ./logs/invite_msgs/*.log", shell=True, stdout=PIPE)
            Process.wait()
            Process = Popen("rm -f ./results/*", shell=True, stdout=PIPE)                        
            Process.wait()
            Process = Popen("rm -f ./alarms/*", shell=True, stdout=PIPE)
            Process.wait()
            Process = Popen("rm -f ./recorded_calls/*", shell=True, stdout=PIPE)
            Process.wait()
                                                
        elif s == "mode active":
            behaviour_mode = "active"
            Output.Print("Behaviour mode changed to active.") 

        elif s == "mode passive":
            behaviour_mode = "passive"
            Output.Print("Behaviour mode changed to passive (inference analysis is disabled).")
            
        elif s == "mode aggressive":
            behaviour_mode = "aggressive"
            Output.Print("Behaviour mode changed to aggressive.")
                        
        elif s.find("verbose") != -1 and s.find("on") != -1:
            verbose = True
            Output.Print("Verbose mode on.")
            
        elif s.find("verbose") != -1 and s.find("off") != -1:
            verbose = False
            Output.Print("Verbose mode off.")
                        
        elif s == "show warranty":
            print ""
            print "THERE IS NO WARRANTY FOR THE PROGRAM, TO THE EXTENT PERMITTED BY"
            print "APPLICABLE LAW. EXCEPT WHEN OTHERWISE STATED IN WRITING THE COPYRIGHT"
            print "HOLDERS AND/OR OTHER PARTIES PROVIDE THE PROGRAM \"AS IS\" WITHOUT WARRANTY"
            print "OF ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING, BUT NOT LIMITED TO,"
            print "THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR"
            print "PURPOSE. THE ENTIRE RISK AS TO THE QUALITY AND PERFORMANCE OF THE PROGRAM"
            print "IS WITH YOU. SHOULD THE PROGRAM PROVE DEFECTIVE, YOU ASSUME THE COST OF"
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
            
        elif s == "show license":
            print ""
            print "This program is free software: you can redistribute it and/or modify"
            print "it under the terms of the GNU General Public License as published by"
            print "the Free Software Foundation, either version 3 of the License, or"
            print "(at your option) any later version."
            print ""
            print "This program is distributed in the hope that it will be useful,"
            print "but WITHOUT ANY WARRANTY; without even the implied warranty of"
            print "MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the"
            print "GNU General Public License for more details."
            print ""
            print "You should have received a copy of the GNU General Public License"
            print "along with this program. If not, see <http://www.gnu.org/licenses/>."
            print ""
            
        elif s == "q" or s == "s" or s == "quit" or s == "exit":
            break

        else:
            print "Command not found. Type \"help\" for a list of commands."

    EndConnection()
    print ""
    print "Good bye!"
    print ""
    Output.Print("Artemisa ended.", False)
    Output.Print("-------------------------------------------------------------------------------------------------", False)
       
    sys.exit(0)
    
if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        EndConnection()
        print ""
        print "Good bye!"
        print ""
        Output.Print("Artemisa ended.", False)
        Output.Print("-------------------------------------------------------------------------------------------------", False)
        sys.exit(0)
    
    
