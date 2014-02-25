# Artemisa v1.1
# Copyright (C) 2009-2013 Mohamed Nassar <nassar@loria.fr>, Rodrigo do Carmo <rodrigodocarmo@gmail.com>,
# Pablo Masri <pablomasri87@gmail.com>, Mauro Villarroel <villarroelmt@gmail.com> and Exequiel Barrirero <exequielrafaela@gmail.com>.
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

# Important note:
# The following string "repvernumber" will be autimatically replaced by 
# the clean_and_prepare_for_release.sh script. So, don't modify it!
VERSION = "repvernumber"

# Definition of directories and files
CONFIG_DIR = "./conf/"
RESULTS_DIR = "./results/"
AUDIOFILES_DIR = "./audiofiles/"
LOGS_DIR = "./logs/"
RECORDED_CALLS_DIR = "./recorded_calls/"

CONFIG_FILE_PATH = CONFIG_DIR + "artemisa.conf"
BEHAVIOUR_FILE_PATH = CONFIG_DIR + "behaviour.conf"
ACTIONS_FILE_PATH = CONFIG_DIR + "actions.conf"
EXTENSIONS_FILE_PATH = CONFIG_DIR + "extensions.conf"
SERVERS_FILE_PATH = CONFIG_DIR + "servers.conf"

NUMBER_OF_OPTIONS_MATCHES = 3 # Maximum number of different extension that an OPTIONS message can "target" after being considered a scanning attack

import sys

try:
    """
    Try to import the PJSUA library. It's used for the SIP stack handling.
    """
    import pjsua as pj
except ImportError:
    print ""
    print "Critical error:"
    print "    PJSIP library module MUST be installed!"
    print ""
    print "Download it from:"
    print "    http://www.pjsip.org/download.htm"
    print ""
    print "    or, if you have the wget, can do in a console:"
    print ""
    print "    wget http://www.pjsip.org/release/1.8.10/pjproject-1.8.10.tar.bz2"
    print ""
    print "Installation steps:"
    print "    http://trac.pjsip.org/repos/wiki/Python_SIP/Build_Install"
    print ""
    print "       In a nutshell:"
    print ""
    print "       1) Check that make, gcc, binutils, Python, and Python-devel are installed."
    print "       2) Build the PJSIP libraries first with \"# ./configure && make dep && make\" commands."
    print "          Note: if fails try:./configure CFLAGS=-fPIC"
    print "       3) Go to the pjsip-apps/src/python directory."
    print "       4) Run \'# python setup.py install\' or just \'# make install\'."
    print ""
    sys.exit(1)


import os
import getpass
from time import strftime
from time import sleep
from time import time
from time import gmtime
import threading                                # Use of threads
from subprocess import Popen
from subprocess import PIPE
import ConfigParser                             # Read configuration files
from optparse import OptionParser               # For parsing command line parameters

from libs.IPy.IPy import IP                     # Module to deal with IPs

from modules.commons import *                   # Import functions from commons.py
from modules.classifier import Classifier       # Message classifier 
from modules.correlator import Correlator       # Correlator
from modules.correlator import CheckIfScanning
from modules.correlator import CheckIfFlood
from modules.mail import Email
from modules.results_format import get_results_txt
from modules.results_format import get_results_html
from modules.logger import logger               # Instance a logger for information about Artemisa
from modules.logger import pjsua_logger         # Instance a logger for information about the PJSUA library

from SimpleXMLRPCServer import SimpleXMLRPCServer
from SimpleXMLRPCServer import SimpleXMLRPCRequestHandler

#from modules.xml_server import *
#rom modules.threading_xml import *
#import thread

Unregister = False                              # Flag to know whether the unregistration process is taking place
MediaReceived = False                           # Flag to know if media has been received

class Extension(object):
    """
    Keeps the user data with an unique extension.
    """

    def __init__(self, Extension, Username, Password):
        self.Extension = Extension
        self.Username = Username
        self.Password = Password
   
class Server(object):
    """
    Manage registration information.
    """

    def __init__(self, behaviour_mode, Name, Active_mode, Passive_mode, Aggressive_mode, Registrar_IP, Registrar_port, Registrar_time, NAT_ka_interval, Extensions, lib, Sound_enabled, Playfile):
        self.Name = Name
        self.Active_mode = Active_mode
        self.Passive_mode = Passive_mode
        self.Aggressive_mode = Aggressive_mode
        self.Registrar_IP = Registrar_IP        # Registrar server IP (Asterisk, SER, etc.)
        self.Registrar_port = Registrar_port    # Registrar server port
        self.Registrar_time = Registrar_time    # Time in minutes between REGISTRAR messeges sent to the server.
        self.RegSchedule = ""                   # Time between registrations
        self.NAT_ka_inverval = NAT_ka_interval  # Time between NAT keep alive messages
        self.behaviour_mode = behaviour_mode    # Artemisa's behaviour mode

        self.Extensions = Extensions            # Store the extensions registered to the SIP server
        self.acc = None
        self.acc_cfg = None
        self.acc_cb = None

        self.lib = lib
        self.Sound_enabled = Sound_enabled
        self.Playfile = Playfile

    def __del__(self):
        self.Unregister()
            
    def Register(self):
        """
        This method registers the honeypot at the SIP server, and keeps it alive by sending REGISTER
        messages within the time specified in the configuration file.
        """
        if len(self.Extensions) == 0:
            logger.info("There are no extensions configured to be used with server " + self.Name)
            return

        try:
            if self.acc.info().reg_status == 100: # This means that the registration process is in progress.
                return
        except:
            pass

        for i in range(len(self.Extensions)):
            self.acc_cfg = pj.AccountConfig(self.Registrar_IP + ":" + self.Registrar_port, self.Extensions[i].Extension, self.Extensions[i].Password, self.Extensions[i].Username)
            self.acc_cfg.reg_timeout = self.Registrar_time * 60
            self.acc_cfg.ka_interval = self.NAT_ka_inverval
            self.acc = self.lib.create_account(self.acc_cfg)

            self.acc_cb = MyAccountCallback(self.acc, self.lib, self.behaviour_mode, self.Active_mode, self.Passive_mode, self.Aggressive_mode, self.Sound_enabled, self.Playfile)
            self.acc.set_callback(self.acc_cb)
    
            logger.info("Extension " + str(self.Extensions[i].Extension) + " registration sent. Status: " + str(self.acc.info().reg_status) + " (" + str(self.acc.info().reg_reason) + ")")

    def Reregister(self):
        """
        This method does the re-registration.
        """
        try:
            self.account.set_registration(True)
        except:
            logger.error("Error in on_reg_state() while trying to do set_registration().")

    def Unregister(self):
        """
        This method closes the connections.
        """
        try:
            del self.acc_cb
        except:
            pass

class RequestHandler(SimpleXMLRPCRequestHandler):
  rpc_paths = ('/RPC2',)

class MyAccountCallback(pj.AccountCallback):
    """
    Callback to receive events from account.
    """

    def __init__(self, account, lib, behaviour_mode, Active_mode, Passive_mode, Aggressive_mode, Sound_enabled, Playfile):
        pj.AccountCallback.__init__(self, account)
        self.lib = lib
        self.behaviour_mode = behaviour_mode
        self.Active_mode = Active_mode
        self.Passive_mode = Passive_mode
        self.Aggressive_mode = Aggressive_mode
        self.Sound_enabled = Sound_enabled
        self.Playfile = Playfile
        self.call_cb = None

    def on_reg_state(self):
        if not Unregister:
            if self.account.info().reg_status >= 200 and self.account.info().reg_status < 300:
                logger.info("Extension " + str(self.account.info().uri) + " registered, status=" + str(self.account.info().reg_status) + " (" + str(self.account.info().reg_reason) + ")")    
            #elif (self.account.info().reg_status >= 400 and self.account.info().reg_status < 500) or self.account.info().reg_status > 700:
            elif self.account.info().reg_status >= 300 and self.account.info().reg_status < 700:
                logger.info("Extension " + str(self.account.info().uri) + " registration failed, status=" + str(self.account.info().reg_status) + " (" + str(self.account.info().reg_reason) + ")")
                # This part is important since it's necessary to try the registration again if it fails.
                logger.info("Trying to register again.")
                try:
                    self.account.set_registration(True)
                except:
                    logger.error("Error in on_reg_state() while trying to do set_registration().")
            else:
                logger.info("Extension " + str(self.account.info().uri) + " registration status=" + str(self.account.info().reg_status) + " (" + str(self.account.info().reg_reason) + ")")
        else:
            # It's necessary to use a flag variable to know whether a registration or unregistration
            # process is taking place, because both SIP messages are REGISTER but with different 
            # "expire" time. So, there is no other way to determine if it's a registration or an unregistration.  
            if self.account.info().reg_status >= 200 and self.account.info().reg_status < 300:
                logger.info("Extension " + str(self.account.info().uri) + " unregistered, status=" + str(self.account.info().reg_status) + " (" + str(self.account.info().reg_reason) + ")")    
            #elif (self.account.info().reg_status >= 400 and self.account.info().reg_status < 500) or self.account.info().reg_status > 700:
            elif self.account.info().reg_status >= 300 and self.account.info().reg_status < 700:
                logger.info("Extension " + str(self.account.info().uri) + " unregistration failed, status=" + str(self.account.info().reg_status) + " (" + str(self.account.info().reg_reason) + ")")
            # No problem if the unregistration process fails.
            else:
                logger.info("Extension " + str(self.account.info().uri) + " unregistration status=" + str(self.account.info().reg_status) + " (" + str(self.account.info().reg_reason) + ")")
                           
    # Notification on incoming call
    def on_incoming_call(self, call):

        logger.info("Incoming call from " + str(call.info().remote_uri))

        try:
            self.current_call = call

            self.call_cb = MyCallCallback(self.lib, self.current_call, self.Sound_enabled, self.Playfile)
            self.current_call.set_callback(self.call_cb)

            if self.behaviour_mode == "active":
                for item in self.Active_mode:
                    if item == "send_180":
                        self.current_call.answer(180)
                    if item == "send_200":
                        self.current_call.answer(200)

            elif self.behaviour_mode == "passive":
                for item in self.Passive_mode:
                    if item == "send_180":
                        self.current_call.answer(180)
                    if item == "send_200":
                        self.current_call.answer(200)

            elif self.behaviour_mode == "aggressive":
                for item in self.Aggressive_mode:
                    if item == "send_180":
                        self.current_call.answer(180)
                    if item == "send_200":
                        self.current_call.answer(200)
        
        except:
            logger.error("Error in method on_incoming_call().")
                            
        #self.current_call.hangup()

class MyCallCallback(pj.CallCallback):
    """
    Callback to receive events from Call
    """
    def __init__(self, lib, current_call, Sound_enabled, Playfile):
        self.rec_slot = None
        self.rec_id = None
        self.player_slot = None
        self.player_id = None

        self.lib = lib
        self.Sound_enabled = Sound_enabled
        self.Playfile = Playfile

        self.current_call = current_call
        pj.CallCallback.__init__(self, self.current_call)

    # Notification when call state has changed
    def on_state(self):
        
        logger.info("Call from " + str(self.call.info().remote_uri) +  " is " + str(self.call.info().state_text) + ", last code = " + str(self.call.info().last_code) + " (" + str(self.call.info().last_reason) + ")")
        
        if self.call.info().state == pj.CallState.DISCONNECTED:
            
            if self.Sound_enabled:
                try:
                    
                    self.call_slot = self.call.info().conf_slot
                        
                    # Disconnect the call with the WAV recorder
                    self.lib.conf_disconnect(self.call_slot, self.rec_slot)
                    
                    self.lib.recorder_destroy(self.rec_id)

                    # Disconnect the call from the player
                    self.lib.conf_disconnect(self.player_slot, self.call_slot)
                    
                    self.lib.player_destroy(self.player_id)
                    
                except:
                    logger.warning("Error while closing the conferences in method on_state().")
                    
                self.current_call = None
        
    # Notification when call's media state has changed.
    def on_media_state(self):
        
        global MediaReceived

        if not self.Sound_enabled: return
        
        if self.call.info().media_state == pj.MediaState.ACTIVE: 
            try:
                # Connect the call to the recorder 
                self.call_slot = self.call.info().conf_slot 
                
                if self.rec_id < 0: 
                    
                    a = 0
                    while 1:
                        Filename = RECORDED_CALLS_DIR + strftime("%Y-%m-%d") + "_call_from_" + str(self.call.info().remote_uri).split("@")[0].split(":")[1] + "_" + str(a) + ".wav"
                        
                        if os.path.isfile(Filename):
                            a += 1
                        else:
                            break
                    
                    # Set the recorder
                    self.rec_id = self.lib.create_recorder(Filename)
                    self.rec_slot = self.lib.recorder_get_slot(self.rec_id)
                
                    # Connect the call with the WAV recorder
                    self.lib.conf_connect(self.call_slot, self.rec_slot)
                    
                    logger.info("Audio is now being recorded on file: " + Filename)
                    
                    MediaReceived = True
                
            except:
                logger.error("Error while trying to record the call.")

            try:
                if self.player_id < 0:

                    # And now set the file player
                    if self.Playfile != "":
                        self.call_slot = self.call.info().conf_slot 
                        
                        WAVPlayFilename = AUDIOFILES_DIR + self.Playfile

                        self.player_id = self.lib.create_player(WAVPlayFilename)
                        self.player_slot = self.lib.player_get_slot(self.player_id)

                        # Connect the call with the WAV player
                        self.lib.conf_connect(self.player_slot, self.call_slot)
                    
                        logger.info("The following audio file is now being played: " + self.Playfile)
    
            except:
                logger.error("Error while trying to play the WAV file.")
  
        else:

            try:
                self.call_slot = self.call.info().conf_slot
                
                # Disconnect the call with the WAV recorder
                pj.Lib.instance().conf_disconnect(self.call_slot, self.lib.recorder_get_slot(self.rec_id))

                # Disconnect the call from the player
                pj.Lib.instance().conf_disconnect(self.lib.player_get_slot(self.player_id), self.call_slot)

            except:
                logger.warning("Error while closing the conferences in method on_media_state()")
            
            logger.info("Audio is inactive. Check the configuration file.") 

class Artemisa(object):
    """
    This is the class which defines the whole program.
    """ 
    #  global xml_serv
    
    def __init__(self):

        self.VERSION = VERSION
        self.SIP_VERSION = "2.0"

        # Environment configuration
        self.Local_IP = ""                      # Local IP
        self.Local_port = ""                    # Local port
        self.Local_xml_port = ""                # Local XML Server port
        self.SIPdomain = ""                     # Local SIP domain
        self.UserAgent = ""                     # User-Agent name used by Artemisa 
        self.MaxCalls = 0                       # Max number of calls to handle
        self.NumCalls = 0                       # Number of calls being analysed
        self.Playfile = ""                      # Name of the file to be played

        # Sound configuration
        self.Sound_enabled = True
        self.Sound_device = 0
        self.Sound_rate = 44100

        # Behaviour modes configuration
        self.behaviour_mode = "active"          # Inference analysis behaviour
        self.Active_mode = []
        self.Passive_mode = []
        self.Aggressive_mode = []

        self.On_flood_parameters = ""           # Parameters to send when calling on_flood.sh
        self.On_SPIT_parameters = ""            # Parameters to send when calling on_spit.sh
        self.On_scanning_parameters = ""        # Parameters to send when calling on_scanning.sh

        self.verbose = False                    # verbose mode

        self.Servers = []                       # SIP REGISTRAR servers
        self.Extensions = []                    # Extensions

        self.LastINVITEreceived = ""            # Store the last INVITE message received in order to avoid analysing repeated messages
        self.LastOPTIONSreceived = ""           # Same for OPTIONS
        self.LastREGISTERreceived = ""          # Same for REGISTER

        #self.nSeq = 0                          # Number of received messages

        # Statistics
        self.N_INVITE = 0
        self.N_OPTIONS = 0
        self.N_REGISTER = 0

        self.OPTIONSReceived = False            # Flag to know if a OPTIONS was received
        self.OPTIONS_Last_time = gmtime()       # Time of the last OPTIONS received (used to detect flood)
        self.REGISTERReceived = False           # Same for REGISTER
        self.REGISTER_Last_time = gmtime()      # Same for REGISTER

        self.OPTIONS_Exten = []                 # Extensions of the honeypot targeted with OPTIONS of the same source

        self.INVITETag = ""                     # Tag of the received INVITE
        self.ACKReceived = False                # We must know if an ACK was received
        self.Flood = False                      # Flag to know whether flood was detected
    
        self.Show_sound_devices = False
        self.No_registration_param = False
        self.No_audio_param = False

        global reinicioXml
        reinicioXml=False
        
        self.main()                             # Here invokes the method that starts Artemisa

    def __del__(self):
        """
        Destructor. It closes the active connections.
        """

        global Unregister
        
        try:
            del self.email
        except:
            pass

        Unregister = True

        # Delete the Server instances which will close the connections
        try:
            for i in range(len(self.Servers)):
                del self.Servers[i]
        except:
            pass
            
        try:
            self.lib.destroy()
            self.lib = None
        except:
            pass

        xml_serv.server_close()
        xml_serv.shutdown()
        
        
        logger.debug("Artemisa ended.")

    def ArtemisaRestart(self):
        self.__del__()
        sleep(3)
        self.__init__()
        
    def CheckCommandLineParameters(self):
        """
        Checks if some command line parameter has been given and set the corresponding variables.
        """

        usage = "Usage: artemisa [options]"
        parser = OptionParser(usage)
        parser.add_option("-v",
                        "--verbose",
                        dest="verbose",
                        action="store_true",
                        help="verbose mode (shows more information)")
        parser.add_option("-g",
                        "--get_sound_devices",
                        dest="sounddevices",
                        action="store_true",
                        help="show the available sound devices")
        parser.add_option("-r",
                        "--no_registration",
                        dest="noreg",
                        action="store_true",
                        help="doesn't register any extension to the server(s)")
        parser.add_option("-a",
                        "--no_audio",
                        dest="noaudio",
                        action="store_true",
                        help="doesn't use the audio device (audio recording disabled)")

        (options, args) = parser.parse_args()
        
        print (options,args)
        
        if len(args) != 0:
            parser.error("Incorrect number of arguments.")

        if options.verbose:
            self.verbose = True

        if options.sounddevices:
            self.Show_sound_devices = True

        if options.noreg:
            self.No_registration_param = True

        if options.noaudio:
            self.No_audio_param = True

    def main(self):
        """
        Artemisa starts here.
        """
        global Unregister
        global xml_serv

        # First check the command line parameters
        self.CheckCommandLineParameters()


        print "Artemisa v" + self.VERSION + " Copyright (C) 2009-2013 Mohamed Nassar, Rodrigo do Carmo, Pablo Masri, Mauro Villarroel and Exequiel Barrirero"
        print ""
        print "This program comes with ABSOLUTELY NO WARRANTY; for details type 'show warranty'."
        print "This is free software, and you are welcome to redistribute it under certain"
        print "conditions; type 'show license' for details."
        print ""
        print ""
        print "Type 'help' for help."
        print ""
        
        # Read the configuration file artemisa.conf
        self.LoadConfiguration()

        # Read the extensions configuration in extensions.conf
        self.LoadExtensions()

        # Initialize the PJSUA library
        self.lib = pj.Lib() # Starts PJSUA library

        # Read the registrar servers configuration in servers.conf
        self.LoadServers()
        
              
                
        # Create an Email object
        self.email = Email()

        # Set the parameters needed for the PJSUA library
        self.ua_cfg = pj.UAConfig()
        self.ua_cfg.user_agent = self.UserAgent
        self.ua_cfg.max_calls = self.MaxCalls
            
        self.media_cfg = pj.MediaConfig()
        self.media_cfg.clock_rate = self.Sound_rate
        self.media_cfg.no_vad = True
            
        self.log_cfg = pj.LogConfig()
        self.log_cfg.level = 5
        self.log_cfg.callback = self.log_cb
        self.log_cfg.console_level = 5 # The value console_level MUST be 5 since it's used to analyze the messages

        # Initialize the PJSUA library
        try:
            self.lib.init(self.ua_cfg, self.log_cfg, self.media_cfg)
        except Exception, e:
            logger.critical(str(e))
            sys.exit(1)
    
        try:
            self.transp = self.lib.create_transport(pj.TransportType.UDP,
                            pj.TransportConfig(port=int(self.Local_port),
                            bound_addr=self.Local_IP))
            
        except:
            logger.critical("Error while opening port. The port number " + self.Local_port + " is either invalid or already in use by another process.")
            sys.exit(1)
    
        try:
            self.lib.start()
        except:
            logger.critical("Error while starting pj.Lib.")
            sys.exit(1)
    
        # If the command line parameter "-g" has been given then:
        if self.Show_sound_devices:
            a = 0
            print ""
            print ""
            print "List of available sound devices:"
            print ""
            if len(self.lib.enum_snd_dev()) == 0:
                print "No sound device detected."
            else:
                for item in self.lib.enum_snd_dev():
                    print "Index=" + str(a) + " Name=" + item.name
                    a += 1

            print ""
            print ""
        
            exit()

        # Put some lines into the log file
        logger.debug("-------------------------------------------------------------------------------------------------")
        logger.debug("Artemisa started.")
        
        if self.No_audio_param: self.Sound_enabled = False

        if self.Sound_enabled:
            # Configure the audio device 
            try:
                if len(self.lib.enum_snd_dev()) > 0:
                    self.lib.set_snd_dev(self.Sound_device,self.Sound_device)
                else:
                    logger.warning("Audio device not found. Calls will not be recorded.")
                    self.Sound_enabled = False
            except:
                logger.warning("Audio device not found. Calls will not be recorded.")
                self.Sound_enabled = False
        else:
            print "The audio is disabled. Calls will not be recorded."

                
        Unregister = False

        print "SIP User-Agent  listening on: " + self.Local_IP + ":" + self.Local_port
        print "XML-RPC service listening on: "+ self.Local_IP  + ":" + self.Local_xml_port
                   

        print "Behaviour mode: " + self.behaviour_mode
        if len(self.Servers) == 0:
            print "No extensions have been configured."
        else:
            if not self.No_registration_param:
                print "Starting extensions registration process..."
        
                # Register each account
                for i in range(len(self.Servers)):
                    self.Servers[i].Register()
            else:
                print "Server registration is disabled. No extension will be registered."
                
                # One accound must exist in pjsip; otherwise it crashes.
                self.acc = self.lib.create_account_for_transport(self.transp)
                self.acc_cb = MyAccountCallback(self.acc, self.lib, self.behaviour_mode, self.Active_mode, self.Passive_mode, self.Aggressive_mode, self.Sound_enabled, self.Playfile)
                self.acc.set_callback(self.acc_cb)                

        # Convert function XmlServer in a thread and call it.
        thrServerXml = threading.Thread(target=self.XmlServer)
        thrServerXml.start()
        #pj.Lib.thread_register(self.lib, thrServerXml.getName()) #Registro de un external thread a pjsua.
        
        
        # The keyboard is read:
        self.ReadKeyboard()

        # Here finalizes the program when the ReadKeyboard() function is returned.
        
        self.__del__()
        exit()
    
    def ShowHelp(self):
        """
        Keyword Arguments:
        Commands -- when True the commands list is shown 
    
        Shows the help
        """
        print ""    
        print "Commands list:"
        print ""
        print "mode active                  Change behaviour mode to active"
        print "mode passive                 Change behaviour mode to passive"
        print "mode aggressive              Change behaviour mode to aggressive"
        print ""
        print "verbose on                   Turn verbose mode on (it shows more information)"
        print "verbose off                  Turn verbose mode off"
        print "email on                     Turn e-mail report on"
        print "email off                    Turn e-mail report off"
        print ""
        print "show statistics, stats       Show the statistics of the current instance."
        print ""
        print "clean logs                   Remove all log files"
        print "clean results                Remove all results files"
        print "clean calls                  Remove all the recorded calls"
        print "clean all                    Remove all files"
        print "                             (Use these commands carefully)"
        print ""
        print "hangup all                   Hang up all calls"
        print ""
        print "show warranty                Show the program warrany"
        print "show license                 Show the program license"
        print ""
        print "modify extension             To add or delete an Extension"
        print "restart                      To restart Artemisa"
        print ""
        print "s, q, quit, exit             Exit"
     
    def ReadKeyboard(self): 
        """
        This method handles the keyboard process.
        """
        CLIprompt = GetCLIprompt()
            
        while True:
        
            s = raw_input(CLIprompt).strip()
        
            if s == "help":
                self.ShowHelp()
        
            elif s == "show statistics" or s == "stats":
                print "Artemisa's instance statistics"
                print "-------------------------------------------------------------------"
                print ""
                print "INVITE messages received: " + str(self.N_INVITE)
                print "OPTIONS messages received: " + str(self.N_OPTIONS)
                print "REGISTER messages received: " + str(self.N_REGISTER)
                if self.Flood: 
                    FloodDetected = "yes"
                else:
                    FloodDetected = "no"
                print "Flood detected?: " + FloodDetected
                print ""
                
            elif s == "hangup all":
                self.lib.hangup_all()
                print "Done"
            
            elif s == "clean logs":
                Process = Popen("rm -f " + LOGS_DIR + "*.log", shell=True, stdout=PIPE)
                Process.wait()
                # FIXME: Here is a bug! If the logs are deleted the logger cannot continue logging.
                print "Cleaned"
            
            elif s == "clean results":
                Process = Popen("rm -f " + RESULTS_DIR + "*", shell=True, stdout=PIPE)
                Process.wait()
                print "Cleaned"
            
            elif s == "clean calls":
                Process = Popen("rm -f " + RECORDED_CALLS_DIR + "*", shell=True, stdout=PIPE)
                Process.wait()
                print "Cleaned"
                        
            elif s == "clean all":
                Process = Popen("rm -f " + LOGS_DIR + "*.log", shell=True, stdout=PIPE)
                Process.wait()
                Process = Popen("rm -f " + RESULTS_DIR + "*", shell=True, stdout=PIPE)
                Process.wait()
                Process = Popen("rm -f " + RECORDED_CALLS_DIR + "*", shell=True, stdout=PIPE)
                Process.wait()
                print "Cleaned"
                               
            elif s == "mode active":
                self.behaviour_mode = "active"
                logger.info("Behaviour mode changed to active.")

            elif s == "mode passive":
                self.behaviour_mode = "passive"
                logger.info("Behaviour mode changed to passive.")
            
            elif s == "mode aggressive":
                self.behaviour_mode = "aggressive"
                logger.info("Behaviour mode changed to aggressive.")
                        
            elif s.find("verbose") != -1 and s.find("on") != -1:
                self.verbose = True
                logger.info("Verbose mode on.")
            
            elif s.find("verbose") != -1 and s.find("off") != -1:
                self.verbose = False
                logger.info("Verbose mode off.")
                        
            elif s.find("email") != -1 and s.find("on") != -1:
                self.email.Enabled = True
                logger.info("E-mail reporting on.")
            
            elif s.find("email") != -1 and s.find("off") != -1:
                self.email.Enabled = False
                logger.info("E-mail reporting off.")
            
            elif s == 'modify extension':
                
                mod = raw_input('add|delete: ').strip()
                ext = raw_input ('extension: ').strip()
                user = raw_input ('username: ').strip()
                passwd = getpass.getpass('password: ').strip()
                
                self.ModifyExt(mod,ext,user,passwd)
                
            elif s == 'restart':
                self.ArtemisaRestart()
                  
            
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
                #thread_xml_s = xml_serv()
                #thread_xml_s.stop()
                break

                                        
            elif s.strip() == "":
                continue

            else:
                print "Command not found. Type \"help\" for the list of commands."

    def LoadExtensions(self):
        """
        Load configurations from file extensions.conf
        """
        config = ConfigParser.ConfigParser()
        try:
            Temp = config.read(EXTENSIONS_FILE_PATH)
        except:
            logger.critical("The configuration file extensions.conf cannot be read.")
            sys.exit(1)
    
        if Temp == []:
            logger.critical("The configuration file extensions.conf cannot be read.")
            sys.exit(1)
        else:
            try:
                if len(config.sections()) == 0:
                    logger.critical("At least one extension must be defined in extensions.conf.")
                    sys.exit(1)

                for item in config.sections():
                    self.Extensions.append(Extension(item, config.get(item, "username"), config.get(item, "password")))
                    
            except Exception, e:
                logger.critical("The configuration file extensions.conf cannot be correctly read. Check it out carefully. More info: " + str(e))
                sys.exit(1)

        del config
    
    def LoadServers(self): 
        """
        Load configurations from file servers.conf
        """
        config = ConfigParser.ConfigParser()
        try:
            Temp = config.read(SERVERS_FILE_PATH)
        except:
            logger.critical("The configuration file servers.conf cannot be read.")
            sys.exit(1)
    
        if Temp == []:
            logger.critical("The configuration file servers.conf cannot be read.")
            sys.exit(1)
        else:
            try:
                if len(config.sections()) == 0:
                    logger.critical("At least one server must be defined in servers.conf.")
                    sys.exit(1)

                for item in config.sections():

                    Temp2 = config.get(item, "exten")
                    Temp2 = Temp2.split(",")

                    exten_list = []
                    for x in range(len(Temp2)):
                        for j in range(len(self.Extensions)):
                            if Temp2[x] == self.Extensions[j].Extension:
                                exten_list.append(self.Extensions[j])
                                break

                    self.Servers.append(Server(self.behaviour_mode, 
                                            item,
                                            self.Active_mode,
                                            self.Passive_mode,
                                            self.Aggressive_mode,
                                            config.get(item, "registrar_ip"),
                                            config.get(item, "registrar_port"),
                                            int(config.get(item, "registrar_time")),
                                            int(config.get(item, "nat_keepalive_interval")),
                                            exten_list,
                                            self.lib,
                                            self.Sound_enabled,
                                            self.Playfile))
            
            except Exception, e:
                print str(e)
                logger.critical("The configuration file servers.conf cannot be correctly read. Check it out carefully. More info: " + str(e))
                sys.exit(1)

        del config
    
    def LoadConfiguration(self):
        """
        Load configurations from file artemisa.conf
        """
        config = ConfigParser.ConfigParser()
        try:
            Temp = config.read(CONFIG_FILE_PATH)
        except:
            logger.critical("The configuration file artemisa.conf cannot be read.")
            sys.exit(1)
    
        if Temp == []:
            logger.critical("The configuration file artemisa.conf cannot be read.")
            sys.exit(1)
        else:
        
            try:    
       
                # Gets the parameters of the behaviour modes
                self.Active_mode = GetConfigSection(BEHAVIOUR_FILE_PATH, "active")
                self.Passive_mode = GetConfigSection(BEHAVIOUR_FILE_PATH, "passive")
                self.Aggressive_mode = GetConfigSection(BEHAVIOUR_FILE_PATH, "aggressive")
                self.Investigate_sec = GetConfigSection(BEHAVIOUR_FILE_PATH, "investigate") 
                
                # Now checks if the items read are known
                for item in self.Active_mode:
                    if (item != "send_180") and (item != "send_200"):
                        self.Active_mode.remove(item)

                for item in self.Passive_mode:
                    if (item != "send_180") and (item != "send_200"):
                        self.Passive_mode.remove(item)

                for item in self.Aggressive_mode:
                    if (item != "send_180") and (item != "send_200"):
                        self.Aggressive_mode.remove(item)
    
                self.Local_IP = config.get("environment", "local_ip")
                
                # Now check if the given IP is a valid IP (valid format)
                try:
                    IP(self.Local_IP)
                except:
                    logger.critical("The IP address configured in local_ip in file artemisa.conf is not valid (IP address: " + self.Local_IP + ").")
                    sys.exit(1)
        
                self.Local_port = config.get("environment", "local_port")

                try:
                    int(self.Local_port)
                except:
                    logger.error("local_port in configuration file must be an integer. Set to 5060.")
                    self.Local_port = "5060"
                
                self.Local_xml_port = config.get("environment", "local_xml_port")
                
                try:
                    int(self.Local_xml_port)
                except:
                    logger.error("local_xml_port in configuration file must be an integer. Set to 8000.")
                    self.Local_xml_port = "8000"

                self.SIPdomain = config.get("environment", "sip_domain")
                self.UserAgent = config.get("environment", "user_agent")
                self.behaviour_mode = config.get("environment", "behaviour_mode")
                try:
                    self.MaxCalls  = int(config.get("environment", "max_calls"))
                except:
                    logger.error("max_calls in configuration file must be an integer. Set to 1.")
                    self.MaxCalls = 1
                self.Playfile = config.get("environment", "playfile")

                self.Sound_enabled = config.get("sound", "enabled")
                
                            

                try:
                    self.Sound_device = int(config.get("sound", "device"))
                except:
                    logger.error("device in configuration file must be an integer. Set to 0.")
                    self.Sound_device = 0

                try:
                    self.Sound_rate = int(config.get("sound", "rate"))
                except:
                    logger.error("rate in configuration file must be an integer. Set to 44100.")
                    self.Sound_rate = 44100
            
                if self.behaviour_mode != "active" and self.behaviour_mode != "passive" and self.behaviour_mode != "aggressive":
                    self.behaviour_mode = "passive"
                    logger.info("behaviour_mode value is invalid. Changed to passive.")
                    
            except Exception, e:
                logger.critical("The configuration file artemisa.conf cannot be correctly read. Check it out carefully. Details: " + str(e))
                sys.exit(1)

        del config
        
        # Now it reads the actions.conf file to load the user-defined parameters to sent when calling the scripts
        config = ConfigParser.ConfigParser()
        try:
            Temp = config.read(ACTIONS_FILE_PATH)
        except:
            logger.critical("The configuration file actions.conf cannot be read.")
            sys.exit(1)    

        if Temp == []:
            logger.critical("The configuration file actions.conf cannot be read.")
            sys.exit(1)
        else:
            try:
                # Gets the parameters for the on_flood.sh
                self.On_flood_parameters = config.get("actions", "on_flood")
                self.On_SPIT_parameters = config.get("actions", "on_spit")
                self.On_scanning_parameters = config.get("actions", "on_scanning")
            
            except:
                logger.critical("The configuration file actions.conf cannot be correctly read. Check it out carefully.")
                sys.exit(1)

        del config            

    def XmlServer(self):
        """
        Creation of the XML Server
        """
        global xml_serv
        xml_serv = SimpleXMLRPCServer((self.Local_IP, int(self.Local_xml_port)), requestHandler=RequestHandler)
        ### Function to allow Clients (XML-RPC connections) to access XML-RPC service methos - API Interface
        xml_serv.register_introspection_functions()
        
        print '' # necessary to correct the console for a better output visualization
        #logger.info('XML-RPC service running...')
       
        xml_serv.register_function(self.ModifyExt,'modify_extension')
              
        def RestartArtemisa():
            f= open('/dev/stdin','w')
            f.write('restart\n')
            #self.ArtemisaRestart()
        xml_serv.register_function(RestartArtemisa,'restart')
        
        #### Run the XML-RPC_service main loop
        xml_serv.serve_forever()
        
                
    def ModifyExt(self,mod,ext,user,passwd):
        """
        Modify extensions from file extensions.conf
        """
        
        config = ConfigParser.ConfigParser()
        config.read(EXTENSIONS_FILE_PATH)
        
        config1 = ConfigParser.ConfigParser()
        config1.read(SERVERS_FILE_PATH)
        
        ext_aux = []
        
        # se usara la instancia configServer de la clase ConfigParser para
        # escribir en server.conf 
        #configServer = ConfigParser.ConfigParser()
        #configServer.read(EXTENSIONS_FILE_PATH)
        
        if mod == 'add':
            if config.has_section(ext):
                logger.info ('Extension '+ext+' already exists in extensions.conf')
                return 'Extension '+ext+' already exists'

            elif len(config.sections()) <= 7:
                
                config.add_section(ext)
                config.set(ext,'username','"'+user+'"')
                config.set(ext,'password',passwd)
                
                with open(EXTENSIONS_FILE_PATH,'wb') as configfile:
                    config.write(configfile)
                
                archi=open(EXTENSIONS_FILE_PATH,'r')
                lineS=archi.readlines()
                archi.close()

                archi=open(EXTENSIONS_FILE_PATH,'w')                
                archi.write("# Artemisa - Extensions configuration file\n#\n# Be careful when modifying this file!\n\n\n# Here you are able to set up the extensions that shall be used by Artemisa in the registration process. In order to use them, they must be defined in the servers.conf file.\n#\n# The sections name hereunder, such as 3000 in section [3000], refers to a SIP extension and it must be unique in this file, as well as correctly configured in the registrar server.\n\n")
                archi.writelines(lineS)
                archi.close()
                
                logger.info ('Extension '+ext+' added in extensions.conf')
            
                if config1.has_option('myproxy','exten'):
                    b = False
                    ext_aux = config1.get('myproxy','exten').split(',')
                    for i in ext_aux:
                        if ext == i:
                            logger.info ('Extension '+ext+' already exists in servers.conf')
                            return 'Extension '+ext+' already exists.'
                       
                        aux_str = '%s' % ','.join(map(str, ext_aux))
                        config1.set('myproxy','exten',str(aux_str)+','+ext)
                        with open(SERVERS_FILE_PATH,'wb') as configfile:
                            config1.write(configfile)
                        
                        archi=open(SERVERS_FILE_PATH,'r')
                        lineS=archi.readlines()
                        archi.close()

                        archi=open(SERVERS_FILE_PATH,'w')                
                        archi.write("# Artemisa - Servers configuration file\n#\n# Be careful when modifying this file!\n\n\n# Here you are able to set the registrar servers configuration that Artemisa shall use to register itself.\n#\n# registrar_time=\n# Is the time in minutes between automatic registrations. This is performed in order to avoid\n# being disconnected from the server because of a lack of activity.\n#\n# nat_keepalive_interal=\n# When dealing with NAT proxies, you can set a value in seconds which indicates the time interval between keep alive messages. If zero is written, then the NAT keep alive messages shall not be sent.\n#\n# exten=\n# In this field you should set the extensions to be used. They must be declared in extensions.conf.\n\n")
                        archi.writelines(lineS)
                        archi.close()
                                                
                        logger.info ('Extension '+ext+' added in servers.conf')
                        return 'Extension '+ext+' added'
                       
            else:
                logger.info ('Max number of extensions registered. Run another artemisa instance to register more extensions.')
                return 'Max number of extensions registered. Run another artemisa instance to register more extensions.'
        elif mod == 'delete':
            if config.has_section(ext):
                config.remove_section(ext)
                with open(EXTENSIONS_FILE_PATH,'wb') as configfile:
                    config.write(configfile)
                
                archi=open(EXTENSIONS_FILE_PATH,'r')
                lineS=archi.readlines()
                archi.close()

                archi=open(EXTENSIONS_FILE_PATH,'w')                
                archi.write("# Artemisa - Extensions configuration file\n#\n# Be careful when modifying this file!\n\n\n# Here you are able to set up the extensions that shall be used by Artemisa in the registration process. In order to use them, they must be defined in the servers.conf file.\n#\n# The sections name hereunder, such as 3000 in section [3000], refers to a SIP extension and it must be unique in this file, as well as correctly configured in the registrar server.\n\n")
                archi.writelines(lineS)
                archi.close()
                
                logger.info ('Extension '+ext+' deleted in extensions.conf')
                
            else:
                
                logger.info ('Extension '+ext+' does not exists in extensions.conf')
        
            if config1.has_option('myproxy','exten'):
                b = False
                ext_aux = config1.get('myproxy','exten').split(',')
                
                #len_list_aux = len(ext_aux)
                j=0
                while j<len(ext_aux):
                    if ext ==  ext_aux[j]:
                        del(ext_aux[j])
                        #len_list_aux = len(ext_aux)
                        b = True
                    else:
                        j=j+1      
                
                aux_str = '%s' % ','.join(map(str, ext_aux))
                config1.set('myproxy','exten',aux_str)
                with open(SERVERS_FILE_PATH,'wb') as configfile:
                    config1.write(configfile)    
                   
                if not b :
                    
                    archi=open(SERVERS_FILE_PATH,'r')
                    lineS=archi.readlines()
                    archi.close()

                    archi=open(SERVERS_FILE_PATH,'w')                
                    archi.write("# Artemisa - Extensions configuration file\n#\n# Be careful when modifying this file!\n\n\n# Here you are able to set up the extensions that shall be used by Artemisa in the registration process. In order to use them, they must be defined in the servers.conf file.\n#\n# The sections name hereunder, such as 3000 in section [3000], refers to a SIP extension and it must be unique in this file, as well as correctly configured in the registrar server.\n\n")
                    archi.writelines(lineS)
                    archi.close()
                    
                    logger.info ('Extension '+ext+' does not exists in servers.conf')
                    return 'Extension '+ext+' does not exists'
                
                archi=open(SERVERS_FILE_PATH,'r')
                lineS=archi.readlines()
                archi.close()

                archi=open(SERVERS_FILE_PATH,'w')                
                archi.write("# Artemisa - Servers configuration file\n#\n# Be careful when modifying this file!\n\n\n# Here you are able to set the registrar servers configuration that Artemisa shall use to register itself.\n#\n# registrar_time=\n# Is the time in minutes between automatic registrations. This is performed in order to avoid\n# being disconnected from the server because of a lack of activity.\n#\n# nat_keepalive_interal=\n# When dealing with NAT proxies, you can set a value in seconds which indicates the time interval between keep alive messages. If zero is written, then the NAT keep alive messages shall not be sent.\n#\n# exten=\n# In this field you should set the extensions to be used. They must be declared in extensions.conf.\n\n")
                archi.writelines(lineS)
                archi.close()
                
                logger.info ('Extension '+ext+' deleted in servers.conf')
                return 'extension '+ext+' deleted' 
                    
            else:
                logger.info ('Extension '+ext+' does not exists.')
            
        else:
            logger.info ('wrong request please try with "add" or "delete"') 
            return 'wrong request please try with "add" or "delete"'
                              
        del config
        
    """
    The following methods do the message capturing part.
    """

    def WaitForPackets(self, seconds):
        """
        Keyword Arguments:
        seconds -- number of seconds to wait

        This function stops the program some seconds in order to let the system collect more traces
        """
        for i in range(seconds):
            logger.info("Waiting for SIP messages (" + str(seconds-i) + ")...")
            sleep(1)
        
    def GetBehaviourActions(self):
        """
        This function returns the actions of the behaviour mode.
        """
        if self.behaviour_mode == "active":
            return self.Active_mode
        elif self.behaviour_mode == "passive":
            return self.Passive_mode
        elif self.behaviour_mode == "aggressive":
            return self.Aggressive_mode
        
    def SaveResultsToTextFile(self, Results, Filename):
        """
        Keyword Arguments:
        Results -- A CallData instance that contains call information.

        This functions creates a plain text file for the results.
        """
        try:
            File = open(Filename, "w")
            File.write(Results)
            File.close()
            logger.info("This report has been saved on file " + Filename)
        except Exception, e:
            logger.error("Cannot save file " + Filename + ". Details: " + str(e))
            
    def SaveResultsToHTML(self, Results, Filename):
        """
        Keyword Arguments:
        Results -- A CallData instance that contains call information.

        This functions creates a HTML file for the results.
        """
        try:
            File = open(Filename, "w")
            File.write(Results)
            File.close()
            logger.info("NOTICE This report has been saved on file " + Filename)
        except Exception, e:
            logger.error("Cannot save file " + Filename + ". Details: " + str(e))
            
        return Filename

    def SendResultsByEmail(self, HTMLData):
    
        if not self.email.Enabled: 
            logger.info("E-mail notification is disabled.")
        else:
            logger.info("Sending this report by e-mail...")
            self.email.sendemail(HTMLData)
    
    def GetFilename(self, Ext):
        """
        Defines a file name to store the output.
        """
        Filename = ""
        try:
            a = 0
            while 1:
                Filename = RESULTS_DIR + strftime("%Y-%m-%d") + "_" + str(a) + "." + Ext
                        
                if os.path.isfile(Filename):
                    a += 1
                else:
                    break
        except Exception, e:
            logger.error("Cannot create the results file " + Filename + ". Details: " + str(e))

        return Filename

    def AnalyzeMessage(self, SIP_Message_data, MessageType):    
        """
        Core of the program. Here is where the honeypot concludes if the packet received is trusted or not.
        """
        global MediaReceived

        if MessageType == "INVITE":

            # Wait 5 seconds for an ACK and media events. 
            self.WaitForPackets(5)

            # Create an instance of the Classifier
            classifier_instance = Classifier(self.verbose,
                                            self.Local_IP,
                                            self.Local_port,
                                            self.behaviour_mode,
                                            self.GetBehaviourActions(),
                                            SIP_Message_data,
                                            self.Extensions,
                                            self.ACKReceived,
                                            MediaReceived)

            # Start the classification
            classifier_instance.Start()

            while classifier_instance.Running:
                pass
        
            Results = classifier_instance.CallInformation    

            del classifier_instance

            # Call the correlator
            Correlator(Results,
                    self.Flood,
                    self.On_flood_parameters,
                    self.On_SPIT_parameters,
                    self.On_scanning_parameters)
        
            # Save the raw SIP message in the report file
            TXTFilenme = self.GetFilename("txt")
            TXTData = get_results_txt(TXTFilenme,
                                    self.VERSION,
                                    Results,
                                    self.Local_IP,
                                    self.Local_port)
            self.SaveResultsToTextFile(TXTData, TXTFilenme)

            # Save the results in a HTML file
            HTMLFilenme = self.GetFilename("html")    
            HTMLData = get_results_html(HTMLFilenme,
                                        self.VERSION,
                                        Results,
                                        False,
                                        self.Local_IP,
                                        self.Local_port)
            self.SaveResultsToHTML(HTMLData, HTMLFilenme)

            # Send the results by e-mail
            # The function get_results_html is called again and it return an email-adapted format
            HTMLMailData = get_results_html(HTMLFilenme,
                                            self.VERSION,
                                            Results,
                                            True,
                                            self.Local_IP,
                                            self.Local_port)
            self.SendResultsByEmail(HTMLMailData)
            
            Results = None
            
            self.ACKReceived = False

            MediaReceived = False

            self.Flood = False
        
            self.NumCalls -= 1

        elif MessageType == "OPTIONS":

            # The proceedment with the OPTIONS messages is rather different. 

            # Get useful data from the message
            MessageInformation = CallData(SIP_Message_data)

            logger.info("OPTIONS message detected in extension " + MessageInformation.To_Extension + " from " + MessageInformation.Contact_IP + ":" + MessageInformation.Contact_Port)

            # Warning: don't analyze the OPTIONS message if it comes from the Registrar servers since it can
            # cause that Artemisa detects it as a scanning.
            for item in self.Servers:
                if MessageInformation.Contact_IP == item.Registrar_IP:
                    if MessageInformation.Contact_Port == item.Registrar_port:
                        logger.info("OPTIONS message seems to come from one of the SIP proxies. Nothing done.")
                        self.Flood = False
                        return

            # Save the information that links the extension of Artemisa and the IP of the message
            #
            # NOTE: the extensions could be, in fact, any extension (not just extension of Artemisa)
            self.OPTIONS_Exten.append([MessageInformation.To_Extension, MessageInformation.Contact_IP])

            # Now we check if OPTIONS messages from the same source has been seen in two
            # more registered extensions of the honeypot.
            Matches = 1
            for item in self.OPTIONS_Exten:
                if item[0] != MessageInformation.To_Extension: # The extension shoudln't be the same
                    if item[1] == MessageInformation.Contact_IP:
                        Matches += 1

            if Matches == NUMBER_OF_OPTIONS_MATCHES:
                MessageInformation.Classification.append("Scanning")

                logger.info("*********************************** OPTIONS analysis *************************************")
                logger.info("")
                logger.info("The OPTIONS message is detected as an scanning attack!")                
                logger.info("")

                # And call the same method of the correlator used to deal with INVITEs scannings
                CheckIfScanning(MessageInformation, self.On_scanning_parameters)
    
                # Clear the buffer for future detections
                self.OPTIONS_Exten = []
                    
            # If flood is present then call CheckIfFlood
            if self.Flood:
                logger.info("*********************************** OPTIONS analysis *************************************")
                logger.info("")
                logger.info("The OPTIONS message is detected as a flood attack!")                
                logger.info("")

                CheckIfFlood(MessageInformation, True, self.On_flood_parameters)
                self.Flood = False


        elif MessageType == "REGISTER":

            # The proceedment with the REGISTER messages is rather different. 

            # Get useful data from the message
            MessageInformation = CallData(SIP_Message_data)

            # Warning: don't analyze the REGISTER message if it comes from Artemisa.
            if MessageInformation.Contact_IP == self.Local_IP:
                if MessageInformation.Contact_Port == self.Local_port:
                    self.Flood = False
                    return

            logger.info("*********************************** REGISTER message **************************************")
            logger.info("")
            logger.info(" To: " + MessageInformation.To_Extension)
            logger.info(" From: " + MessageInformation.Contact_IP + ":" + MessageInformation.Contact_Port)
            logger.info("")

            # TODO: here we must improve this part, for now copied from the OPTIONS analysis, and make especial
            # considerations for the REGISTER messages.

            # Store in memory the last REGISTER messages received.
            # If the message has the same password, comes from the same sender, and tries to register several extensions,
            # then is a scanning attempt.
            # If the message tries to register one extension but trying to use different passwords, then register message
            # is a password-cracking attack.

            # TODO: THIS IS NOT YET IMPLEMENTED!!!!!!!

            #if not self.Flood:
            #    MessageInformation.Classification.append("Scanning")
            #
            #    logger.info("*********************************** REGISTER analysis *************************************")
            #    logger.info("")
            #    logger.info("The REGISTER message is detected as an scanning attack!")                
            #    logger.info("")
            #
                # And call the same method of the correlator used to deal with INVITEs scannings
            #    CheckIfScanning(MessageInformation, self.On_scanning_parameters)
    
                    
            # If flood is present then call CheckIfFlood
            if self.Flood:
                logger.info("*********************************** REGISTER analysis *************************************")
                logger.info("")
                logger.info("The REGISTER message is detected as a flood attack!")                
                logger.info("")

                CheckIfFlood(MessageInformation, True, self.On_flood_parameters)
                self.Flood = False

    def IsMessage(self, Message, Type):
        Temp = Message.strip().splitlines(True)

        for line in Temp:
            if line.find(Type) != -1 and line.find("SIP/" + self.SIP_VERSION) != -1:
                return True

        return False

    def log_cb(self, level, str, len):
        """
        This is quite dirty but I wasn't able to find another way to capture the raw messages.
        This function saves the data returned by PJSUA module. This shows also the SIP packet, so it's possible
        to analyse it directly from here, and there is no need to use some capturing packet function.
        This function is very important.
        """
        pjsua_logger.debug(str.strip())
    
        # Intercepts ACK messages
        if self.IsMessage(str, "ACK"):
            # Here we check if the ACK received is for the received INVITE.        
            if Search("tag", str) == self.INVITETag:
                self.ACKReceived = True


        # Intercepts OPTIONS messages
        elif self.IsMessage(str, "OPTIONS"):
            # Actions if the message is an OPTIONS

            self.OPTIONSReceived = True
            self.N_OPTIONS += 1

            TimeNow = gmtime()

            # If the distance in time between this OPTIONS message and the last received is less than
            # a second, then it's reported as flood.
            if (TimeNow.tm_hour - self.OPTIONS_Last_time.tm_hour) == 0:
                if (TimeNow.tm_min - self.OPTIONS_Last_time.tm_min) == 0:
                    if (TimeNow.tm_sec - self.OPTIONS_Last_time.tm_sec) == 0:
                        self.Flood = True

            self.OPTIONS_Last_time = TimeNow

            OPTIONSMessage = ""

            Temp = str.strip().splitlines(True)            
            i = -1
            for line in Temp:
                line = line.strip()
                i += 1
                if i > 0 and line.find("--end msg--") == -1:
                    if OPTIONSMessage != "":
                        OPTIONSMessage += "\n" + line
                    else:
                        OPTIONSMessage = line
        
            if self.LastOPTIONSreceived == OPTIONSMessage:
                logger.info("Duplicated OPTIONS detected.")
                return # Don't analyze repeated messages
                
            # Store the OPTIONS message for the future
            self.LastOPTIONSreceived = OPTIONSMessage

            # Convert function AnalyzeMessage in a thread and call it.
            thrAnalyzeMessage = threading.Thread(target=self.AnalyzeMessage, args=(OPTIONSMessage,"OPTIONS",))
            thrAnalyzeMessage.start()


        # Intercepts REGISTER messages
        elif self.IsMessage(str, "REGISTER"):
            # Actions if the message is an REGISTER

            self.REGISTERReceived = True
            self.N_REGISTER += 1

            TimeNow = gmtime()

            # If the distance in time between this REGISTER message and the last received is less than
            # a second, then it's reported as flood.
            if (TimeNow.tm_hour - self.REGISTER_Last_time.tm_hour) == 0:
                if (TimeNow.tm_min - self.REGISTER_Last_time.tm_min) == 0:
                    if (TimeNow.tm_sec - self.REGISTER_Last_time.tm_sec) == 0:
                        self.Flood = True

            self.REGISTER_Last_time = TimeNow

            REGISTERMessage = ""

            Temp = str.strip().splitlines(True)            
            i = -1
            for line in Temp:
                line = line.strip()
                i += 1
                if i > 0 and line.find("--end msg--") == -1:
                    if REGISTERMessage != "":
                        REGISTERMessage += "\n" + line
                    else:
                        REGISTERMessage = line
        
            if self.LastREGISTERreceived == REGISTERMessage:
                logger.info("Duplicated REGISTER detected.")
                return # Don't analyze repeated messages
                
            # Store the REGISTER message for the future
            self.LastREGISTERreceived = REGISTERMessage

            # Convert function AnalyzeMessage in a thread and call it.
            thrAnalyzeMessage = threading.Thread(target=self.AnalyzeMessage, args=(REGISTERMessage,"REGISTER",))
            thrAnalyzeMessage.start()


        # Intercepts INVITE messages
        elif self.IsMessage(str, "INVITE"):
            # Actions if the message is an INVITE

            self.N_INVITE += 1

            # Store the tag of the INVITE to be used later to identify the ACK
            self.INVITETag = Search("tag", str)
        
            INVITEMessage = ""

            Temp = str.strip().splitlines(True)            
            i = -1
            for line in Temp:
                line = line.strip()
                i += 1
                if i > 0 and line.find("--end msg--") == -1:
                    if INVITEMessage != "":
                        INVITEMessage += "\n" + line
                    else:
                        INVITEMessage = line
        
            if self.LastINVITEreceived == INVITEMessage:
                logger.info("Duplicated INVITE detected.")
                return # Don't analyze repeated messages
                
            logger.info("INVITE message detected.")

            # Store the INVITE message for the future
            self.LastINVITEreceived = INVITEMessage

            if self.NumCalls == self.MaxCalls:
                logger.info("The maximum number of calls to simultaneously analyze has been reached.")
                self.Flood = True
                     
                return

            # Convert function AnalyzeMessage in a thread and call it.
            thrAnalyzeMessage = threading.Thread(target=self.AnalyzeMessage, args=(INVITEMessage,"INVITE",))
        
            self.NumCalls += 1

            thrAnalyzeMessage.start()
            
            
    
    

    
