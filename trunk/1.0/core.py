# Artemisa v1.0
# Copyright (C) 2009 Mohamed Nassar <nassar@loria.fr>, Rodrigo do Carmo <rodrigodocarmo@gmail.com>, 
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

VERSION = "1.0."

# Definition of directories and files
CONFIG_DIR = "./conf/"
SCRIPTS_DIR = "./scripts/"
RESULTS_DIR = "./results/"
AUDIOFILES_DIR = "./audiofiles/"
LOGS_DIR = "./logs/"
RECORDED_CALLS_DIR = "./recorded_calls/"

CONFIG_FILE_PATH = CONFIG_DIR + "artemisa.conf"
BEHAVIOUR_FILE_PATH = CONFIG_DIR + "behaviour.conf"
ACTIONS_FILE_PATH = CONFIG_DIR + "actions.conf"
EXTENSIONS_FILE_PATH = CONFIG_DIR + "extensions.conf"
SERVERS_FILE_PATH = CONFIG_DIR + "servers.conf"
ON_FLOOD_SCRIPT_PATH = SCRIPTS_DIR + "on_flood.sh"
ON_SPIT_SCRIPT_PATH = SCRIPTS_DIR + "on_spit.sh"
ON_SCANNING_SCRIPT_PATH = SCRIPTS_DIR + "on_scanning.sh"

try:
	"""
	Try to import the PJSUA library. It's used for the SIP stack handling.
	"""
	import pjsua as pj
except ImportError:
	print ""
	print "Critical error:"
	print "PJSIP library module MUST be installed!"
	print ""
	print "Download it from:"
	print "    http://www.pjsip.org/download.htm"
	print ""
	print "    or do:"
	print ""
	print "    wget http://www.pjsip.org/release/1.6/pjproject-1.6.tar.bz2"
	print ""
	print "Installation steps:"
	print "    http://trac.pjsip.org/repos/wiki/Python_SIP/Build_Install"
	print ""
	print "       In a nutshell:"
	print ""
	print "       1) Check that make, gcc, binutils, Python, and Python-devel are installed."
	print "       2) Build the PJSIP libraries first with \"# ./configure && make dep && make\" commands."
	print "	      Note: if fails try:./configure CFLAGS=-fPIC"
	print "       3) Go to the pjsip-apps/src/python directory."
	print "       4) Run \'# python setup.py install\' or just \'# make\'."
	print ""
	sys.exit(1)

import sys, os
	
import ConfigParser							# Read configuration files

from time import strftime, sleep, time
import sched
from modules.commons import *				# Import functions from commons.py
from modules.classifier import Classifier	# Message classifier 
from modules.correlator import Correlator	# Correlator
from modules.correlator import IfCategory
import threading							# Use of threads

from modules.mail import Email
from modules.results_format import get_results_txt, get_results_html

from subprocess import Popen, PIPE

from modules.logger import logger 			# Instance a logger for information about Artemisa
from modules.logger import pjsua_logger 	# Instance a logger for information about the PJSUA library

Unregister = False 							# Flag to know whether the unregistration process is taking place

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

	def __init__(self, behaviour_mode, Name, Active_mode, Passive_mode, Aggressive_mode, Registrar_IP, Registrar_port, Registrar_time, NAT_ka_interval, Extensions, lib, Sound_enabled, MediaReceived, Playfile):
		self.Name = Name
		self.Active_mode = Active_mode
		self.Passive_mode = Passive_mode
		self.Aggressive_mode = Aggressive_mode
		self.Registrar_IP = Registrar_IP	# Registrar server IP (Asterisk, SER, etc.)
		self.Registrar_port = Registrar_port	# Registrar server port
		self.Registrar_time = Registrar_time	# Time in minutes between REGISTRAR messeges sent to the server.
		self.RegSchedule = ""			# Time between registrations
		self.NAT_ka_inverval = NAT_ka_interval	# Time between NAT keep alive messages
		self.behaviour_mode = behaviour_mode	# Artemisa's behaviour mode

		self.Extensions = Extensions		# Store the extensions registered to the SIP server
		self.acc = None
		self.acc_cfg = None
		self.acc_cb = None

		self.lib = lib
		self.Sound_enabled = Sound_enabled
		self.MediaReceived = MediaReceived
		self.Playfile = Playfile

	def Register(self):
		"""
		This method registers the honeypot at the SIP server, and keeps it alive by sending REGISTRAR
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

		try:
			self.acc = None
			self.acc_cfg = None
			self.acc_cb = None
		except:
			pass
		
		for i in range(len(self.Extensions)):
			self.acc_cfg = pj.AccountConfig(self.Registrar_IP + ":" + self.Registrar_port, self.Extensions[i].Extension, self.Extensions[i].Password, self.Extensions[i].Username)
			self.acc_cfg.reg_timeout = self.Registrar_time * 60
			self.acc_cfg.ka_interval = self.NAT_ka_inverval
			self.acc = self.lib.create_account(self.acc_cfg)

			self.acc_cb = MyAccountCallback(self.acc, self.lib, self.behaviour_mode, self.Active_mode, self.Passive_mode, self.Aggressive_mode, self.Sound_enabled, self.MediaReceived, self.Playfile)
			self.acc.set_callback(self.acc_cb)
	
			logger.info("Extension " + str(self.Extensions[i].Extension) + " registration sent. Status: " + str(self.acc.info().reg_status) + " (" + str(self.acc.info().reg_reason) + ")")


	def Reregister(self):
		"""
		This method do the re-registration.
		"""
		self.acc.set_registration(True)

	#def Unregister(self):
	#	self.acc.delete()
	#	self.acc = None



class MyAccountCallback(pj.AccountCallback):
	"""
	Callback to receive events from account.
	"""

	def __init__(self, account, lib, behaviour_mode, Active_mode, Passive_mode, Aggressive_mode, Sound_enabled, MediaReceived, Playfile):
		pj.AccountCallback.__init__(self, account)
		self.lib = lib
		self.behaviour_mode = behaviour_mode
		self.Active_mode = Active_mode
		self.Passive_mode = Passive_mode
		self.Aggressive_mode = Aggressive_mode
		self.Sound_enabled = Sound_enabled
		self.MediaReceived = MediaReceived
		self.Playfile = Playfile

	def on_reg_state(self):
		if Unregister == False:
			if self.account.info().reg_status >= 200 and self.account.info().reg_status < 300:
				logger.info("Extension " + str(self.account.info().uri) + " registered, status=" + str(self.account.info().reg_status) + " (" + str(self.account.info().reg_reason) + ")")	
			#elif (self.account.info().reg_status >= 400 and self.account.info().reg_status < 500) or self.account.info().reg_status > 700:
			elif self.account.info().reg_status >= 300 and self.account.info().reg_status < 700:
				logger.info("Extension " + str(self.account.info().uri) + " registration failed, status=" + str(self.account.info().reg_status) + " (" + str(self.account.info().reg_reason) + ")")
				# This part is important since it's necessary to try the registration again if it fails.
				logger.info("Trying to register again.")
				self.account.set_registration(True)
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

		self.current_call = call

		self.call_cb = MyCallCallback(self.lib, self.current_call, self.Sound_enabled, self.MediaReceived, self.Playfile)
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
							
		#self.current_call.hangup()

class MyCallCallback(pj.CallCallback):
	"""
	Callback to receive events from Call
	"""
 	def __init__(self, lib, current_call, Sound_enabled, MediaReceived, Playfile):
		self.current_call = current_call
		pj.CallCallback.__init__(self, self.current_call)
		self.rec_slot = None
		self.rec_id = None
		self.player_slot = None
		self.player_id = None

		self.lib = lib
		self.Sound_enabled = Sound_enabled
		self.MediaReceived = MediaReceived
		self.Playfile = Playfile

	# Notification when call state has changed
	def on_state(self):
		
		logger.info("Call from " + str(self.call.info().remote_uri) +  " is " + str(self.call.info().state_text) + ", last code = " + str(self.call.info().last_code) + " (" + str(self.call.info().last_reason) + ")")
		
		if self.call.info().state == pj.CallState.DISCONNECTED:
			
			if self.Sound_enabled == True:
				try:
					
					self.call_slot = self.call.info().conf_slot
						
					# Disconnect the call with the WAV recorder
					self.lib.conf_disconnect(self.call_slot, self.rec_slot)
					
					self.lib.recorder_destroy(self.rec_id)

					# Disconnect the call from the player
					self.lib.conf_disconnect(self.player_slot, self.call_slot)
					
					self.lib.player_destroy(self.player_id)
					
				except Exception, e:
					logger.warning("Error: " + str(e))
					
				self.current_call = None
				logger.info("Current call is " + str(current_call))
		
	# Notification when call's media state has changed.
	def on_media_state(self):
		
		if self.Sound_enabled == False: return
		
		if self.call.info().media_state == pj.MediaState.ACTIVE: 
			try:
				# Connect the call to the recorder 
				self.call_slot = self.call.info().conf_slot 
				
				if self.rec_id < 0: 
					
					a = 0
					while 1:
						Filename = RECORDED_CALLS_DIR + strftime("%Y-%m-%d") + "_call_from_" + str(self.call.info().remote_uri).split("@")[0].split(":")[1] + "_" + str(a) + ".wav"
						
						if os.path.isfile(Filename) == True:
							a += 1
						else:
							break
					
					# Set the recorder
					self.rec_id = self.lib.create_recorder(Filename)
					self.rec_slot = self.lib.recorder_get_slot(self.rec_id)
				
					# Connect the call with the WAV recorder
					self.lib.conf_connect(self.call_slot, self.rec_slot)
					
					logger.info("Audio is now being recorded on file: " + Filename)
					
					self.MediaReceived = True
				
			except Exception, e:
				logger.error("Error while trying to record the call. Details: " + str(e))

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
	
			except Exception, e:
				logger.error("Error while trying to play the WAV file. Details: " + str(e))
  
		else:

			try:
				self.call_slot = self.call.info().conf_slot
				
				# Disconnect the call with the WAV recorder
				pj.Lib.instance().conf_disconnect(self.call_slot, self.lib.recorder_get_slot(self.rec_id))

				# Disconnect the call from the player
				pj.Lib.instance().conf_disconnect(self.lib.player_get_slot(self.player_id), self.call_slot)

			except Exception, e:
				logger.warning("Error: " + str(e))
			
			logger.info("Audio is inactive. Check the configuration file.") 

class Artemisa(object):
	"""
	This is the class which defines de whole program.
	"""

	def __init__(self, args=[]):

		self.VERSION = VERSION
		self.SIP_VERSION = "2.0"

		# Environment configuration
		self.Local_IP = ""				# Local IP
		self.Local_port = ""				# Local port
		self.SIPdomain = ""				# Local SIP domain
		self.UserAgent = ""				# User-Agent name used by Artemisa 
		self.MaxCalls = 0				# Max number of calls to handle
		self.NumCalls = 0				# Number of calls being analysed
		self.Playfile = ""				# Name of the file to be played

		# Sound configuration
		self.Sound_enabled = True
		self.Sound_device = 0
		self.Sound_rate = 44100

		# Behaviour modes configuration
		self.behaviour_mode = "active"			# Inference analysis behaviour
		self.Active_mode = []
		self.Passive_mode = []
		self.Aggressive_mode = []

		self.On_flood_parameters = ""			# Parameters to send when calling on_flood.sh
		self.On_SPIT_parameters = ""			# Parameters to send when calling on_spit.sh
		self.On_scanning_parameters = ""		# Parameters to send when calling on_scanning.sh

		self.verbose = False				# verbose mode

		self.Servers = []				# SIP REGISTRAR servers
		self.Extensions = []				# Extensions

		self.LastINVITEreceived = ""			# Store the last INVITE message received in order to avoid analysing repeated messages

		#self.nSeq = 0					# Number of received messages

		# Statistics
		self.N_INVITE = 0
		self.N_OPTIONS = 0
		self.FLOOD = "no"

		self.OPTIONSReceived = False			# Flag to know if a OPTIONS was received

		# TODO: Anti-flood mechanism for OPTIONS flood not yet implemented
		#self.OPTIONS_Flood_timer0 = 0			# Flag to set a timer to detect OPTIONS flood
		#self.OPTIONS_Flood_timer1 = 0			# Flag to set a timer to detect OPTIONS flood

		self.INVITETag = ""				# Tag of the received INVITE
		self.ACKReceived = False			# We must know if an ACK was received
		self.MediaReceived = False			# Flag to know whether media has been received
		self.Flood = False				# Flag to know whether flood was detected
	
		self.main(args) # Here invokes the method that starts Artemisa

	def __del__(self):
		"""
		Destructor. It closes the active connections.
		"""

		Unregister = True

		#del self.current_call

		try:
			self.lib.destroy()
			self.lib = None
		except:
			pass

		logger.debug("Artemisa ended.")

	def main(self, args=[]):
		"""
		Artemisa starts here.
		"""
		Show_sound_devices = False
	
		# Check if some arguments has been passed
		if len(args) > 1:
			for i in range(1, len(args)):
				if args[i] == "-h" or args[i] == "--help":
					self.ShowHelp(False)
					sys.exit(0)
				elif args[i] == "-v" or args[i] == "--verbose":
					self.verbose = True
				elif args[i] == "-g" or args[i] == "--get_sound_devices":
					Show_sound_devices = True
				else:
					print "Invalid argument: " + args[i]
					sys.exit(0)
					
		print "Artemisa v" + self.VERSION + " Copyright (C) 2009-2010 Mohamed Nassar, Rodrigo do Carmo, and Pablo Masri"
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
			
		try:
			self.lib.init(self.ua_cfg, self.log_cfg, self.media_cfg)
		except Exception, e:
			logger.error(str(e))
			sys.exit(0)
	
		try:
			self.lib.create_transport(pj.TransportType.UDP, pj.TransportConfig(int(self.Local_port)))
		except Exception, e:
			logger.error("Error. More info: " + str(e))
			self.lib.destroy()
			self.lib = None
			sys.exit(1)
	
		try:
			self.lib.start()
		except Exception, e:
			logger.error(str(e))
			sys.exit(0)
	
		if Show_sound_devices == True:
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
		
			sys.exit(0)

		# Put some lines into the log file
		logger.debug("-------------------------------------------------------------------------------------------------")
		logger.debug("Artemisa started.")
			
		if self.Sound_enabled == True:
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

				
		Unregister = False

		print "User Agent listening on: " + self.Local_IP + ":" + self.Local_port
	
		print "Behaviour mode: " + self.behaviour_mode

		if len(self.Servers) == 0:
			print "No extensions have been configured."
		else:
			print "Starting extensions registration process..."
		
			# Register each account
			for i in range(len(self.Servers)):
				self.Servers[i].Register()
	   
		# The keyboard is read:
		self.ReadKeyboard()

		# Here finalizes the program when the ReadKeyboard() function is returned.
		sys.exit(0)
	
	def ShowHelp(self, Commands = True):
		"""
		Keyword Arguments:
		Commands -- when True the commands list is shown. 
	
		Shows the help
		"""
		print "Usage: artemisa [Options]"
		print "  -v, --verbose			Verbose mode (it shows more information)."
		print "  -g, --get_sound_devices   Show the available sound devices."
	
		if Commands == False: return
	
		print ""	
		print "Commands list:"
		print ""
		print "mode active			Change behaviour mode to active."
		print "mode passive			Change behaviour mode to passive."
		print "mode aggressive			Change behaviour mode to aggressive."
		print ""
		print "verbose on			Turn verbose mode on (it shows more information)."
		print "verbose off			Turn verbose mode off."
		print ""
		print "show statistics, stats		Show the statistics of the current instance."
		print ""
		print "clean logs			Remove all log files."
		print "clean results			Remove all results files."
		print "clean calls			Remove all the recorded calls."
		print "clean all			Remove all files."
		print "				(Use these commands carefully)"
		print ""
		print "hangup all			Hang up all calls."
		print ""
		print "show warranty			Show the program warrany."
		print "show license			Show the program license."
		print ""
		print "s, q, quit, exit		Exit"
	 
	def ReadKeyboard(self): 
		"""
		This method handles the keyboard process.
		"""
		if os.getenv('HOSTNAME') == None:
			# Well... some distributions don't export the environmental variable HOSTNAME...
			CLIprompt = str(os.getenv('USER')) + "> "
		else:
			CLIprompt = str(os.getenv('HOSTNAME')) + "> "
	
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
				print "Flood detected?: " + self.FLOOD
				print ""
				
			elif s == "hangup all":
				self.lib.hangup_all()
				print "Done"
			
			elif s == "clean logs":
				Process = Popen("rm -f " + LOGS_DIR + "*.log", shell=True, stdout=PIPE)
				Process.wait()
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

			elif s.strip() == "":
				continue

			else:
				print "Command not found. Type \"help\" for a list of commands."

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
					logger.error("At least one extension must be defined in extensions.conf")
					sys.exit(1)

				for item in config.sections():
					self.Extensions.append(Extension(item, config.get(item, "username"), config.get(item, "password")))
					
			except:
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
					logger.error("At least one server must be defined in servers.conf")
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

					self.Servers.append(Server(self.behaviour_mode, item, self.Active_mode, self.Passive_mode, self.Aggressive_mode, config.get(item, "registrar_ip"), config.get(item, "registrar_port"), int(config.get(item, "registrar_time")), int(config.get(item, "nat_keepalive_interval")), exten_list, self.lib, self.Sound_enabled, self.MediaReceived, self.Playfile))
			
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
				self.Local_port = config.get("environment", "local_port")

				try:
					temp = int(self.Local_port)
				except:
					logger.error("local_port in configuration file must be an integer. Set to 5060")
					self.Local_port = "5060"

				self.SIPdomain = config.get("environment", "sip_domain")
				self.UserAgent = config.get("environment", "user_agent")
				self.behaviour_mode = config.get("environment", "behaviour_mode")
				try:
					self.MaxCalls  = int(config.get("environment", "max_calls"))
				except:
					logger.error("max_calls in configuration file must be an integer. Set to 1")
					self.MaxCalls = 1
				self.Playfile = config.get("environment", "playfile")

				self.Sound_enabled = config.get("sound", "enabled")
				
							

				try:
					self.Sound_device = int(config.get("sound", "device"))
				except:
					logger.error("device in configuration file must be an integer. Set to 0")
					self.Sound_device = 0

				try:
					self.Sound_rate = int(config.get("sound", "rate"))
				except:
					logger.error("rate in configuration file must be an integer. Set to 44100")
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
		
	def CheckIfFlood(self, Results):
		"""
		Keyword Arguments:
		Results -- A CallData instance that contains call information.
	
		This functions runs a script if flood was detected.
		"""

		if self.Flood == True:

			self.On_flood_parameters = self.On_flood_parameters.replace("$From_Extension$", Results.From_Extension)
			self.On_flood_parameters = self.On_flood_parameters.replace("$From_IP$", Results.From_IP)
			self.On_flood_parameters = self.On_flood_parameters.replace("$From_Port$", Results.From_Port)
			self.On_flood_parameters = self.On_flood_parameters.replace("$From_Transport$", Results.From_Transport)
			self.On_flood_parameters = self.On_flood_parameters.replace("$Contact_IP$", Results.Contact_IP)
			self.On_flood_parameters = self.On_flood_parameters.replace("$Contact_Port$", Results.Contact_Port)
			self.On_flood_parameters = self.On_flood_parameters.replace("$Contact_Transport$", Results.Contact_Transport)
			self.On_flood_parameters = self.On_flood_parameters.replace("$Connection_IP$", Results.Connection)
			self.On_flood_parameters = self.On_flood_parameters.replace("$Owner_IP$", Results.Owner)
			
			Command = "bash " + ON_FLOOD_SCRIPT_PATH + " " + self.On_flood_parameters
			logger.info("Executing " + Command + " ...")
			# Execute a script
			try:
				Process = Popen(Command, shell=True, stdout=PIPE)
			except Exception, e:
				logger.error("Cannot execute script. Details: " + str(e))

	def CheckCategory(self, Results):
		"""
		Keyword Arguments:
		Results -- A CallData instance that contains call information.

		This functions runs a script if certain data was found on the call.
		"""
		if IfCategory("SPIT",Results.Classification) == True:
		
			self.On_SPIT_parameters = self.On_SPIT_parameters.replace("$From_Extension$", Results.From_Extension)
			self.On_SPIT_parameters = self.On_SPIT_parameters.replace("$From_IP$", Results.From_IP)
			self.On_SPIT_parameters = self.On_SPIT_parameters.replace("$From_Port$", Results.From_Port)
			self.On_SPIT_parameters = self.On_SPIT_parameters.replace("$From_Transport$", Results.From_Transport)
			self.On_SPIT_parameters = self.On_SPIT_parameters.replace("$Contact_IP$", Results.Contact_IP)
			self.On_SPIT_parameters = self.On_SPIT_parameters.replace("$Contact_Port$", Results.Contact_Port)
			self.On_SPIT_parameters = self.On_SPIT_parameters.replace("$Contact_Transport$", Results.Contact_Transport)
			self.On_SPIT_parameters = self.On_SPIT_parameters.replace("$Connection_IP$", Results.Connection)
			self.On_SPIT_parameters = self.On_SPIT_parameters.replace("$Owner_IP$", Results.Owner)
		
			Command = "bash " + ON_SPIT_SCRIPT_PATH + " " + self.On_SPIT_parameters
			logger.info("Executing " + Command + " ...")
			# Execute a script
			try:
				Process = Popen(Command, shell=True, stdout=PIPE)
			except Exception, e:
				logger.error("Cannot execute script. Details: " + str(e))

	def CheckIfScanning(self, Results):
		"""
		Keyword Arguments:
		Results -- A CallData instance that contains call information.

		This functions runs a script if certain data was found on the call.
		"""
		if IfCategory("Scanning",Results.Classification) == True:
		
			self.On_scanning_parameters = self.On_scanning_parameters.replace("$From_Extension$", Results.From_Extension)
			self.On_scanning_parameters = self.On_scanning_parameters.replace("$From_IP$", Results.From_IP)
			self.On_scanning_parameters = self.On_scanning_parameters.replace("$From_Port$", Results.From_Port)
			self.On_scanning_parameters = self.On_scanning_parameters.replace("$From_Transport$", Results.From_Transport)
			self.On_scanning_parameters = self.On_scanning_parameters.replace("$Contact_IP$", Results.Contact_IP)
			self.On_scanning_parameters = self.On_scanning_parameters.replace("$Contact_Port$", Results.Contact_Port)
			self.On_scanning_parameters = self.On_scanning_parameters.replace("$Contact_Transport$", Results.Contact_Transport)
			self.On_scanning_parameters = self.On_scanning_parameters.replace("$Connection_IP$", Results.Connection)
			self.On_scanning_parameters = self.On_scanning_parameters.replace("$Owner_IP$", Results.Owner)
		
			Command = "bash " + ON_SCANNING_SCRIPT_PATH + " " + self.On_scanning_parameters
			logger.info("Executing " + Command + " ...")
			# Execute a script
			try:
				Process = Popen(Command, shell=True, stdout=PIPE)
			except Exception, e:
				logger.error("Cannot execute script. Details: " + str(e))

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
		email = Email() # Creates an Email object
	
		if email.Enabled == False: 
			logger.info("E-mail notification is disabled.")
		else:
			logger.info("Sending this report by e-mail...")
			email.sendemail(HTMLData)
	
		del email

	def GetFilename(self, Ext):
		"""
		Defines a file name to store the output.
		"""
		Filename = ""
		try:
			a = 0
			while 1:
				Filename = RESULTS_DIR + strftime("%Y-%m-%d") + "_" + str(a) + "." + Ext
						
				if os.path.isfile(Filename) == True:
					a += 1
				else:
					break
		except Exception, e:
			logger.error("Cannot create the results file " + Filename + ". Details: " + str(e))

		return Filename

	def AnalyzeCall(self, SIP_Message_data):	
		"""
		Core of the program. Here is where the honeypot concludes if the packet received is trusted or not.
		"""
		# Wait 5 seconds for an ACK and media events. 
		self.WaitForPackets(5)
	
		# Create an instance of the Classifier
		classifier_instance = Classifier(self.VERSION, self.verbose, self.Local_IP, self.Local_port, self.behaviour_mode, self.GetBehaviourActions(), SIP_Message_data, self.Extensions, self.ACKReceived, self.MediaReceived)

		# Start the classification
		classifier_instance.Start()

		while classifier_instance.Running:
			pass
	
		Results = classifier_instance.CallInformation	

		del classifier_instance

		# Call the correlator
		Correlator(Results, self.Flood)
	
		self.CheckIfFlood(Results)
		
		self.CheckCategory(Results)
		
		self.CheckIfScanning(Results)

		# Save the raw SIP message in the report file
		TXTFilenme = self.GetFilename("txt")
		TXTData = get_results_txt(TXTFilenme, Results, self.VERSION, self.Local_IP, self.Local_port)
		self.SaveResultsToTextFile(TXTData, TXTFilenme)

		# Save the results in a HTML file
		HTMLFilenme = self.GetFilename("html")	
		HTMLData = get_results_html(HTMLFilenme, Results, False, self.VERSION, self.Local_IP, self.Local_port)
		self.SaveResultsToHTML(HTMLData, HTMLFilenme)

		# Send the results by e-mail
		# The function get_results_html is called again and it return an email-adapted format
		HTMLMailData = get_results_html(HTMLFilenme, Results, True, self.VERSION, self.Local_IP, self.Local_port)
		self.SendResultsByEmail(HTMLMailData)
				
		self.ACKReceived = False
		self.MediaReceived = False
		self.Flood = False
	
		self.NumCalls -= 1

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
	
		if self.IsMessage(str, "ACK") == True:
			# Here we check if the ACK received is for the received INVITE.		
			if Search("tag", str) == self.INVITETag:
				self.ACKReceived = True
			return

		if self.IsMessage(str, "OPTIONS") == True:
			self.OPTIONSReceived = True
			self.N_OPTIONS += 1
			return

		if self.IsMessage(str, "INVITE") == False:
			# If False means that the received message was not an INVITE one
			return

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
			self.FLOOD = "yes"
			self.Flood = True
				 
			return

		# Convert function AnalyzeCall in a thread and call it.
		thrAnalyzeCall = threading.Thread(target = self.AnalyzeCall, args = (INVITEMessage,))
	
		self.NumCalls += 1

		thrAnalyzeCall.start()
