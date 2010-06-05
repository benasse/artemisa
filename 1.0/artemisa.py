#!/usr/bin/env python
# -*- coding: UTF-8 -*-

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


VERSION = "1.0.78"

import sys
import os
	
import ConfigParser				# Read configuration files

from time import strftime, sleep, time
import sched
from logs import log				# Import class log from logs.py
from commons import *				# Import functions from commons.py
from classifier import Classifier		# Message classifier 
from correlator import Correlator		# Correlator
from correlator import IfCategory
import threading				# Use of threads

from mail import Email
from htmlresults import get_results_html

from subprocess import Popen, PIPE

try:
	import pjsua as pj
except ImportError:
	print ""
	print "Critical error:"
	print "PJSIP library module MUST be installed!"
	print ""
	print "Download it from:"
	print "http://www.pjsip.org/download.htm"
	print ""
	print "Installation steps:"
	print "http://trac.pjsip.org/repos/wiki/Python_SIP/Build_Install"
	print ""
	print "   In a nutshell:"
	print ""
	print "   1) Check that make, gcc, binutils, Python, and Python-devel are installed."
	print "   2) Build the PJSIP libraries first with \"# ./configure && make dep && make\" commands."
	print "	  Note: if fails try:./configure CFLAGS=-fPIC"
	print "   3) Go to the pjsip-apps/src/python directory."
	print "   4) Run \'# python ./setup.py install\' or just \'# make\'."
	print ""
	sys.exit(1)


# Environment configuration
strLocal_IP = ""				# Local IP
strLocal_port = ""				# Local port
strSIPdomain = ""				# Local SIP domain
strUserAgent = ""				# User-Agent name used by Artemisa 
intMaxCalls = 0					# Max number of calls to handle
intNumCalls = 0					# Number of calls being analysed

# Sound configuration
Sound_enabled = True
Sound_device = 0
Sound_rate = 44100

# Behaviour modes configuration
behaviour_mode = "active"			# Inference analysis behaviour
Active_mode = []
Passive_mode = []
Aggressive_mode = []

On_flood_parameters = ""			# Parameters to send when calling on_flood.sh
On_SPIT_parameters = ""				# Parameters to send when calling on_spit.sh
On_scanning_parameters = ""			# Parameters to send when calling on_scanning.sh

current_call = None

verbose = False					# verbose mode

Servers = []					# SIP REGISTRAR servers
Extensions = []					# Extensions

thrAnalyzeCall = threading.Thread()		# Thread used to analyze the received messages.

Output = PrintClass()
logging = log()

Unregister = False				# Used to know when Artemisa is performing an un-registration

LastINVITEreceived = ""				# Store the last INVITE message received in order to avoid analysing repeated messages

#nSeq = 0					# Number of received messages

# Statistics
intN_INVITE = 0
intN_OPTIONS = 0
strFLOOD = "no"

bOPTIONSReceived = False			# Flag to know if a OPTIONS was received

# TODO: Anti-flood mechanism for OPTIONS flood not yet implemented
#intOPTIONS_Flood_timer0 = 0			# Flag to set a timer to detect OPTIONS flood
#intOPTIONS_Flood_timer1 = 0			# Flag to set a timer to detect OPTIONS flood

strINVITETag = ""				# Tag of the received INVITE
bACKReceived = False				# We must know if an ACK was received
bMediaReceived = False				# Flag to know whether media has been received
bFlood = False					# Flag to know whether flood was detected

class Extension():
	"""
	Keeps the user data which an unique extension.
	"""
	Extension = ""
	Username = ""
	Password = ""
   
class Server():
	"""
	Manage registration information.
	"""
	
	Name = ""
	Registrar_IP = ""			# Registrar server IP (Asterisk, SER, etc.)
	Registrar_port = ""			# Registrar server port
	Registrar_time = 10			# Time in minutes between REGISTRAR messeges sent to the server.
	RegSchedule = ""			# Time between registrations
	NAT_ka_inverval = 0			# Time between NAT keep alive messages
	behaviour_mode = ""			# Artemisa behaviour mode

	Extensions = []				# Store the extensions registered to the SIP server

	acc = None
	acc_cfg = None
	acc_cb = None
	
	def __init__(self):
		self.Extensions = []
		self.acc = None
		self.acc_cfg = None
		self.acc_cb = None
		
	def Register(self):
		"""
		This function registers the honeypot at the SIP server, and keep it alive sending REGISTRAR
		messages within the time specified in the configuration file.
		"""
		global lib

		if len(self.Extensions) == 0:
			Output.Print("WARNING There are no extensions configured to be used with server " + self.Name)
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
			self.acc = lib.create_account(self.acc_cfg)
	
			self.acc_cb = MyAccountCallback(self.acc)
			self.acc.set_callback(self.acc_cb)
	
			Output.Print("NOTICE Extension " + str(self.Extensions[i].Extension) + " registration sent. Status: " + str(self.acc.info().reg_status) + " (" + str(self.acc.info().reg_reason) + ")")


	def Reregister(self):
		self.acc.set_registration(True)

	#def Unregister(self):
	#	self.acc.delete()
	#	self.acc = None

def log_cb(level, str, len):
	"""
	This function saves the data returned by PJSUA module. This shows also the SIP packet, so it's possible
	to analyse it directly from here, and there is no need to use some capturing packet function.
	This function is very important.
	"""
	global thrAnalyzeCall
	global LastINVITEreceived
	global intNumCalls
	global intMaxCalls
	global intN_INVITE
	global intN_OPTIONS
	global strFLOOD
	global bACKReceived
	global bOPTIONSReceived 
	global strINVITETag
	global bFlood
	
	strTemp = str.strip().splitlines(True)
	
	logging.PJSUA_Log(str)
	
	bFound = False
	bAckFound = False
	
	for line in strTemp:
		if line.find("INVITE") != -1 and line.find("SIP/2.0") != -1:
			bFound = True
			break
		elif line.find("ACK") != -1 and line.find("SIP/2.0") != -1:
			bAckFound = True
			break
		elif line.find("OPTIONS") != -1 and line.find("SIP/2.0") != -1:
			bOPTIONSReceived = True
			break

	if bOPTIONSReceived == True:
		intN_OPTIONS += 1

	# Here we check if the ACK received is for the received INVITE.		
	if bAckFound == True:
		for line in strTemp:
			line = line.strip()
			if line.find("tag=") != -1:
				if strINVITETag == line.split("tag=")[1]:
					bACKReceived = True
					break
	return
			
	if bFound == False: return # If False means that the received message was not an INVITE one

	intN_INVITE += 1

	strINVITEMessage = ""
			
	i = -1
	for line in strTemp:
		line = line.strip()
		i += 1
		if i > 0 and line.find("--end msg--") == -1:
			if strINVITEMessage != "":
				strINVITEMessage = strINVITEMessage + "\n" + line
			else:
				strINVITEMessage = line
				
	for line in strTemp:
		line = line.strip()				
		if line.find("tag=") != -1:
			strINVITETag = line.split("tag=")[1] # Store the tag of the INVITE to be used later to identify the ACK
			break
	
	if LastINVITEreceived == strINVITEMessage:
		#Output.Print("Duplicated INVITE arrived. Seq: " + str(nSeq))
		Output.Print("Duplicated INVITE detected.")
		return # Don't analyze repeated messages
			
	#Output.Print("INVITE message detected and logged. Seq: " + str(nSeq))
	Output.Print("INVITE message detected and logged.")
			
	logging.InviteLog(strINVITEMessage)

	LastINVITEreceived = strINVITEMessage

	if intNumCalls == intMaxCalls:
		Output.Print("The maximum number of calls to analyze simultaneously has been reached.")
		strFLOOD = "yes"
		bFlood = True
			 
		return

	# Convert function AnalyzeCall in a thread and call it.
	thrAnalyzeCall = threading.Thread(target = AnalyzeCall, args = (strINVITEMessage,))
	
	intNumCalls += 1
	
	thrAnalyzeCall.start()

class MyAccountCallback(pj.AccountCallback):
	"""
	Callback to receive events from account.
	"""
	global Unregister

	def __init__(self, account=None):
		pj.AccountCallback.__init__(self, account)

	def on_reg_state(self):
		if Unregister == False:
			if self.account.info().reg_status >= 200 and self.account.info().reg_status < 300:
				Output.Print("NOTICE Extension " + str(self.account.info().uri) + " registered, status=" + str(self.account.info().reg_status) + " (" + str(self.account.info().reg_reason) + ")")	
			elif (self.account.info().reg_status >= 400 and self.account.info().reg_status < 500) or self.account.info().reg_status > 700:
				Output.Print("NOTICE Extension " + str(self.account.info().uri) + " registration failed, status=" + str(self.account.info().reg_status) + " (" + str(self.account.info().reg_reason) + ")")
				# This part is important since it's necessary to try the registration again if it fails.
				Output.Print("NOTICE Trying to register again.")
				self.account.set_registration(True)
			else:
				Output.Print("NOTICE Extension " + str(self.account.info().uri) + " registration status=" + str(self.account.info().reg_status) + " (" + str(self.account.info().reg_reason) + ")")
		else:
			# It's necessary to use a flag variable to know whether a registration or unregistration
			# process is taking place, because both SIP messages are REGISTER but with different 
			# "expire" time. So, there is no other way to determine if it's a registration or an unregistration.  
			if self.account.info().reg_status >= 200 and self.account.info().reg_status < 300:
				Output.Print("NOTICE Extension " + str(self.account.info().uri) + " unregistered, status=" + str(self.account.info().reg_status) + " (" + str(self.account.info().reg_reason) + ")")	
			elif (self.account.info().reg_status >= 400 and self.account.info().reg_status < 500) or self.account.info().reg_status > 700:
				Output.Print("NOTICE Extension " + str(self.account.info().uri) + " unregistration failed, status=" + str(self.account.info().reg_status) + " (" + str(self.account.info().reg_reason) + ")")
			# No problem if the unregistration process fails.
			else:
				Output.Print("NOTICE Extension " + str(self.account.info().uri) + " unregistration status=" + str(self.account.info().reg_status) + " (" + str(self.account.info().reg_reason) + ")")
						   
	# Notification on incoming call
	def on_incoming_call(self, call):

		global current_call
		global lib
	   
		global behaviour_mode
		global Active_mode
		global Passive_mode
		global Aggressive_mode
		
		Output.Print("NOTICE Incoming call from " + str(call.info().remote_uri))

		current_call = call

		call_cb = MyCallCallback(current_call)
		current_call.set_callback(call_cb)

		if behaviour_mode == "active":
			for item in Active_mode:
				if item == "send_180":
					current_call.answer(180)
				if item == "send_200":
					current_call.answer(200)

		elif behaviour_mode == "passive":
			for item in Passive_mode:
				if item == "send_180":
					current_call.answer(180)
				if item == "send_200":
					current_call.answer(200)

		elif behaviour_mode == "aggressive":
			for item in Passive_mode:
				if item == "send_180":
					current_call.answer(180)
				if item == "send_200":
					  current_call.answer(200)
							
		#current_call.hangup()

class MyCallCallback(pj.CallCallback):
	"""
	Callback to receive events from Call
	"""
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
			
			if Sound_enabled == True:
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
		global Sound_enabled
		global bMediaReceived
		
		if Sound_enabled == False: return
		
		if self.call.info().media_state == pj.MediaState.ACTIVE: 
			try:
				# Connect the call to the recorder 
				call_slot = self.call.info().conf_slot 
				
				if self.rec_id < 0: 
					
					a = 0
					while 1:
						
						strFilename = "./recorded_calls/" + strftime("%Y-%m-%d") + "_call_from_" + str(self.call.info().remote_uri).split("@")[0].split(":")[1] + "_" + str(a) + ".wav"
						
						if os.path.isfile(strFilename) == True:
							a += 1
						else:
							break
					
					self.rec_id = lib.create_recorder(strFilename)
					self.rec_slot = lib.recorder_get_slot(self.rec_id)
				
					# Connect the call with the WAV recorder
					lib.conf_connect(call_slot, self.rec_slot)
					
					Output.Print("Audio is now being recorded on file: " + strFilename)
					
					bMediaReceived = True
				
			except Exception, e:
				Output.Print("WARNING Error while trying to record the call. Error: " + str(e))
  

		else:

			try:
				call_slot = self.call.info().conf_slot
				
				# Disconnect the call with the WAV recorder
				pj.Lib.instance().conf_disconnect(call_slot, lib.recorder_get_slot(self.rec_id))

			except Exception, e:
				Output.Print("WARNING Error: " + str(e))
			
			Output.Print("NOTICE Audio is inactive. Check the configuration file.") 
			
def LoadExtensions():
	"""
	Load configurations from file extensions.conf
	"""
	global Extensions

	config = ConfigParser.ConfigParser()
	strTemp = config.read("./conf/extensions.conf")
	
	if strTemp == []:
		Output.Print("CRITICAL The configuration file extensions.conf cannot be read.")
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
			Output.Print("CRITICAL The configuration file extensions.conf cannot be correctly read. Check it out carefully.")
			sys.exit(1)

	del config
	
def LoadServers(): 
	"""
	Load configurations from file servers.conf
	"""
	global Servers
	global Extentions
	
	config = ConfigParser.ConfigParser()
	strTemp = config.read("./conf/servers.conf")
	
	if strTemp == []:
		Output.Print("CRITICAL The configuration file servers.conf cannot be read.")
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


				strTemp2 = config.get(item, "exten")
				strTemp2 = strTemp2.split(",")

				for x in range(len(strTemp2)):
					for j in range(len(Extensions)):
						if strTemp2[x] == Extensions[j].Extension:
							Servers[i].Extensions.append(Extension())
							Servers[i].Extensions[len(Servers[i].Extensions)-1] = Extensions[j]
							break
			
		except :
			Output.Print("CRITICAL The configuration file servers.conf cannot be correctly read. Check it out carefully.")
			sys.exit(1)

	del config
	
def LoadConfiguration():
	"""
	Load configurations from file artemisa.conf
	"""
	global strLocal_IP
	global strLocal_port
	global strSIPdomain
	global strUserAgent
	global intMaxCalls
	global behaviour_mode

	global Sound_enabled
	global Sound_device
	global Sound_rate
	
	global Active_mode
	global Passive_mode
	global Aggressive_mode

	global On_flood_parameters
	global On_SPIT_parameters
	global On_scanning_parameters
	
	config = ConfigParser.ConfigParser()
	strTemp = config.read("./conf/artemisa.conf")
	
	if strTemp == []:
		Output.Print("CRITICAL The configuration file artemisa.conf cannot be read.")
		sys.exit(1)
	else:
		
		try:	
   
			# Gets the parameters of the behaviour modes
			Active_mode = GetConfigSection("./conf/behaviour.conf", "active")
			Passive_mode = GetConfigSection("./conf/behaviour.conf", "passive")
			Aggressive_mode = GetConfigSection("./conf/behaviour.conf", "aggressive")
			Investigate_sec = GetConfigSection("./conf/behaviour.conf", "investigate") 
				
			# Now checks if the items read are known
			for item in Active_mode:
			#	if (item != "send_180") and (item != "send_200") and (item != "inference") and (item != "investigate") and (item != "validdns") and (item != "fingerprint") and (item != "historical") and (item != "whois") and (item != "gl") and (item != "reliability") and (item != "to") and (item != "dispersion"):
				if (item != "send_180") and (item != "send_200"):
					Active_mode.remove(item)
			#			
			#	elif item == "investigate":
			#		Active_mode = Active_mode + Investigate_sec
			#
			for item in Passive_mode:
			#	if (item != "send_180") and (item != "send_200") and (item != "inference") and (item != "investigate") and (item != "validdns") and (item != "fingerprint") and (item != "historical") and (item != "whois") and (item != "gl") and (item != "reliability") and (item != "to") and (item != "dispersion"):
				if (item != "send_180") and (item != "send_200"):
					Passive_mode.remove(item)
			#			
			#	elif item == "investigate":
			#		Passive_mode = Passive_mode + Investigate_sec					 
			#
			for item in Aggressive_mode:
			#	if (item != "send_180") and (item != "send_200") and (item != "inference") and (item != "investigate") and (item != "validdns") and (item != "fingerprint") and (item != "historical") and (item != "whois") and (item != "gl") and (item != "reliability") and (item != "to") and (item != "dispersion"):
				if (item != "send_180") and (item != "send_200"):
					Aggressive_mode.remove(item)
			#			
			#	elif item == "investigate":
			#		Aggressive_mode = Aggressive_mode + Investigate_sec   
					
			strLocal_IP = config.get("environment", "local_ip")
			strLocal_port = config.get("environment", "local_port")
			strSIPdomain = config.get("environment", "sip_domain")
			strUserAgent = config.get("environment", "user_agent")
			behaviour_mode = config.get("environment", "behaviour_mode")
			intMaxCalls  = int(config.get("environment", "max_calls"))
			
			Sound_enabled = config.get("sound", "enabled")
			Sound_device = int(config.get("sound", "device"))
			Sound_rate = int(config.get("sound", "rate"))			
			
			if behaviour_mode != "active" and behaviour_mode != "passive" and behaviour_mode != "aggressive":
				behaviour_mode = "passive"
				Output.Print("WARNING behaviour_mode value is invalid. Changed to passive.")
					
		except:
			Output.Print("CRITICAL The configuration file artemisa.conf cannot be correctly read. Check it out carefully.")
			sys.exit(1)

	del config
		
	# Now ir reads the actions.conf file to load the user-defined parameters to sent when calling the scripts
	config = ConfigParser.ConfigParser()
	strTemp = config.read("./conf/actions.conf")
	
	if strTemp == []:
		Output.Print("CRITICAL The configuration file actions.conf cannot be read.")
		sys.exit(1)
	else:
		try:
			# Gets the parameters for the on_flood.sh
			On_flood_parameters = config.get("actions", "on_flood")
			On_SPIT_parameters = config.get("actions", "on_spit")
			On_scanning_parameters = config.get("actions", "on_scanning")
			
		except:
			Output.Print("CRITICAL The configuration file actions.conf cannot be correctly read. Check it out carefully.")
			sys.exit(1)

	del config			

def WaitForPackets(seconds):
	"""
	Keyword Arguments:
	seconds -- number of seconds to wait

	This function stops the program some seconds in order to let the system collect more traces
	"""
	for i in range(seconds):
		Output.Print("Waiting for SIP dialogs (" + str(seconds-i) + ")...")
		sleep(1)
		
def GetBehaviourActions(behaviour_mode):
	"""
	Keyword Arguments:
	behaviour_mode
	
	This function returns the actions of the given behaviour mode
	"""
	global Active_mode
	global Passive_mode
	global Aggressive_mode
	
	if behaviour_mode == "active":
		return Active_mode
	elif behaviour_mode == "passive":
		return Passive_mode
	elif behaviour_mode == "aggressive":
		return Aggressive_mode
		
def AnalyzeCall(strData):	
	"""
	Core of the program. Here is where the honeypot concludes if the packet received is trusted or not.
	"""
	global verbose
	global Extensions
	global behaviour_mode

	global strLocal_IP
	global strLocal_port
	global VERSION
	global intNumCalls
	global bACKReceived
	global bMediaReceived
	global bFlood
	
	global On_flood_parameters
	global On_SPIT_parameters
	global On_scanning_parameters
	
	# Wait 5 seconds for an ACK and media events. 
	WaitForPackets(5)
	
	# Create an instance of the Classifier
	classifier_instance = Classifier(VERSION, verbose, strLocal_IP, strLocal_port, behaviour_mode, GetBehaviourActions(behaviour_mode), strData, Extensions, bACKReceived, bMediaReceived)

	# Start the classification
	classifier_instance.Start()

	while classifier_instance.Running:
		pass
	
	
	Output.Print("+ The message is classified as:",True,classifier_instance.Results_file)
	for i in range(len(classifier_instance.Classification)):
		Output.Print("| " + classifier_instance.Classification[i],True,classifier_instance.Results_file)
	
	Output.Print("",True,classifier_instance.Results_file)
	
	
	# Call the correlator
	Correlator(classifier_instance.Classification, bFlood, classifier_instance.Results_file, classifier_instance.ToolName)
	
	# Save the raw SIP message in the report file
	Output.Print("************************************** SIP message ***************************************",False,classifier_instance.Results_file)
	Output.Print("",False,classifier_instance.Results_file)
	Output.Print(classifier_instance.SIP_Message,False,classifier_instance.Results_file)
	
	Output.Print("NOTICE This report has been saved on file " + classifier_instance.Results_file + ".txt")

	# Save the results in a HTML file
	File = open(classifier_instance.Results_file + ".html", "w")
		
	File.write(get_results_html(classifier_instance.Results_file, False, classifier_instance.SIP_Message, classifier_instance.CallInformation.From_Extension, classifier_instance.CallInformation.From_IP, classifier_instance.CallInformation.To_Extension, classifier_instance.CallInformation.To_IP, classifier_instance.CallInformation.Contact_Extension, classifier_instance.CallInformation.Contact_IP, classifier_instance.CallInformation.Connection, classifier_instance.CallInformation.Owner, classifier_instance.CallInformation.Via, classifier_instance.CallInformation.UserAgent, VERSION, strLocal_IP, strLocal_port))
			
	File.close()
	
	Output.Print("NOTICE This report has been saved on file " + classifier_instance.Results_file + ".html")


	# If a flooding has been detected then run the script
	if bFlood == True:
		
		On_flood_parameters = On_flood_parameters.replace("$From_IP$", classifier_instance.CallInformation.From_IP)
		On_flood_parameters = On_flood_parameters.replace("$From_Port$", classifier_instance.CallInformation.From_Port)
		On_flood_parameters = On_flood_parameters.replace("$From_Transport$", classifier_instance.CallInformation.From_Transport)
		On_flood_parameters = On_flood_parameters.replace("$Contact_IP$", classifier_instance.CallInformation.Contact_IP)
		On_flood_parameters = On_flood_parameters.replace("$Contact_Port$", classifier_instance.CallInformation.Contact_Port)
		On_flood_parameters = On_flood_parameters.replace("$Contact_Transport$", classifier_instance.CallInformation.Contact_Transport)
		On_flood_parameters = On_flood_parameters.replace("$Connection_IP$", classifier_instance.CallInformation.Connection)
		On_flood_parameters = On_flood_parameters.replace("$Owner_IP$", classifier_instance.CallInformation.Owner)
		
		strCommand = "bash ./scripts/on_flood.sh " + On_flood_parameters
		Output.Print("Executing " + strCommand + " ...")
		# Execute a script
		Process = Popen(strCommand, shell=True, stdout=PIPE)
		
	# If SPIT has been detected then run the script
	if IfCategory("SPIT",classifier_instance.Classification) == True:
		
		On_SPIT_parameters = On_SPIT_parameters.replace("$From_IP$", classifier_instance.CallInformation.From_IP)
		On_SPIT_parameters = On_SPIT_parameters.replace("$From_Port$", classifier_instance.CallInformation.From_Port)
		On_SPIT_parameters = On_SPIT_parameters.replace("$From_Transport$", classifier_instance.CallInformation.From_Transport)
		On_SPIT_parameters = On_SPIT_parameters.replace("$Contact_IP$", classifier_instance.CallInformation.Contact_IP)
		On_SPIT_parameters = On_SPIT_parameters.replace("$Contact_Port$", classifier_instance.CCallInformation.ontact_Port)
		On_SPIT_parameters = On_SPIT_parameters.replace("$Contact_Transport$", classifier_instance.CallInformation.Contact_Transport)
		On_SPIT_parameters = On_SPIT_parameters.replace("$Connection_IP$", classifier_instance.CallInformation.Connection)
		On_SPIT_parameters = On_SPIT_parameters.replace("$Owner_IP$", classifier_instance.CallInformation.Owner)
		
		strCommand = "bash ./scripts/on_spit.sh " + On_SPIT_parameters
		Output.Print("Executing " + strCommand + " ...")
		# Execute a script
		Process = Popen(strCommand, shell=True, stdout=PIPE)
		
	# If a scanning has been detected then run the script
	if IfCategory("Scanning",classifier_instance.Classification) == True:
		
		On_scanning_parameters = On_scanning_parameters.replace("$From_IP$", classifier_instance.CallInformation.From_IP)
		On_scanning_parameters = On_scanning_parameters.replace("$From_Port$", classifier_instance.CallInformation.From_Port)
		On_scanning_parameters = On_scanning_parameters.replace("$From_Transport$", classifier_instance.CallInformation.From_Transport)
		On_scanning_parameters = On_scanning_parameters.replace("$Contact_IP$", classifier_instance.CallInformation.Contact_IP)
		On_scanning_parameters = On_scanning_parameters.replace("$Contact_Port$", classifier_instance.CallInformation.Contact_Port)
		On_scanning_parameters = On_scanning_parameters.replace("$Contact_Transport$", classifier_instance.CallInformation.Contact_Transport)
		On_scanning_parameters = On_scanning_parameters.replace("$Connection_IP$", classifier_instance.CallInformation.Connection)
		On_scanning_parameters = On_scanning_parameters.replace("$Owner_IP$", classifier_instance.CallInformation.Owner)
		
		strCommand = "bash ./scripts/on_scanning.sh " + On_scanning_parameters
		Output.Print("Executing " + strCommand + " ...")
		# Execute a script
		Process = Popen(strCommand, shell=True, stdout=PIPE)
				
	# Send the results by e-mail
	email = Email() # Creates an Email object

	if email.Enabled == False: 
		Output.Print("NOTICE E-mail notification is disabled.")
	else:
	
		strData = get_results_html(classifier_instance.Results_file, True, classifier_instance.SIP_Message, classifier_instance.CallInformation.From_Extension, classifier_instance.CallInformation.From_IP, classifier_instance.CallInformation.To_Extension, classifier_instance.CallInformation.To_IP, classifier_instance.CallInformation.Contact_Extension, classifier_instance.CallInformation.Contact_IP, classifier_instance.CallInformation.Connection, classifier_instance.CallInformation.Owner, classifier_instance.CallInformation.Via, classifier_instance.CallInformation.UserAgent, VERSION, strLocal_IP, strLocal_port)
					
		Output.Print("NOTICE Sending this report by e-mail...")
		Output.Print(email.sendemail(strData))
	
		del email

	
	# End of the analysis
	
	del classifier_instance
	
	bACKReceived = False
	bMediaReceived = False
	bFlood = False
	
	intNumCalls -= 1

def EndConnection():
	"""
	Finalizes PJSUA.
	"""
	global lib
	global Servers
	global Unregister
	global current_call

	Unregister = True	

	del current_call

	lib.destroy()
	lib = None
	
def ShowHelp(bCommands = True):
	"""
	Keyword Arguments:
	bCommands -- when True the commands list is shown. 
	
	Shows the help
	"""
	print "Usage: artemisa [Options]"
	print "  -v, --verbose			 Verbose mode (it shows more information)."
	print "  -g, --get_sound_devices   Show the available sound devices."
	
	if bCommands == False: return
	
	print ""	
	print "Commands list:"
	print ""
	print "mode active			  Change behaviour mode to active."
	print "mode passive			 Change behaviour mode to passive."
	print "mode aggressive		  Change behaviour mode to aggressive."
	print ""
	print "verbose on			   Turn verbose mode on (it shows more information)."
	print "verbose off			  Turn verbose mode off."
	print ""
	print "show statistics, stats   Show the statistics of the current instance."
	print ""
	#print "clean historical		 Remove the historical database."
	print "clean logs			   Remove all log files."
	print "clean results			Remove all results files."
	print "clean alarms			 Remove all alarm files."
	print "clean calls			  Remove all the recorded calls."
	print "clean all				Remove all files."
	print "						 (Use these commands carefully)"
	print ""
	print "hangup all			   Hang up all calls."
	print ""
	print "show warranty			Show the program warrany."
	print "show license			 Show the program license."
	print ""
	print "s, q, quit, exit		 Exit"
 
def ReadKeyboard(): 
	"""
	This function handles the keyboard process
	"""
	# Stats' variables
	global intN_INVITE
	global intN_OPTIONS
	global strFLOOD
	
	global verbose
	global behaviour_mode

	if os.getenv('HOSTNAME') == None:
		# Well... some distributions don't export the environmental variable HOSTNAME...
		strCLIprompt = str(os.getenv('USER')) + "> "
	else:
		strCLIprompt = str(os.getenv('HOSTNAME')) + "> "
	
	while True:
		
		s = raw_input(strCLIprompt).strip()
		
		if s == "help":
			ShowHelp()
		
		elif s == "show statistics" or s == "stats":
			print "Artemisa's instance statistics"
			print "-------------------------------------------------------------------"
			print ""
			print "INVITE messages received: " + str(intN_INVITE)
			print "OPTIONS messages received: " + str(intN_OPTIONS)
			print "Flood detected?: " + strFLOOD
			print ""
				
		elif s == "hangup all":
			lib.hangup_all()
			print "Ok"
			
		#elif s == "clean historical":
		#	Process = Popen("rm -f ./historical/*", shell=True, stdout=PIPE)
		#	Process.wait()
		#	print "Cleaned"
			
		elif s == "clean logs":
			Process = Popen("rm -f ./logs/*.log", shell=True, stdout=PIPE)
			Process.wait()
			Process = Popen("rm -f ./logs/invite_msgs/*.log", shell=True, stdout=PIPE)
			Process.wait()
			print "Cleaned"
			
		elif s == "clean results":
			Process = Popen("rm -f ./results/*", shell=True, stdout=PIPE)
			Process.wait()
			print "Cleaned"
			
		elif s == "clean alarms":
			Process = Popen("rm -f ./alarms/*", shell=True, stdout=PIPE)
			Process.wait()
			print "Cleaned"
			
		elif s == "clean calls":
			Process = Popen("rm -f ./recorded_calls/*", shell=True, stdout=PIPE)
			Process.wait()
			print "Cleaned"
						
		elif s == "clean all":
			#Process = Popen("rm -f ./historical/*", shell=True, stdout=PIPE)
			#Process.wait()
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
			print "Cleaned"
						   
		elif s == "mode active":
			behaviour_mode = "active"
			print "Behaviour mode changed to active." 

		elif s == "mode passive":
			behaviour_mode = "passive"
			print "Behaviour mode changed to passive."
			
		elif s == "mode aggressive":
			behaviour_mode = "aggressive"
			print "Behaviour mode changed to aggressive."
						
		elif s.find("verbose") != -1 and s.find("on") != -1:
			verbose = True
			print "Verbose mode on."
			
		elif s.find("verbose") != -1 and s.find("off") != -1:
			verbose = False
			print "Verbose mode off."
						
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
			
def main():
	"""
	Here starts Artemisa
	"""
	
	global verbose
	global lib
	global strLocal_IP
	global strLocal_port
	global strUserAgent
	global intMaxCalls
	global behaviour_mode
	global Unregister
	
	global Servers
	
	global Sound_enabled
	global Sound_device
	global Sound_rate
	
	Show_sound_devices = False
	
	# Check if some arguments has been passed
	if len(sys.argv) > 1:
		for i in range(1, len(sys.argv)):
			if sys.argv[i] == "-h" or sys.argv[i] == "--help":
				ShowHelp(False)
				sys.exit(0)
			elif sys.argv[i] == "-v" or sys.argv[i] == "--verbose":
				verbose = True
			elif sys.argv[i] == "-g" or sys.argv[i] == "--get_sound_devices":
				Show_sound_devices = True
			else:
				print "Invalid argument: " + sys.argv[i]
					
	print "Artemisa v" + VERSION + " Copyright (C) 2009-2010 Mohamed Nassar, Rodrigo do Carmo, and Pablo Masri"
	print ""
	print "This program comes with ABSOLUTELY NO WARRANTY; for details type 'show warranty'."
	print "This is free software, and you are welcome to redistribute it under certain"
	print "conditions; type 'show license' for details."
	print ""
	print ""
	print "Type 'help' for help."
	print ""
		
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
			
	media_cfg = pj.MediaConfig()
	media_cfg.clock_rate = Sound_rate
	media_cfg.no_vad = True
			
	log_cfg = pj.LogConfig()
	log_cfg.level = 5
	log_cfg.callback = log_cb
	log_cfg.console_level = 5 # The value console_level MUST be 5 since it's used to analyze the messages
			
	lib.init(ua_cfg, log_cfg, media_cfg)
	
	try:
		lib.create_transport(pj.TransportType.UDP, pj.TransportConfig(int(strLocal_port)))
	except:
		print ""
		print "Critical error:"
		print "Port " + strLocal_port + " is already in use by another process. Please close that process or change the port number in the configuration file."
		print ""
		lib.destroy()
		lib = None
		sys.exit(1)
	
			
	lib.start()
	
	if Show_sound_devices == True:
		a = 0
		print ""
		print ""
		print "List of available sound devices:"
		print ""
		if len(lib.enum_snd_dev()) == 0:
			print "No sound device detected."
		else:
			for item in lib.enum_snd_dev():
				print "Index=" + str(a) + " Name=" + item.name
				a += 1

		print ""
		print ""
		
		EndConnection()
		sys.exit(0)

	
	Output.Print("-------------------------------------------------------------------------------------------------", False)
	Output.Print("Artemisa started.", False)
			
	if Sound_enabled == True:
		# Configure the audio device 
		try:
			if len(lib.enum_snd_dev()) > 0:
				lib.set_snd_dev(Sound_device,Sound_device)
			else:
				Output.Print("WARNING Audio device not found. Calls will not be recorded.")
				Sound_enabled = False
		except:
			Output.Print("WARNING Audio device not found. Calls will not be recorded.")
			Sound_enabled = False

				
	Unregister = False

	Output.Print("User Agent listening on: " + strLocal_IP + ":" + strLocal_port)
	
	Output.Print("Behaviour mode: " + behaviour_mode)

	if len(Servers) == 0:
		Output.Print("No extensions have been configured.")
	else:
		Output.Print("Starting extensions registration process...")
		
		# Register each account
		for i in range(len(Servers)):
			Servers[i].Register()
   
	# The keyboard is read:
	ReadKeyboard()

	EndConnection()
	
	print ""
	print "Good bye!"
	print ""
	
	Output.Print("Artemisa ended.", False)
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
		sys.exit(0)
	
	
