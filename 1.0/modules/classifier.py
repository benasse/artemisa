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


import os
from time import strftime

from commons import PrintClass, GetSIPHeader, Search, GetTimeClass, GetIPfromSIP, GetPortfromSIP, GetExtensionfromSIP, GetTransportfromSIP, RemoveComments, ResolveDNS, CallData

from mail import Email
from logs import log				# Import class log from logs.py

from check_fingerprint import CheckFingerprint
from check_dns import CheckDNS
from check_port import CheckPort

class Classifier(PrintClass, log):
	"""
	This class performs the classification of the received SIP message.
	"""
	
	def __init__(self, VERSION, verbose, strLocal_IP, strLocal_port, behaviour_mode, behaviour_actions, strData, Extensions, bACKReceived, bMediaReceived):
		self.VERSION = VERSION # Artemisa's version
		self.strLocal_IP = strLocal_IP
		self.strLocal_port = strLocal_port
		self.verbose = verbose # Flag to know whether the verbose mode is set or not
		self.Extensions = Extensions # Extensions registered by Artemisa
		self.bACKReceived = bACKReceived
		self.bMediaReceived = bMediaReceived
		self.Behaviour = behaviour_mode
		self.Behaviour_actions = behaviour_actions
		self.bRequestURI = False
		self.Running = True # State of the analysis
		self.CallInformation = CallData() # Creates an instance of CallData
		self.CallInformation.SIP_Message = strData # Stores the SIP message to classify (usually the INVITE)
		self.PrintFile = ""

	def GetFilename(self):
		"""
		Defines a file name to store the output. The idea is to make a temporary file to store all the
		output of the screen and then use it to build the HTML report as well as the plain text report.
		"""

		strFilename = ""
		try:
			a = 0
			while 1:
						
				strFilename = "./results/" + strftime("temp_%Y-%m-%d") + "_" + str(a)
						
				if os.path.isfile(strFilename) == True:
					a += 1
				else:
					break
		except:
			raise Exception("Can't create the temporary file " + strFilename)

		return strFilename

	def Tests_CheckFingerprint(self):
		"""
		This method carries out the fingerprint test
		"""
		self.Print("+ Checking fingerprint...",True)
		self.Print("|",True)
		self.Print("| " + self.CallInformation.UserAgent,True)
		
		self.ToolName = CheckFingerprint(self.CallInformation.UserAgent)
		if self.ToolName < 0:
			self.Print("|",True)
			self.Print("| Fingerprint check failed.",True)
		elif self.ToolName == 0:
			self.Print("|",True)
			self.Print("| No fingerprint found.",True)
		else:
			self.Print("|",True)
			self.Print("| Fingerprint found. The following attack tool was employed: " + self.ToolName,True)
			self.Print("|",True)			
			self.Print("| Category: Attack tool",True)
			self.AddCategory("Attack tool")
		
		self.Print("",True)
		
	def Tests_CheckDNS(self):
		"""
		This method carries out the DNS test
		"""
		self.Print("+ Checking DNS...",True)
		
		ip_to_analyze = [] # IPs that will be analyzed
				
		ip_to_analyze.append(self.CallInformation.From_IP)
		if ip_to_analyze.count(self.CallInformation.Contact_IP) == 0: ip_to_analyze.append(self.CallInformation.Contact_IP) # This is to avoid having repeated IPs
		if ip_to_analyze.count(self.CallInformation.Connection) == 0: ip_to_analyze.append(self.CallInformation.Connection)
		if ip_to_analyze.count(self.CallInformation.Owner) == 0: ip_to_analyze.append(self.CallInformation.Owner)
		
		for i in range(len(self.CallInformation.Via)):
				if ip_to_analyze.count(self.CallInformation.Via[i][0]) == 0: ip_to_analyze.append(self.CallInformation.Via[i][0])
	   
		# Analyze each IP address 
		for i in range(len(ip_to_analyze)):
			self.Print("|",True)
			self.Print("| + Checking " + ip_to_analyze[i] + "...",True)
			self.Print("| |",True)   
			DNS_Result = CheckDNS(ip_to_analyze[i], self.verbose)
			if DNS_Result <= 0:
				self.Print("| | IP cannot be resolved.",True)
				self.Print("| |",True)
				self.Print("| | Category: Spoofed message",True)
				self.AddCategory("Spoofed message")
			else:
				if (DNS_Result.find("WHOIS data not found") != -1 or DNS_Result.find("none") != -1) and DNS_Result.find("not DNS") == -1:
					DNS_Result = DNS_Result.splitlines()
					for line in DNS_Result:
						self.Print("| | " + line,True) 
					self.Print("| |",True)
					self.Print("| | Category: Spoofed message",True)
					self.AddCategory("Spoofed message")
				elif DNS_Result.find("not DNS") != -1:
					self.Print("| | This is already an IP address. Nothing done.",True)
				else:
					DNS_Result = DNS_Result.splitlines()
					for line in DNS_Result:
						self.Print("| | " + line,True) 
					self.Print("| |",True)
					self.Print("| | Category: Interactive attack",True)
					self.AddCategory("Interactive attack")
	
		self.Print("",True)
		
	def Tests_CheckSIPPorts(self):
		"""
		This method carries out the SIP ports test
		"""
		self.Print("+ Checking if SIP port is opened...",True)

		self.Print("|",True)
		self.Print("| + Checking " + self.CallInformation.Contact_IP + ":" + self.CallInformation.Contact_Port + "/" + self.CallInformation.Contact_Transport + "...",True)
		self.Print("| |",True)   
			
		strResult = CheckPort(self.CallInformation.Contact_IP, self.CallInformation.Contact_Port, self.CallInformation.Contact_Transport, self.verbose)
			
		if strResult == 0 or strResult < 0:
			self.Print("| | Error while scanning the port.",True)
			self.Print("| |",True)
			self.Print("| | Category: -",True)
		else:
			if strResult.find("closed") != -1:
				strResult = strResult.splitlines()
				for line in strResult:
					self.Print("| | " + line,True)  
				#self.Print("| | Result: Port closed",True) 
				self.Print("| |",True)
				self.Print("| | Category: Spoofed message",True)
				self.AddCategory("Spoofed message")
			else:
				strResult = strResult.splitlines()
				for line in strResult:
					self.Print("| | " + line,True)
				#self.Print("| | Result: Port opened",True) 
				self.Print("| |",True)
				self.Print("| | Category: Interactive attack",True)
				self.AddCategory("Interactive attack")
				
		self.Print("",True)
		
	def Tests_CheckMediaPorts(self):
		"""
		This method carries out the media ports test
		"""
		self.Print("+ Checking if media port is opened...",True)

		# FIXME: this parsing could be improved
		strRTPPort = GetSIPHeader("m=audio", self.CallInformation.SIP_Message)
		
		if strRTPPort == "": # Could happen that no RTP was delivered
			self.Print("|",True) 
			self.Print("| No RTP info delivered.",True)
			self.Print("|",True)
			self.Print("| Category: Spoofed message",True)
			self.AddCategory("Spoofed message")
		else:
			strRTPPort = strRTPPort.split(" ")[1]

			self.Print("|",True)
			self.Print("| + Checking " + self.CallInformation.Contact_IP + ":" + strRTPPort + "/" + "udp" + "...",True)
			self.Print("| |",True)   
				
			strResult = CheckPort(self.CallInformation.Contact_IP, strRTPPort, "udp", self.verbose)
				
			if strResult == 0 or strResult < 0:
				self.Print("| | Error while scanning the port.",True)
				self.Print("| |",True)
				self.Print("| | Category: -",True)
			else:
				if strResult.find("closed") != -1:
					strResult = strResult.splitlines()
					for line in strResult:
						self.Print("| | " + line,True)   
					#self.Print("| | Result: Port closed",True) 
					self.Print("| |",True)
					self.Print("| | Category: Spoofed message",True)
					self.AddCategory("Spoofed message")
				else:
					strResult = strResult.splitlines()
					for line in strResult:
						self.Print("| | " + line,True)  
					#self.Print("| | Result: Port opened",True) 
					self.Print("| |",True)
					self.Print("| | Category: Interactive attack",True)
					self.AddCategory("Interactive attack")
				
		self.Print("",True)
		
	def Tests_CheckURI(self):
		"""
		This method carries out the URI comprobation test
		"""
		self.bRequestURI = False # Flag to know if this test gives a positive or negative result

		self.Print("+ Checking request URI...",True)
		self.Print("|",True)
		self.Print("| Extension in field To: " + self.CallInformation.To_Extension,True)
		self.Print("|",True)
		
		# Now it checks if the extension contained in the "To" field is one of the honeypot's registered
		# extesions.
		bFound = False
		for i in range(len(self.Extensions)):
			if str(self.Extensions[i].Extension) == self.CallInformation.To_Extension:
				# The extension contained in the "To" field is an extension of the honeypot.
				bFound = True
				self.Print("| Request addressed to the honeypot? Yes",True)
				self.bRequestURI = True
				break
				
		if bFound == False:
			self.Print("| Request addressed to the honeypot? No",True)
			self.bRequestURI = False

		self.Print("",True)
		
	def Tests_CheckVia(self):
		"""
		This method carries out the Via test
		"""
		# This entire tests depends on the result of the previous
		if self.bRequestURI == False:

			# Via[0] is the first Via field, so that it has the IP of the last proxy.
			
			self.Print("+ Checking if proxy in Via...",True)
			self.Print("|",True)
			self.Print("| + Checking " + self.CallInformation.Via[0][0] + ":" + self.CallInformation.Via[0][1] + "/" + self.CallInformation.Via[0][2] + "...",True)
			self.Print("| |",True)   
	
			# We determine the existence of the proxy by checking the port with nmap
			strResult = CheckPort(self.CallInformation.Via[0][0], self.CallInformation.Via[0][1], self.CallInformation.Via[0][2], self.verbose)
				
			if strResult == 0 or strResult < 0:
				self.Print("| | Error while scanning.",True)
				self.Print("| |",True)
				self.Print("| | Category: -",True)
			else:
				if strResult.find("closed") != -1: 
					self.Print("| | Result: There is no SIP proxy",True) 
					self.Print("| |",True)
					self.Print("| | Category: DialPlan fault",True)
					self.AddCategory("DialPlan fault")
				else:
					self.Print("| | Result: There is a SIP proxy",True) 
					self.Print("| |",True)
					self.Print("| | Category: Direct attack",True)
					self.AddCategory("Direct attack")
		
			self.Print("",True)
			
	def Tests_CheckACK(self):
		"""
		This method carries out the ACK test
		"""
		self.Print("+ Checking for ACK...",True)
		self.Print("|",True)
		
		if self.bACKReceived == True:
			self.Print("| ACK received: Yes",True)
		else:
			self.Print("| ACK received: No",True)
			self.Print("|",True)
			self.Print("| Category: Scanning",True)
			self.AddCategory("Scanning")

		self.Print("",True)
		
	def Tests_CheckMedia(self):
		"""
		This method carries out the received media test
		"""
		self.Print("+ Checking for received media...",True)
		self.Print("|",True)
		
		if self.bMediaReceived == True:
			self.Print("| Media received: Yes",True)
			self.Print("|",True)
			self.Print("| Category: SPIT",True)
			self.AddCategory("SPIT")
		else:
			self.Print("| Media received: No",True)
			self.Print("|",True)
			self.Print("| Category: Ringing",True)
			self.AddCategory("Ringing")	   

		self.Print("",True)
		
	def Start(self):
		"""
		This function starts the process. 
		"""

		self.GetCallData() # Retrieves all the necessary data from the message for further analysis

		self.CallInformation.Results_file = self.GetFilename()
		
		self.PrintFile = self.CallInformation.Results_file

		self.Print("")
		self.Print("******************************* Information about the call *******************************",True)
		self.Print("",True)
		
		self.Print("From: " + self.CallInformation.From_Extension + " in " + self.CallInformation.From_IP + ":" + self.CallInformation.From_Port + "/" + self.CallInformation.From_Transport,True)
		self.Print("To: "  + self.CallInformation.To_Extension + " in " + self.CallInformation.To_IP,True)
		self.Print("Contact: "  + self.CallInformation.Contact_Extension + " in " + self.CallInformation.Contact_IP + ":" + self.CallInformation.Contact_Port + "/" + self.CallInformation.Contact_Transport,True)
		self.Print("Connection: " + self.CallInformation.Connection,True)
		self.Print("Owner: " + self.CallInformation.Owner,True)
		
		for i in range(len(self.CallInformation.Via)):
			self.Print("Via " + str(i) + ": " + self.CallInformation.Via[i][0] + ":" + self.CallInformation.Via[i][1] + "/" + self.CallInformation.Via[i][2],True)
			
		self.Print(self.CallInformation.UserAgent,True)

		self.Print("",True)
		self.Print("************************************* Classification *************************************",True)
		self.Print("",True)
				
		# ---------------------------------------------------------------------------------
		# Check fingerprint
		# ---------------------------------------------------------------------------------
		self.Tests_CheckFingerprint()

		# ---------------------------------------------------------------------------------
		# Check DNS
		# ---------------------------------------------------------------------------------
		self.Tests_CheckDNS()
		
		# ---------------------------------------------------------------------------------
		# Check if SIP ports are opened
		# ---------------------------------------------------------------------------------
		self.Tests_CheckSIPPorts()

		# ---------------------------------------------------------------------------------
		# Check if media ports are opened
		# ---------------------------------------------------------------------------------
		self.Tests_CheckMediaPorts()

		# ---------------------------------------------------------------------------------
		# Check request URI
		# ---------------------------------------------------------------------------------
		self.Tests_CheckURI()

		# ---------------------------------------------------------------------------------
		# Check if proxy in Via
		# ---------------------------------------------------------------------------------
		self.Tests_CheckVia()

		# ---------------------------------------------------------------------------------
		# Check for ACK
		# ---------------------------------------------------------------------------------
		self.Tests_CheckACK()

		# ---------------------------------------------------------------------------------
		# Check received media
		# ---------------------------------------------------------------------------------
		self.Tests_CheckMedia()

		# Print the categories
		self.Print("+ The message is classified as:",True)
		for i in range(len( self.CallInformation.Classification)):
			self.Print("| " +  self.CallInformation.Classification[i],True)
	
		self.Print("",True)

		self.Running = False


	def GetCallData(self):
		"""
		This method extracts information from the SIP message.
		"""
				
		# First line of the SIP message (We call it INVITE)
		self.CallInformation.INVITE_IP = GetIPfromSIP(GetSIPHeader("INVITE",self.CallInformation.SIP_Message))
		self.CallInformation.INVITE_Port = GetPortfromSIP(GetSIPHeader("INVITE",self.CallInformation.SIP_Message))
		if self.CallInformation.INVITE_Port == "": self.CallInformation.INVITE_Port = "5060" # By default
		self.CallInformation.INVITE_Extension = GetExtensionfromSIP(GetSIPHeader("INVITE",self.CallInformation.SIP_Message))

		self.CallInformation.INVITE_Transport = GetTransportfromSIP(GetSIPHeader("INVITE",self.CallInformation.SIP_Message))
	
		# Field To
		self.CallInformation.To_IP = GetIPfromSIP(GetSIPHeader("To",self.CallInformation.SIP_Message))
		self.CallInformation.To_Extension = GetExtensionfromSIP(GetSIPHeader("To",self.CallInformation.SIP_Message))
		
		# Field From
		self.CallInformation.From_IP = GetIPfromSIP(GetSIPHeader("From",self.CallInformation.SIP_Message))
		self.CallInformation.From_Port = GetPortfromSIP(GetSIPHeader("From",self.CallInformation.SIP_Message))
		if self.CallInformation.From_Port == "": self.CallInformation.From_Port = "5060" # By default
		self.CallInformation.From_Extension = GetExtensionfromSIP(GetSIPHeader("From",self.CallInformation.SIP_Message))

		self.CallInformation.From_Transport = GetTransportfromSIP(GetSIPHeader("From",self.CallInformation.SIP_Message))

		# Field Contact
		self.CallInformation.Contact_IP = GetIPfromSIP(GetSIPHeader("Contact",self.CallInformation.SIP_Message))
		self.CallInformation.Contact_Port = GetPortfromSIP(GetSIPHeader("Contact",self.CallInformation.SIP_Message))
		if self.CallInformation.Contact_Port == "": self.CallInformation.Contact_Port = "5060" # By default
		self.Contact_Extension = GetExtensionfromSIP(GetSIPHeader("Contact",self.CallInformation.SIP_Message))

		self.CallInformation.Contact_Transport = GetTransportfromSIP(GetSIPHeader("Contact",self.CallInformation.SIP_Message))
			
		# Field Connection
		self.CallInformation.Connection = GetIPfromSIP(GetSIPHeader("c=",self.CallInformation.SIP_Message))
		
		# Field Owner
		self.CallInformation.Owner = GetIPfromSIP(GetSIPHeader("o=",self.CallInformation.SIP_Message))
			
		# Field UserAgent
		self.CallInformation.UserAgent = GetSIPHeader("User-Agent",self.CallInformation.SIP_Message)
	
		# Field RecordRoute
		#self.CallInformation.Record_Route = GetSIPHeader("Record-Route",self.CallInformation.SIP_Message)
		
		# Field Via
		for line in self.CallInformation.SIP_Message.splitlines():
			if line[0:4] == "Via:":
				self.CallInformation.Via.append([GetIPfromSIP(line.strip()), GetPortfromSIP(line.strip()), GetTransportfromSIP(GetSIPHeader(line.strip(),self.CallInformation.SIP_Message))])
		
		
	def AddCategory(self, strCategory):
		"""
		Keyword Arguments:
		strCategory -- category to add
		
		"""
		bFound = False
		
		for i in range(len(self.CallInformation.Classification)):
			if self.CallInformation.Classification[i] == strCategory:
				bFound = True
				break

		if bFound == True: return

		self.CallInformation.Classification.append(strCategory)

	
