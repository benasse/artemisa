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

from time import strftime
from logs import log				# Import class log from logs.py
import ConfigParser				# Read configuration files
from libs.IPy.IPy import *			# Module to deal with IPs
from subprocess import Popen, PIPE

class CallData():
	"""
	Class employed to store some data about the received call and the analysis
	"""

	def __init__(self):
		self.SIP_Message = ""

		self.INVITE_IP = "" # Corresponds to the first line of a INVITE message
		self.INVITE_Port = ""
		self.INVITE_Transport = ""
		self.INVITE_Extension = ""
		
		self.To_IP = ""
		self.To_Extension = ""
		
		self.From_IP = ""
		self.From_Port = ""
		self.From_Transport = ""
		self.From_Extension = ""
		
		self.Contact_IP = ""
		self.Contact_Port = ""
		self.Contact_Transport = ""
		self.Contact_Extension = ""
		
		self.Via = []
		
		self.Record_Route = ""
		
		self.Connection = ""
		self.Owner = ""

		self.UserAgent = ""

		# The following variables are set for results
		self.Classification = []
		self.ToolName = "" # Flag to store the attack tool detected
		self.Results_file = ""

class GetTimeClass:
	"""
	This class has a method that returns the time in a specific format.
	"""
	def GetTime(self):
		return "[" + str(strftime("%Y-%m-%d %H:%M:%S")) + "]"

def Search(strLabel, strData):
	"""
	Keyword Arguments:
	strLabel -- label to find
	strData -- string containg the bunch of data
	
	Search a value in a bunch of data and return its content. The values to search have the
	structure "label=value"
	"""
	
	strTemp = strData.splitlines()
	
	for line in strTemp:
	   if line.search(strLabel + "=") != -1:
	   	   return strData.split("=")[1]

	return ""

def GetSIPHeader(strKeyword, strData):
	"""
	Keyword Arguments:
	strKeyword -- pattern to identify the line
	strData -- typically the SIP message to where the function looks for the header
	
	This function searches a line of the SIP header and returns it.
	"""
	strTemp = strData.splitlines()

	for line in strTemp:
		if line[0:len(strKeyword)] == strKeyword:
			return line.strip()

	return ""

def GetIPfromSIP(strHeaderLine):
	"""
	Keyword Arguments:
	strHeaderLine -- a string containing a specific SIP header
	
	This function gets and returns the IP address from a SIP header field.
	"""
	if strHeaderLine == "": return ""

	if strHeaderLine.find("sip:") != -1:
		strIP = strHeaderLine.split("sip:")[1]
		if strIP.find("@") != -1:
			strIP = strIP.split("@")[1]
		strIP = strIP.split(">")[0]
		strIP = strIP.split(":")[0]

		return strIP.strip()

	strIP = strHeaderLine.split(">")[0]
	if strIP.find("@") != -1:
		strIP = strIP.split("@")[1]
	strIP = strIP.split(";")[0]
	if strIP.find(" ") != -1:
		strIP = strIP.split(" ")[len(strIP.split(" "))-1]
	strIP = strIP.split(":")[0]
	strIP = strIP.split("<")[len(strIP.split("<"))-1]
	
	return strIP.strip()
	
def GetPortfromSIP(strHeaderLine):
	"""
	Keyword Arguments:
	strHeaderLine -- a string containing a specific SIP header
	
	This function gets and returns the port number from a SIP header field.
	"""
	if strHeaderLine == "": return ""

	if strHeaderLine.find("sip:") != -1:
		strPort = strHeaderLine.split("sip:")[1]
		strPort = strPort.split(" ")[0]
		strPort = strPort.split(";")[0]
		if strPort.find("@") != -1:
			strPort = strPort.split("@")[1]
		strPort = strPort.split(">")[0]
		
		if strPort.find(":") != -1:
			strPort = strPort.split(":")[1].strip()
		else:
			return ""

		return strPort.strip()

	strPort = strHeaderLine.split(">")[0]
	if strPort.find("@") != -1:
		strPort = strPort.split("@")[1]
	strPort = strPort.split(";")[0]
	if strPort.find(" ") != -1:
		strPort = strPort.split(" ")[len(strPort.split(" "))-1]

	if strPort.find(":") != -1:
		strPort = strPort.split(":")[len(strPort.split(":"))-1].strip()
	else:
		return ""
	
	return strPort.strip()
	
def GetExtensionfromSIP(strHeaderLine):
	"""
	Keyword Arguments:
	strHeaderLine -- a string containing a specific SIP header
	
	This function gets and returns the extension value from a SIP header field.
	"""
	if strHeaderLine == "": return ""

	if strHeaderLine.find("@") == -1:
		return "" # This means that there is not extension found

	if strHeaderLine.find("sip:") == -1:
		return "" # This means that there is not extension found
		
	strExtension = strHeaderLine.split("sip:")[1]
	strExtension = strExtension.split("@")[0]
	
	return strExtension.strip()
	
def GetTransportfromSIP(strHeaderLine):
	"""
	Keyword Arguments:
	strHeaderLine -- a string containing a specific SIP header
	
	This function gets and returns the transport protocol value from a SIP header field.
	"""
	if strHeaderLine.lower().find("udp") != -1: 
		return "udp"
	elif strHeaderLine.lower().find("tcp") != -1: 
		return "tcp"
	else:
		return "udp" # By default	

class PrintClass(log, GetTimeClass):

	def __init__(self):
		self.PrintFile = ""

	def Print(self, strData, bPrint=True):
		"""
		Keyword Arguments:
		strData -- string to print
		bPrint -- boolean to know whether the string shoud (True) or not (False) be printed on screen
		
		This method prints strData in console (unless bPrint is False) and log it.
		"""
		
		strTemp = strData.splitlines()
		
		if bPrint == True:
			if strData == "":
				print self.GetTime()
			else:
				for line in strTemp:
					print self.GetTime() + " " + line.replace("\n","").replace("\r","")
		   	
		# if self.PrintFile has a string value, it prints the string into a file   
		if self.PrintFile != "":
			File = open(self.PrintFile, "a")
			
			if strData == "":
				File.write("\n")
			else:
				for line in strTemp:
					File.write(line.replace("\n","").replace("\r","" + "\n") + "\n")
								
			File.close()
			
			
		self.Log(strData)
	
def GetConfigSection(strFilename, strSection):
	"""
	Keyword Arguments:
	strFilename -- configuration file to read
	strSection -- section searched
	
	This function reads a file and returns the content of a section. This was made in order to
	read the sections related with the behaviour mode in the configuration file artemisa.conf.
	"""
	SectionData = []
	
	File = open(strFilename, "r")
	
	section_found = False
	
	for line in File:
		line = RemoveComments(line)
		line = line.strip()
		
		if line.find("[") != -1:
			section_found = False

		if section_found == True:
			if line != "":
				SectionData.append(line)
						
		if line.find("[" + strSection + "]") != -1:
			section_found = True

	File.close()
	
	return SectionData

def ResolveDNS(strDNS):
	"""
	Keyword Arguments:
	strDNS -- DNS to resolve
	
	Get the IP from a DNS name.
	"""
	
	# Check if strDNS is an IP or a domain name
	bDNS = False
	try:
		temp = IP(strDNS)
	except:
		bDNS = True
			
	if bDNS == True: # Get the IP from the domain name
		try:		
			Process = Popen("dig " + strDNS + " A +noall +answer +short", shell=True, stdout=PIPE)
			Process.wait()
			strData = Process.communicate()[0].strip().split("\n")
			strDNS = strData[len(strData)-1]
				
		except OSError:
			return -1

	try:
		temp = IP(strDNS)
	except:
		# The address could't be resolved.
		return ""
	
	return IP(strDNS).strNormal()
	
def RemoveComments(strLine):
	"""
	Removes the comments (# comments) of a line.
	"""
	if len(strLine) == 0: return strLine
	
	while 1:
		if strLine.find("#") != -1: 
			strLine = strLine.split("#")[0]

		else:
			break
		
	return strLine
