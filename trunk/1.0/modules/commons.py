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
import ConfigParser				# Read configuration files
from libs.IPy.IPy import *			# Module to deal with IPs
from subprocess import Popen, PIPE

from modules.logger import logger

class CallData(object):
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
		self.Results_File_Buffer = "" # Stores the results printed on screen

class GetTimeClass:
	"""
	This class has a method that returns the time in a specific format.
	"""
	def GetTime(self):
		return "[" + str(strftime("%Y-%m-%d %H:%M:%S")) + "]"

def Search(Label, Data):
	"""
	Keyword Arguments:
	Label -- label to find
	Data -- string containg the bunch of data
	
	Search a value in a bunch of data and return its content. The values to search have the
	structure "label=value"
	"""
	
	Temp = Data.strip().splitlines(True)
	
	for line in Temp:
		if line.find(Label + "=") != -1:
			try:
				return Data.split("=")[1]
			except:
				raise Exception("Error in function commons.Search. Cannot return value=string.")
				break

	return ""

def GetSIPHeader(Keyword, Data):
	"""
	Keyword Arguments:
	Keyword -- pattern to identify the line
	Data -- typically the SIP message to where the function looks for the header
	
	This function searches a line of the SIP header and returns it.
	"""
	Temp = Data.splitlines()

	for line in Temp:
		if line[0:len(Keyword)] == Keyword:
			return line.strip()

	return ""

def GetIPfromSIP(HeaderLine):
	"""
	Keyword Arguments:
	HeaderLine -- a string containing a specific SIP header
	
	This function gets and returns the IP address from a SIP header field.
	"""
	if HeaderLine == "": return ""

	try:
		if HeaderLine.find("sip:") != -1:
			IPaddr = HeaderLine.split("sip:")[1]
			if IPaddr.find("@") != -1:
				IPaddr = IPaddr.split("@")[1]
			IPaddr = IPaddr.split(">")[0]
			IPaddr = IPaddr.split(":")[0]

			return IPaddr.strip()

		IPaddr = HeaderLine.split(">")[0]
		if IPaddr.find("@") != -1:
			IPaddr = IPaddr.split("@")[1]
		IPaddr = IPaddr.split(";")[0]
		if IPaddr.find(" ") != -1:
			IPaddr = IPaddr.split(" ")[len(IPaddr.split(" "))-1]
		IPaddr = IPaddr.split(":")[0]
		IPaddr = IPaddr.split("<")[len(IPaddr.split("<"))-1]
	except Exception, e:
		logger.error("Error in GetIPfromSIP function. Details: " + str(e))
		return ""
	
	return IPaddr.strip()
	
def GetPortfromSIP(HeaderLine):
	"""
	Keyword Arguments:
	HeaderLine -- a string containing a specific SIP header
	
	This function gets and returns the port number from a SIP header field.
	"""
	if HeaderLine == "": return ""

	try:
		if HeaderLine.find("sip:") != -1:
			Port = HeaderLine.split("sip:")[1]
			Port = Port.split(" ")[0]
			Port = Port.split(";")[0]
			if Port.find("@") != -1:
				Port = Port.split("@")[1]
			Port = Port.split(">")[0]
			
			if Port.find(":") != -1:
				Port = Port.split(":")[1].strip()
			else:
				return ""

			return Port.strip()

		Port = HeaderLine.split(">")[0]
		if Port.find("@") != -1:
			Port = Port.split("@")[1]
		Port = Port.split(";")[0]
		if Port.find(" ") != -1:
			Port = Port.split(" ")[len(Port.split(" "))-1]

		if Port.find(":") != -1:
			Port = Port.split(":")[len(Port.split(":"))-1].strip()
		else:
			return ""
	except Exception, e:
		logger.error("Error in GetPortfromSIP function. Details: " + str(e))
		return ""
		
	return Port.strip()
	
def GetExtensionfromSIP(HeaderLine):
	"""
	Keyword Arguments:
	HeaderLine -- a string containing a specific SIP header
	
	This function gets and returns the extension value from a SIP header field.
	"""
	if HeaderLine == "": return ""

	try:
		if HeaderLine.find("@") == -1:
			return "" # This means that there is not extension found

		if HeaderLine.find("sip:") == -1:
			return "" # This means that there is not extension found
			
		Extension = HeaderLine.split("sip:")[1]
		Extension = Extension.split("@")[0]
		
	except Exception, e:
		logger.error("Error in GetExtensionfromSIP function. Details: " + str(e))
		return ""
		
	return Extension.strip()
	
def GetTransportfromSIP(HeaderLine):
	"""
	Keyword Arguments:
	HeaderLine -- a string containing a specific SIP header
	
	This function gets and returns the transport protocol value from a SIP header field.
	"""
	if HeaderLine.lower().find("udp") != -1: 
		return "udp"
	elif HeaderLine.lower().find("tcp") != -1: 
		return "tcp"
	else:
		return "udp" # By default	

def GetConfigSection(strFilename, strSection):
	"""
	Keyword Arguments:
	strFilename -- configuration file to read
	strSection -- section searched
	
	This function reads a file and returns the content of a section. This was made in order to
	read the sections related with the behaviour mode in the configuration file artemisa.conf.
	"""
	SectionData = []
	
	try:
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
		
	except Exception, e:
		logger.error("Error in GetConfigSection function. Details: " + str(e))
		return ""
	
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
			Data = Process.communicate()[0].strip().split("\n")
			strDNS = Data[len(Data)-1]
				
		except OSError:
			logger.warning("Error in ResolveDNS function. The dns couldn't be resolved.")
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
