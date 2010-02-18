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


from time import strftime
from logs import log                # Import class log from logs.py
import ConfigParser                 # Read configuration files
from libs.IPy.IPy import *       # Module to deal with IPs
from subprocess import Popen, PIPE

# class GetTimeClass
#
# Returns the time in a specific format.

class GetTimeClass:
	def GetTime(self):
		return "[" + str(strftime("%Y-%m-%d %H:%M:%S")) + "]"

# def Search
#
# Search a value in a bunch of data and return its content. The values to search have the
# structure "label=value"

def Search(strLabel, strData):

	strTemp = strData.splitlines()
	
	for line in strTemp:
	   if line.search(strLabel + "=") != -1:
	   	   return strData.split("=")[1]

	return ""


# def GetSIPHeader
#
# Search a line of the SIP header and returns it.

def GetSIPHeader(strKeyword, strData):

	strTemp = strData.splitlines()

	for line in strTemp:
		if line[0:len(strKeyword)] == strKeyword:
			return line.strip()

	return ""


# def GetIPfromSIP
#
# This function gets and returns the IP address from a SIP header field.

def GetIPfromSIP(strHeaderLine):

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
	


# def GetPortfromSIP
#
# This function gets and returns the port number from a SIP header field.

def GetPortfromSIP(strHeaderLine):

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
		strPort = strPort.split(":")[1].strip()
	else:
		return ""
	
	

# def GetExtensionfromSIP
#
# This function gets and returns the extension value from a SIP header field.

def GetExtensionfromSIP(strHeaderLine):

	if strHeaderLine == "": return ""

	if strHeaderLine.find("@") == -1:
		return "" # This means that there is not extension found

	if strHeaderLine.find("sip:") == -1:
		return "" # This means that there is not extension found
		
	strExtension = strHeaderLine.split("sip:")[1]
	strExtension = strExtension.split("@")[0]
	
	return strExtension.strip()
	
	
	
# class PrintClass
#
# This simple class prints strData in console (unless bPrint is False) and log it.

class PrintClass(log, GetTimeClass):
	
	def Print(self, strData, bPrint=True):

		strTemp = strData.splitlines()
		
		if bPrint == True:
			if strData == "":
				print self.GetTime()
			else:
				for line in strTemp:
					print self.GetTime() + " " + line.replace("\n","").replace("\r","")
		   	   
		self.Log(strData)
		
		
# def GetConfigSection
#
# This function reads a file and returns the content of a section. This was made in order to
# read the sections related with the behaviour mode in the configuration file artemisa.conf.

def GetConfigSection(strFilename, strSection):
	
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


# def ResolveDNS
#
# Get the IP from a DNS name.

def ResolveDNS(strIP):
	
	# Check if strIP is an IP or a domain name
	bDNS = False
	try:
		temp = IP(strIP)
	except:
		bDNS = True
            
	if bDNS == True: # Get the IP from the domain name
		try:        
			Process = Popen("dig " + strIP + " A +noall +answer +short", shell=True, stdout=PIPE)
			Process.wait()
			strData = Process.communicate()[0].strip().split("\n")
			strIP = strData[len(strData)-1]
                
		except OSError:
			return -1

	try:
		temp = IP(strIP)
	except:
		# The address could't be resolved.
		return ""
    
	return IP(strIP).strNormal()
	
	
# def RemoveComments
#
# Removes the comments (# comments) of a line.

def RemoveComments(strLine):
	
	if len(strLine) == 0: return strLine
	
	while 1:
		if strLine.find("#") != -1: 
			strLine = strLine.split("#")[0]

		else:
			break
		
	return strLine