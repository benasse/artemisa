#!/usr/bin/env python
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
# along with Artemisa.  If not, see <http://www.gnu.org/licenses/>.


from time import strftime
from logs import log                # Import class log from logs.py
import ConfigParser                 # Read configuration files

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

	strIP = strHeaderLine.split(">")[0]
	if strIP.find("@") != -1:
		strIP = strIP.split("@")[1]
	strIP = strIP.split(";")[0]
	if strIP.find(" ") != -1:
		strIP = strIP.split(" ")[len(strIP.split(" "))-1]
	strIP = strIP.split(":")[0]
	
	return strIP.strip()
	

# def GetExtensionfromSIP
#
# This function gets and returns the extension value from a SIP header field.

def GetExtensionfromSIP(strHeaderLine):

	if strHeaderLine == "": return ""

	strExtension = strHeaderLine.split("@")[0]
	strExtension = strExtension.split(":")[len(strExtension.split(":"))-1]
	
	return strExtension.strip()
	
	
	
# class PrintClass
#
# This simple class prints strData in console (unless bPrint is False) and log it.

class PrintClass(log, GetTimeClass):
	
	def Print(self, strData, bPrint=True):
	
		strTemp = ""	
		strTemp = strData.splitlines()
		
		if bPrint == True:
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
		
	
	
def GetCPTmatrix(strAnalysis):
	
	output = PrintClass()
	
	if strAnalysis == "dispersion":
		
		# Now read the dispersion.conf file and get the CPT table
		config = ConfigParser.ConfigParser()
		strTemp = config.read("./cptdb/dispersion.conf")

		if strTemp == []:
			output.Print("WARNING Can't read /cptdb/dispersion.conf. The dispersion analysis is not completed.")
			return -1
		else:
			try:

				CPT_matrix = [(float(config.get("DISPERSION", "d1").split(",")[0]),float(config.get("DISPERSION", "d1").split(",")[1]),float(config.get("DISPERSION", "d1").split(",")[2])),(float(config.get("DISPERSION", "d14").split(",")[0]),float(config.get("DISPERSION", "d14").split(",")[1]),float(config.get("DISPERSION", "d14").split(",")[2])),(float(config.get("DISPERSION", "d4").split(",")[0]),float(config.get("DISPERSION", "d4").split(",")[1]),float(config.get("DISPERSION", "d4").split(",")[2]))]
                    
			except:
				output.Print("WARNING Can't read /cptdb/dispersion.conf. The dispersion analysis is not completed.")
				return -1


	elif strAnalysis == "validdns":
		
		# Now read the dns.conf file and get the CPT table
		config = ConfigParser.ConfigParser()
		strTemp = config.read("./cptdb/dns.conf")
		
		if strTemp == []:
		    output.Print("WARNING Can't read /cptdb/dns.conf. The dns analysis is not completed.")
		    return -1
		else:
		    try:
		        
		    	CPT_matrix = [(float(config.get("DNS", "valid_dns").split(",")[0]),float(config.get("DNS", "invalid_dns").split(",")[0])),(float(config.get("DNS", "valid_dns").split(",")[1]),float(config.get("DNS", "invalid_dns").split(",")[1]))]

		    except:
		    	output.Print("WARNING Can't read /cptdb/whois.conf. The dns analysis is not completed.")
		        return -1


	elif strAnalysis == "historical":
    	
		# Now read the historical.conf file and get the CPT table
		config = ConfigParser.ConfigParser()
		strTemp = config.read("./cptdb/historical.conf")
		
		if strTemp == []:
		    output.Print("WARNING Can't read /cptdb/historical.conf. The historical analysis is not completed.")
		    return -1
		else:
		    try:

		        CPT_matrix = [(float(config.get("HISTORICAL", "matches0").split(",")[0]),float(config.get("HISTORICAL", "matches0").split(",")[1])),(float(config.get("HISTORICAL", "matches12").split(",")[0]),float(config.get("HISTORICAL", "matches12").split(",")[1])),(float(config.get("HISTORICAL", "matches3inf").split(",")[0]),float(config.get("HISTORICAL", "matches3inf").split(",")[1]))]
		            
		    except:
		        output.Print("WARNING Can't read /cptdb/historical.conf. The historical analysis is not completed.")
		        return -1
    
        
	elif strAnalysis == "whois":
    	
		# Now read the whois.conf file and get the CPT table
		config = ConfigParser.ConfigParser()
		strTemp = config.read("./cptdb/whois.conf")
		
		if strTemp == []:
		    output.Print("WARNING Can't read /cptdb/whois.conf. The whois analysis is not completed.")
		    return -1
		else:
		    try:

		        CPT_matrix = [(float(config.get("WHOIS", "in_secure_list").split(",")[0]),float(config.get("WHOIS", "not_in_secure_list").split(",")[0])),(float(config.get("WHOIS", "in_secure_list").split(",")[1]),float(config.get("WHOIS", "not_in_secure_list").split(",")[1]))]
		            
		    except:
		        output.Print("WARNING Can't read /cptdb/whois.conf. The whois analysis is not completed.")
		        return -1
    

	elif strAnalysis == "to":

		# Now read the to.conf file and get the CPT table
		config = ConfigParser.ConfigParser()
		strTemp = config.read("./cptdb/to.conf")
		
		if strTemp == []:
		    output.Print("WARNING Can't read /cptdb/to.conf. The to analysis is not completed.")
		    return -1
		else:
		    try:

		        CPT_matrix = [(float(config.get("TO", "yes").split(",")[0]),float(config.get("TO", "yes").split(",")[1]),float(config.get("TO", "yes").split(",")[2])),(float(config.get("TO", "no").split(",")[0]),float(config.get("TO", "no").split(",")[1]),float(config.get("TO", "no").split(",")[2]))]
		            
		    except:
		        output.Print("WARNING Can't read /cptdb/to.conf. The to analysis is not completed.")
		        return -1


	elif strAnalysis == "trust":
		
		# Now read the trust.conf file and get the CPT table
		config = ConfigParser.ConfigParser()
		strTemp = config.read("./cptdb/trust.conf")
		
		if strTemp == []:
		    return -1
		else:
		    try:

		        CPT_matrix = [(float(config.get("TRUST", "c1").split(",")[0]),float(config.get("TRUST", "c1").split(",")[1]),float(config.get("TRUST", "c1").split(",")[2])),(float(config.get("TRUST", "c2").split(",")[0]),float(config.get("TRUST", "c2").split(",")[1]),float(config.get("TRUST", "c2").split(",")[2])),(float(config.get("TRUST", "c3").split(",")[0]),float(config.get("TRUST", "c3").split(",")[1]),float(config.get("TRUST", "c3").split(",")[2]))]
		            
		    except:
		        return -1

	elif strAnalysis == "fingerprint":
	
		try:
			File = open("./cptdb/fingerprint.conf", "r")
	    
		except:
			output.Print("WARNING Can't read /cptdb/fingerprint.conf. The fingerprint analysis is not completed.")
			return -1
	
		CPT_matrix = []

		strFingerprint = ""

		for line in File:
			line = line.strip()
			line = RemoveComments(line)
		    
			if line == "": continue
		    
			if line.find("=") != -1:
				strFingerprint = line.split("=")[0].strip()
				nTrusted = float(line.split("=")[1].split(",")[0])
				nDistrusted = float(line.split("=")[1].split(",")[1])
	    
				CPT_matrix.append([strFingerprint, nTrusted, nDistrusted])
		    
		File.close()
	

	elif strAnalysis == "gl":
	
		try:
			File = open("./cptdb/gl.conf", "r")
	    
		except:
			output.Print("WARNING Can't read /cptdb/gl.conf. The gl analysis is not completed.")
			return -1
	
		CPT_matrix = []

		strCountry = ""

		for line in File:
			line = line.strip()
			line = RemoveComments(line)
		    
			if line == "": continue
		    
			if line.find("=") != -1:
				strCountry = line.split("=")[0].strip()
				nTrusted = float(line.split("=")[1].split(",")[0])
				nDistrusted = float(line.split("=")[1].split(",")[1])
				
				CPT_matrix.append([strCountry, nTrusted, nDistrusted])
		    
		File.close()	
	

	elif strAnalysis == "reliability":
	
		try:
			File = open("./cptdb/ipreliability.conf", "r")
	    
		except:
			output.Print("WARNING Can't read /cptdb/ipreliability.conf. The reliability analysis is not completed.")
			return -1
	
		CPT_matrix = []

		strItem = ""

		for line in File:
			line = line.strip()
			line = RemoveComments(line)
		    
			if line == "": continue
		    
			if line.find("=") != -1:
				strItem = line.split("=")[0].strip()
				nTrusted = float(line.split("=")[1].split(",")[0])
				nDistrusted = float(line.split("=")[1].split(",")[1])
				
				CPT_matrix.append([strItem, nTrusted, nDistrusted])
		    
		File.close()	
	
	# At this point the CPT was read from the configuration file

	try:
		del config
	except:
		pass
	
	del output
        
	return CPT_matrix
