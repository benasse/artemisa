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
import os

# Set a path to the main root
sys.path.append("../")

from time import strftime
from subprocess import Popen
from subprocess import PIPE

from libs.IPy.IPy import IP            # Module to deal with IPs

from modules.logger import logger

class CallData(object):
    """
    Class employed to store some data about the received call and the analysis
    """

    def __init__(self, SIP_Message):
        self.SIP_Message = SIP_Message

        # All the properties are created (empty)
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

        # And then some of them are filled
        self.GetDataFromMessage()
    
    def GetDataFromMessage(self):
        """
        This method fill the object properies with the data extracted from 
        the SIP message
        """

        # First line of the SIP message (We call it INVITE). In case the message is not an INVITE
        # there is no problem since that is filled with "".
        self.INVITE_IP = GetIPfromSIP(GetSIPHeader("INVITE",self.SIP_Message))
        self.INVITE_Port = GetPortfromSIP(GetSIPHeader("INVITE",self.SIP_Message))
        if self.INVITE_Port == "": self.INVITE_Port = "5060" # By default
        self.INVITE_Extension = GetExtensionfromSIP(GetSIPHeader("INVITE",self.SIP_Message))
        self.INVITE_Transport = GetTransportfromSIP(GetSIPHeader("INVITE",self.SIP_Message))
    
        # Field To
        self.To_IP = GetIPfromSIP(GetSIPHeader("To",self.SIP_Message))
        self.To_Extension = GetExtensionfromSIP(GetSIPHeader("To",self.SIP_Message))
        
        # Field From
        self.From_IP = GetIPfromSIP(GetSIPHeader("From",self.SIP_Message))
        self.From_Port = GetPortfromSIP(GetSIPHeader("From",self.SIP_Message))
        if self.From_Port == "": self.From_Port = "5060" # By default
        self.From_Extension = GetExtensionfromSIP(GetSIPHeader("From",self.SIP_Message))
        self.From_Transport = GetTransportfromSIP(GetSIPHeader("From",self.SIP_Message))

        # Field Contact
        self.Contact_IP = GetIPfromSIP(GetSIPHeader("Contact",self.SIP_Message))
        self.Contact_Port = GetPortfromSIP(GetSIPHeader("Contact",self.SIP_Message))
        if self.Contact_Port == "": self.Contact_Port = "5060" # By default
        self.Contact_Extension = GetExtensionfromSIP(GetSIPHeader("Contact",self.SIP_Message))
        self.Contact_Transport = GetTransportfromSIP(GetSIPHeader("Contact",self.SIP_Message))
            
        # Field Connection
        self.Connection = GetIPfromSIP(GetSIPHeader("c=",self.SIP_Message))
        
        # Field Owner
        self.Owner = GetIPfromSIP(GetSIPHeader("o=",self.SIP_Message))
            
        # Field UserAgent
        self.UserAgent = GetSIPHeader("User-Agent",self.SIP_Message)
    
        # Field RecordRoute
        #Record_Route = GetSIPHeader("Record-Route",self.SIP_Message)
        
        # Field Via
        for line in self.SIP_Message.splitlines():
            if line[0:4] == "Via:":
                self.Via.append([GetIPfromSIP(line.strip()), GetPortfromSIP(line.strip()), GetTransportfromSIP(GetSIPHeader(line.strip(),self.SIP_Message))])
        



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

            if section_found:
                if line != "":
                    SectionData.append(line)
                            
            if line.find("[" + strSection + "]") != -1:
                section_found = True

        File.close()
        
    except Exception, e:
        logger.error("Error in GetConfigSection function. Details: " + str(e))
        return ""
    
    return SectionData
    
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

def GetCLIprompt():
    if os.getenv('HOSTNAME') is None:
        # Well... some distributions don't export the environmental variable HOSTNAME...
        return str(os.getenv('USER')) + "> "
    else:
        return str(os.getenv('HOSTNAME')) + "> "
