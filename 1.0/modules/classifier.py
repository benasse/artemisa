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
from mail import Email

from commons import GetSIPHeader
from commons import Search
from commons import GetTimeClass
from commons import GetIPfromSIP
from commons import GetPortfromSIP
from commons import GetExtensionfromSIP
from commons import GetTransportfromSIP
from commons import RemoveComments
from commons import CallData
from check_fingerprint import CheckFingerprint
from check_dns import CheckDNS
from check_port import CheckPort
from modules.logger import logger

class Classifier():
    """
    This class performs the classification of the received SIP message.
    """
    
    def __init__(self, verbose, strLocal_IP, strLocal_port, behaviour_mode, behaviour_actions, SIP_Message, Extensions, bACKReceived, MediaReceived):
        self.strLocal_IP = strLocal_IP
        self.strLocal_port = strLocal_port
        self.verbose = verbose # Flag to know whether the verbose mode is set or not
        self.Extensions = Extensions # Extensions registered by Artemisa
        self.bACKReceived = bACKReceived
        self.MediaReceived = MediaReceived
        self.Behaviour = behaviour_mode
        self.Behaviour_actions = behaviour_actions
        self.bRequestURI = False
        self.Running = True # State of the analysis
        self.CallInformation = CallData(SIP_Message) # Creates an instance of CallData

    def Tests_CheckFingerprint(self):
        """
        This method carries out the fingerprint test
        """
        prtString = "+ Checking fingerprint..."; self.CallInformation.Results_File_Buffer += "\n" + prtString; logger.info(prtString)
        prtString = "|"; self.CallInformation.Results_File_Buffer += "\n" + prtString; logger.info(prtString)
        prtString = "| " + self.CallInformation.UserAgent; self.CallInformation.Results_File_Buffer += "\n" + prtString; logger.info(prtString)
        
        # Artemisa will find fingerprint signatures in the whole SIP message
        self.CallInformation.ToolName = CheckFingerprint(self.CallInformation.SIP_Message)
        #if self.CallInformation.ToolName < 0:
        #    prtString = "|"; self.CallInformation.Results_File_Buffer += "\n" + prtString; logger.info(prtString)
        #    prtString = "| Fingerprint check failed."; self.CallInformation.Results_File_Buffer += "\n" + prtString; logger.info(prtString)
        if self.CallInformation.ToolName == "":
            prtString = "|"; self.CallInformation.Results_File_Buffer += "\n" + prtString; logger.info(prtString)
            prtString = "| No fingerprint found."; self.CallInformation.Results_File_Buffer += "\n" + prtString; logger.info(prtString)
        else:
            prtString = "|"; self.CallInformation.Results_File_Buffer += "\n" + prtString; logger.info(prtString)
            prtString = "| Fingerprint found. The following attack tool was employed: " + self.CallInformation.ToolName; self.CallInformation.Results_File_Buffer += "\n" + prtString; logger.info(prtString)
            prtString = "|"; self.CallInformation.Results_File_Buffer += "\n" + prtString; logger.info(prtString)
            prtString = "| Category: Attack tool"; self.CallInformation.Results_File_Buffer += "\n" + prtString; logger.info(prtString)
            self.AddCategory("Attack tool")
        
        prtString = ""; self.CallInformation.Results_File_Buffer += "\n" + prtString; logger.info(prtString)
        
    def Tests_CheckDNS(self):
        """
        This method carries out the DNS test
        """
        prtString = "+ Checking DNS..."; self.CallInformation.Results_File_Buffer += "\n" + prtString; logger.info(prtString)
        
        ip_to_analyze = [] # IPs that will be analyzed
                
        ip_to_analyze.append(self.CallInformation.From_IP)
        if ip_to_analyze.count(self.CallInformation.Contact_IP) == 0: ip_to_analyze.append(self.CallInformation.Contact_IP) # This is to avoid having repeated IPs
        if ip_to_analyze.count(self.CallInformation.Connection) == 0: ip_to_analyze.append(self.CallInformation.Connection)
        if ip_to_analyze.count(self.CallInformation.Owner) == 0: ip_to_analyze.append(self.CallInformation.Owner)
        
        for i in range(len(self.CallInformation.Via)):
                if ip_to_analyze.count(self.CallInformation.Via[i][0]) == 0: ip_to_analyze.append(self.CallInformation.Via[i][0])
       
        # Analyze each IP address 
        for i in range(len(ip_to_analyze)):
            prtString = "|"; self.CallInformation.Results_File_Buffer += "\n" + prtString; logger.info(prtString)
            prtString = "| + Checking " + ip_to_analyze[i] + "..."; self.CallInformation.Results_File_Buffer += "\n" + prtString; logger.info(prtString)
            prtString = "| |"; self.CallInformation.Results_File_Buffer += "\n" + prtString; logger.info(prtString)            
            DNS_Result = CheckDNS(ip_to_analyze[i], self.verbose)
            if DNS_Result <= 0:
                prtString = "| | IP cannot be resolved."; self.CallInformation.Results_File_Buffer += "\n" + prtString; logger.info(prtString)
                prtString = "| |"; self.CallInformation.Results_File_Buffer += "\n" + prtString; logger.info(prtString)
                prtString = "| | Category: Spoofed message"; self.CallInformation.Results_File_Buffer += "\n" + prtString; logger.info(prtString)
                self.AddCategory("Spoofed message")
            else:
                if (DNS_Result.find("WHOIS data not found") != -1 or DNS_Result.find("none") != -1) and DNS_Result.find("not DNS") == -1:
                    DNS_Result = DNS_Result.splitlines()
                    for line in DNS_Result:
                        prtString = "| | " + line; self.CallInformation.Results_File_Buffer += "\n" + prtString; logger.info(prtString)
                    prtString = "| |"; self.CallInformation.Results_File_Buffer += "\n" + prtString; logger.info(prtString)
                    prtString = "| |Category: Spoofed message"; self.CallInformation.Results_File_Buffer += "\n" + prtString; logger.info(prtString)
                    self.AddCategory("Spoofed message")
                elif DNS_Result.find("not DNS") != -1:
                    prtString = "| | This is already an IP address. Nothing done."; self.CallInformation.Results_File_Buffer += "\n" + prtString; logger.info(prtString)
                else:
                    DNS_Result = DNS_Result.splitlines()
                    for line in DNS_Result:
                        prtString = "| | " + line; self.CallInformation.Results_File_Buffer += "\n" + prtString; logger.info(prtString)
                    prtString = "| |"; self.CallInformation.Results_File_Buffer += "\n" + prtString; logger.info(prtString)
                    prtString = "| | Category: Interactive attack"; self.CallInformation.Results_File_Buffer += "\n" + prtString; logger.info(prtString)
                    self.AddCategory("Interactive attack")
    
        prtString = ""; self.CallInformation.Results_File_Buffer += "\n" + prtString; logger.info(prtString)
        
    def Tests_CheckSIPPorts(self):
        """
        This method carries out the SIP ports test
        """
        prtString = "+ Checking if SIP port is opened..."; self.CallInformation.Results_File_Buffer += "\n" + prtString; logger.info(prtString)

        prtString = "|"; self.CallInformation.Results_File_Buffer += "\n" + prtString; logger.info(prtString)
        prtString = "| + Checking " + self.CallInformation.Contact_IP + ":" + self.CallInformation.Contact_Port + "/" + self.CallInformation.Contact_Transport + "..."; self.CallInformation.Results_File_Buffer += "\n" + prtString; logger.info(prtString)
        prtString = "| |"; self.CallInformation.Results_File_Buffer += "\n" + prtString; logger.info(prtString)
            
        strResult = CheckPort(self.CallInformation.Contact_IP, self.CallInformation.Contact_Port, self.CallInformation.Contact_Transport, self.verbose)
            
        if strResult == 0 or strResult < 0:
            prtString = "| |  Error while scanning the port."; self.CallInformation.Results_File_Buffer += "\n" + prtString; logger.info(prtString)
            prtString = "| |"; self.CallInformation.Results_File_Buffer += "\n" + prtString; logger.info(prtString)
            prtString = "| |  Category: -"; self.CallInformation.Results_File_Buffer += "\n" + prtString; logger.info(prtString)
        else:
            if strResult.find("closed") != -1:
                strResult = strResult.splitlines()
                for line in strResult:
                    prtString = "| | " + line; self.CallInformation.Results_File_Buffer += "\n" + prtString; logger.info(prtString)
                prtString = "| |"; self.CallInformation.Results_File_Buffer += "\n" + prtString; logger.info(prtString)
                prtString = "| | Category: Spoofed message"; self.CallInformation.Results_File_Buffer += "\n" + prtString; logger.info(prtString)
                self.AddCategory("Spoofed message")
            else:
                strResult = strResult.splitlines()
                for line in strResult:
                    prtString = "| | " + line; self.CallInformation.Results_File_Buffer += "\n" + prtString; logger.info(prtString)
                prtString = "| |"; self.CallInformation.Results_File_Buffer += "\n" + prtString; logger.info(prtString)
                prtString = "| | Category: Interactive attack"; self.CallInformation.Results_File_Buffer += "\n" + prtString; logger.info(prtString)
                self.AddCategory("Interactive attack")
                
        prtString = ""; self.CallInformation.Results_File_Buffer += "\n" + prtString; logger.info(prtString)
        
    def Tests_CheckMediaPorts(self):
        """
        This method carries out the media ports test
        """
        prtString = "+ Checking if media port is opened..."; self.CallInformation.Results_File_Buffer += "\n" + prtString; logger.info(prtString)

        # FIXME: this parsing could be improved
        strRTPPort = GetSIPHeader("m=audio", self.CallInformation.SIP_Message)
        
        if strRTPPort == "": # Could happen that no RTP was delivered
            prtString = "|"; self.CallInformation.Results_File_Buffer += "\n" + prtString; logger.info(prtString)
            prtString = "| No RTP info delivered."; self.CallInformation.Results_File_Buffer += "\n" + prtString; logger.info(prtString)
            prtString = "|"; self.CallInformation.Results_File_Buffer += "\n" + prtString; logger.info(prtString)
            prtString = "| Category: Spoofed message"; self.CallInformation.Results_File_Buffer += "\n" + prtString; logger.info(prtString)
            self.AddCategory("Spoofed message")
        else:
            strRTPPort = strRTPPort.split(" ")[1]

            prtString = "|"; self.CallInformation.Results_File_Buffer += "\n" + prtString; logger.info(prtString)
            prtString = "| + Checking " + self.CallInformation.Contact_IP + ":" + strRTPPort + "/" + "udp" + "..."; self.CallInformation.Results_File_Buffer += "\n" + prtString; logger.info(prtString)
            prtString = "| |"; self.CallInformation.Results_File_Buffer += "\n" + prtString; logger.info(prtString)

            strResult = CheckPort(self.CallInformation.Contact_IP, strRTPPort, "udp", self.verbose)
                
            if strResult == 0 or strResult < 0:
                prtString = "| | Error while scanning the port."; self.CallInformation.Results_File_Buffer += "\n" + prtString; logger.info(prtString)
                prtString = "| |"; self.CallInformation.Results_File_Buffer += "\n" + prtString; logger.info(prtString)
                prtString = "| | Category: -"; self.CallInformation.Results_File_Buffer += "\n" + prtString; logger.info(prtString)
            else:
                if strResult.find("closed") != -1:
                    strResult = strResult.splitlines()
                    for line in strResult:
                        prtString = "| | " + line; self.CallInformation.Results_File_Buffer += "\n" + prtString; logger.info(prtString)   
                    prtString = "| |"; self.CallInformation.Results_File_Buffer += "\n" + prtString; logger.info(prtString)
                    prtString = "| | Category: Spoofed message"; self.CallInformation.Results_File_Buffer += "\n" + prtString; logger.info(prtString)
                    self.AddCategory("Spoofed message")
                else:
                    strResult = strResult.splitlines()
                    for line in strResult:
                        prtString = "| | " + line; self.CallInformation.Results_File_Buffer += "\n" + prtString; logger.info(prtString)   
                    prtString = "| |"; self.CallInformation.Results_File_Buffer += "\n" + prtString; logger.info(prtString)
                    prtString = "| | Category: Interactive attack"; self.CallInformation.Results_File_Buffer += "\n" + prtString; logger.info(prtString) 
                    self.AddCategory("Interactive attack")
                
        prtString = ""; self.CallInformation.Results_File_Buffer += "\n" + prtString; logger.info(prtString)
        
    def Tests_CheckURI(self):
        """
        This method carries out the URI comprobation test
        """
        self.bRequestURI = False # Flag to know if this test gives a positive or negative result

        prtString = "+ Checking request URI..."; self.CallInformation.Results_File_Buffer += "\n" + prtString; logger.info(prtString)
        prtString = "|"; self.CallInformation.Results_File_Buffer += "\n" + prtString; logger.info(prtString)
        prtString = "| Extension in field To: " + self.CallInformation.To_Extension; self.CallInformation.Results_File_Buffer += "\n" + prtString; logger.info(prtString)
        prtString = "|"; self.CallInformation.Results_File_Buffer += "\n" + prtString; logger.info(prtString)

        # Now it checks if the extension contained in the "To" field is one of the honeypot's registered
        # extesions.
        Found = False
        for i in range(len(self.Extensions)):
            if str(self.Extensions[i].Extension) == self.CallInformation.To_Extension:
                # The extension contained in the "To" field is an extension of the honeypot.
                Found = True
                prtString = "| Request addressed to the honeypot? Yes"; self.CallInformation.Results_File_Buffer += "\n" + prtString; logger.info(prtString)
                self.bRequestURI = True
                break
                
        if not Found:
            prtString = "| Request addressed to the honeypot? No"; self.CallInformation.Results_File_Buffer += "\n" + prtString; logger.info(prtString)
            self.bRequestURI = False

        prtString = ""; self.CallInformation.Results_File_Buffer += "\n" + prtString; logger.info(prtString)
        
    def Tests_CheckVia(self):
        """
        This method carries out the Via test
        """
        # This entire tests depends on the result of the previous
        if not self.bRequestURI:

            # Via[0] is the first Via field, so that it has the IP of the last proxy.
            
            prtString = "+ Checking if proxy in Via..."; self.CallInformation.Results_File_Buffer += "\n" + prtString; logger.info(prtString)
            prtString = "|"; self.CallInformation.Results_File_Buffer += "\n" + prtString; logger.info(prtString)

            if len(self.CallInformation.Via) == 0:
                prtString = "| No Via found."; self.CallInformation.Results_File_Buffer += "\n" + prtString; logger.info(prtString)
                prtString = ""; self.CallInformation.Results_File_Buffer += "\n" + prtString; logger.info(prtString)
                return

            prtString = "| + Checking " + self.CallInformation.Via[0][0] + ":" + self.CallInformation.Via[0][1] + "/" + self.CallInformation.Via[0][2] + "..."; self.CallInformation.Results_File_Buffer += "\n" + prtString; logger.info(prtString)
            prtString = "| |"; self.CallInformation.Results_File_Buffer += "\n" + prtString; logger.info(prtString)

            # We determine the existence of the proxy by checking the port with nmap
            strResult = CheckPort(self.CallInformation.Via[0][0], self.CallInformation.Via[0][1], self.CallInformation.Via[0][2], self.verbose)
                
            if strResult == 0 or strResult < 0:
                prtString = "| | Error while scanning."; self.CallInformation.Results_File_Buffer += "\n" + prtString; logger.info(prtString)
                prtString = "| |"; self.CallInformation.Results_File_Buffer += "\n" + prtString; logger.info(prtString)
                prtString = "| | Category: -"; self.CallInformation.Results_File_Buffer += "\n" + prtString; logger.info(prtString)
            else:
                if strResult.find("closed") != -1: 
                    prtString = "| | Result: There is no SIP proxy"; self.CallInformation.Results_File_Buffer += "\n" + prtString; logger.info(prtString)
                    prtString = "| |"; self.CallInformation.Results_File_Buffer += "\n" + prtString; logger.info(prtString)
                    prtString = "| | Category: Dial plan fault"; self.CallInformation.Results_File_Buffer += "\n" + prtString; logger.info(prtString)
                    self.AddCategory("Dial plan fault")
                else:
                    prtString = "| | Result: There is a SIP proxy"; self.CallInformation.Results_File_Buffer += "\n" + prtString; logger.info(prtString)
                    prtString = "| |"; self.CallInformation.Results_File_Buffer += "\n" + prtString; logger.info(prtString)
                    prtString = "| | Category: Direct attack"; self.CallInformation.Results_File_Buffer += "\n" + prtString; logger.info(prtString)
                    self.AddCategory("Direct attack")
        
            prtString = ""; self.CallInformation.Results_File_Buffer += "\n" + prtString; logger.info(prtString)
            
    def Tests_CheckACK(self):
        """
        This method carries out the ACK test
        """
        prtString = "+ Checking for ACK..."; self.CallInformation.Results_File_Buffer += "\n" + prtString; logger.info(prtString)
        prtString = "|"; self.CallInformation.Results_File_Buffer += "\n" + prtString; logger.info(prtString)

        if self.bACKReceived:
            prtString = "| ACK received: Yes"; self.CallInformation.Results_File_Buffer += "\n" + prtString; logger.info(prtString)
        else:
            prtString = "| ACK received: No"; self.CallInformation.Results_File_Buffer += "\n" + prtString; logger.info(prtString)
            prtString = "|"; self.CallInformation.Results_File_Buffer += "\n" + prtString; logger.info(prtString)
            prtString = "| Category: Scanning"; self.CallInformation.Results_File_Buffer += "\n" + prtString; logger.info(prtString)
            self.AddCategory("Scanning")

        prtString = ""; self.CallInformation.Results_File_Buffer += "\n" + prtString; logger.info(prtString)
        
    def Tests_CheckMedia(self):
        """
        This method carries out the received media test
        """
        prtString = "+ Checking for received media..."; self.CallInformation.Results_File_Buffer += "\n" + prtString; logger.info(prtString)
        prtString = "|"; self.CallInformation.Results_File_Buffer += "\n" + prtString; logger.info(prtString)
        
        if self.MediaReceived:
            prtString = "| Media received: Yes"; self.CallInformation.Results_File_Buffer += "\n" + prtString; logger.info(prtString)
            prtString = "|"; self.CallInformation.Results_File_Buffer += "\n" + prtString; logger.info(prtString)
            prtString = "| Category: SPIT"; self.CallInformation.Results_File_Buffer += "\n" + prtString; logger.info(prtString)
            self.AddCategory("SPIT")
        else:
            prtString = "| Media received: No"; self.CallInformation.Results_File_Buffer += "\n" + prtString; logger.info(prtString)
            prtString = "|"; self.CallInformation.Results_File_Buffer += "\n" + prtString; logger.info(prtString)
            prtString = "| Category: Ringing"; self.CallInformation.Results_File_Buffer += "\n" + prtString; logger.info(prtString)
            self.AddCategory("Ringing")       

        prtString = ""; self.CallInformation.Results_File_Buffer += "\n" + prtString; logger.info(prtString)
        
    def Start(self):
        """
        This function starts the process. 
        """
        
        prtString = ""; self.CallInformation.Results_File_Buffer += "\n" + prtString; logger.info(prtString)
        prtString = "******************************* Information about the call *******************************"; self.CallInformation.Results_File_Buffer += "\n" + prtString; logger.info(prtString)
        prtString = ""; self.CallInformation.Results_File_Buffer += "\n" + prtString; logger.info(prtString)

        prtString = "From: " + self.CallInformation.From_Extension + " in " + self.CallInformation.From_IP + ":" + self.CallInformation.From_Port + "/" + self.CallInformation.From_Transport; self.CallInformation.Results_File_Buffer += "\n" + prtString; logger.info(prtString)
        prtString = "To: "  + self.CallInformation.To_Extension + " in " + self.CallInformation.To_IP; self.CallInformation.Results_File_Buffer += "\n" + prtString; logger.info(prtString)
        prtString = "Contact: "  + self.CallInformation.Contact_Extension + " in " + self.CallInformation.Contact_IP + ":" + self.CallInformation.Contact_Port + "/" + self.CallInformation.Contact_Transport; self.CallInformation.Results_File_Buffer += "\n" + prtString; logger.info(prtString)
        prtString = "Connection: " + self.CallInformation.Connection; self.CallInformation.Results_File_Buffer += "\n" + prtString; logger.info(prtString)
        prtString = "Owner: " + self.CallInformation.Owner; self.CallInformation.Results_File_Buffer += "\n" + prtString; logger.info(prtString)
        
        for i in range(len(self.CallInformation.Via)):
            prtString = "Via " + str(i) + ": " + self.CallInformation.Via[i][0] + ":" + self.CallInformation.Via[i][1] + "/" + self.CallInformation.Via[i][2]; self.CallInformation.Results_File_Buffer += "\n" + prtString; logger.info(prtString)
            
        prtString = self.CallInformation.UserAgent; self.CallInformation.Results_File_Buffer += "\n" + prtString; logger.info(prtString)

        prtString = ""; self.CallInformation.Results_File_Buffer += "\n" + prtString; logger.info(prtString)
        prtString = "************************************* Classification *************************************"; self.CallInformation.Results_File_Buffer += "\n" + prtString; logger.info(prtString)
        prtString = ""; self.CallInformation.Results_File_Buffer += "\n" + prtString; logger.info(prtString)

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
        prtString = "+ The message is classified as:"; self.CallInformation.Results_File_Buffer += "\n" + prtString; logger.info(prtString)
        for i in range(len( self.CallInformation.Classification)):
            prtString = "| " +  self.CallInformation.Classification[i]; self.CallInformation.Results_File_Buffer += "\n" + prtString; logger.info(prtString)
    
        prtString = ""; self.CallInformation.Results_File_Buffer += "\n" + prtString; logger.info(prtString)

        self.Running = False
        
    def AddCategory(self, Category):
        """
        Keyword Arguments:
        Category -- category to add
        
        """
        Found = False
        
        for i in range(len(self.CallInformation.Classification)):
            if self.CallInformation.Classification[i] == Category:
                Found = True
                break

        if Found: return

        self.CallInformation.Classification.append(Category)

    
