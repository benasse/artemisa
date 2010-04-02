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

from commons import PrintClass, GetSIPHeader, Search, GetTimeClass, GetIPfromSIP, GetPortfromSIP, GetExtensionfromSIP, RemoveComments, ResolveDNS

from mail import Email
from htmlresults import get_results_html
from logs import log                # Import class log from logs.py

from check_fingerprint import CheckFingerprint
from check_dns import CheckDNS
from check_port import CheckPort

# class CallData
#
# It stores information extracted from the SIP message.

class CallData():
    
    INVITE_IP = "" # Corresponds to the first line of a INVITE message
    INVITE_Port = ""
    INVITE_Transport = ""
    INVITE_Extension = ""
    
    To_IP = ""
    To_Extension = ""
    
    From_IP = ""
    From_Extension = ""
    
    Contact_IP = ""
    Contact_Port = ""
    Contact_Transport = ""
    Contact_Extension = ""
    
    Via = []
    
    Record_Route = ""
    
    Connection = ""
    Owner = ""

    UserAgent = ""
    
    def __init__(self):

        self.Via = []
        
        
# class Classifier
#
# This class performs the classification of the received SIP message.

class Classifier(PrintClass, log, CallData):
    
    VERSION = "" # Artemisa's version
    
    verbose = False # Flag to know whether the verbose mode is set or not
    
    strLocal_IP = ""
    strLocal_port = ""
    
    Extensions = [] # Extensions registered by Artemisa
    
    SIP_Message = "" # Stores the SIP message to classify (usually the INVITE)
    
    bACKReceived = False
    bMediaReceived = False
    
    Behaviour = ""
    Behaviour_actions = []
    
    Classification = [] # Stores the classification of the message
    
    # Information:
    ToolName = "" # Flag to store the attack tool detected

    Results_file = ""
    
    Running = True # State of the analysis

    def __init__(self):
        self.Running = True
        self.Classification = []
        CallData.__init__(self)
        
        
    # def Start
    #
    # This function starts the process. 
    
    def Start(self):

        self.GetCallData() # Retrieves all the necessary data from the message for further analysis

        # Defines a file name to store the output. The idea is to make a txt file with the same output
        # of the screen and then use it to build the HTML report.
        
        strFilename = ""
        try:
            a = 0
            while 1:
                        
                strFilename = "./results/" + strftime("%Y-%m-%d") + "_" + str(a) 
                        
                if os.path.isfile(strFilename + ".txt") == True:
                    a += 1
                else:
                    break
        except:
            pass
        
        self.Results_file = strFilename
        
        self.Print("")
        #self.Print("===================================================================",True,self.Results_file)
        #self.Print("| Information about the call                                      |",True,self.Results_file)
        #self.Print("===================================================================",True,self.Results_file)

        self.Print("******************************* Information about the call *******************************",True,self.Results_file)
        self.Print("",True,self.Results_file)
        
        self.Print("From: " + self.From_Extension + " in " + self.From_IP,True,self.Results_file)
        self.Print("To: "  + self.To_Extension + " in " + self.To_IP,True,self.Results_file)
        self.Print("Contact: "  + self.Contact_Extension + " in " + self.Contact_IP + ":" + self.Contact_Port + "/" + self.Contact_Transport,True,self.Results_file)
        self.Print("Connection: " + self.Connection,True,self.Results_file)
        self.Print("Owner: " + self.Owner,True,self.Results_file)
        
        for i in range(len(self.Via)):
            self.Print("Via " + str(i) + ": " + self.Via[i][0] + ":" + self.Via[i][1] + "/" + self.Via[i][2],True,self.Results_file)
            
        self.Print(self.UserAgent,True,self.Results_file)

        self.Print("",True,self.Results_file)

        #self.Print("===================================================================",True,self.Results_file)
        #self.Print("| Classification                                                  |",True,self.Results_file)
        #self.Print("===================================================================",True,self.Results_file)
        
        self.Print("************************************* Classification *************************************",True,self.Results_file)
        self.Print("",True,self.Results_file)
                
        # ---------------------------------------------------------------------------------
        # Check fingerprint
        # ---------------------------------------------------------------------------------
        
        self.Print("+ Checking fingerprint...",True,self.Results_file)
        self.Print("|",True,self.Results_file)
        self.Print("| " + self.UserAgent,True,self.Results_file)
        
        self.ToolName = CheckFingerprint(self.UserAgent)
        if self.ToolName < 0:
            self.Print("|",True,self.Results_file)
            self.Print("| Fingerprint check failed.",True,self.Results_file)
        elif self.ToolName == 0:
            self.Print("|",True,self.Results_file)
            self.Print("| No fingerprint found.",True,self.Results_file)
        else:
            self.Print("|",True,self.Results_file)
            self.Print("| Fingerprint found. The following attack tool was employed: " + self.ToolName,True,self.Results_file)
            self.Print("|",True,self.Results_file)            
            self.Print("| Category: Attack tool",True,self.Results_file)
            self.AddCategory("Attack tool")
        
        self.Print("",True,self.Results_file)
        
        # ---------------------------------------------------------------------------------
        # Check DNS
        # ---------------------------------------------------------------------------------
        
        self.Print("+ Checking DNS...",True,self.Results_file)
        
        ip_to_analyze = [] # IPs that will be analyzed
                
        ip_to_analyze.append(self.From_IP)
        if ip_to_analyze.count(self.Contact_IP) == 0: ip_to_analyze.append(self.Contact_IP) # This is to avoid having repeated IPs
        if ip_to_analyze.count(self.Connection) == 0: ip_to_analyze.append(self.Connection)
        if ip_to_analyze.count(self.Owner) == 0: ip_to_analyze.append(self.Owner)
        
        for i in range(len(self.Via)):
                if ip_to_analyze.count(self.Via[i][0]) == 0: ip_to_analyze.append(self.Via[i][0])
       
        
        # Analyze each IP address 
       
        for i in range(len(ip_to_analyze)):
            self.Print("|",True,self.Results_file)
            self.Print("| + Checking " + ip_to_analyze[i] + "...",True,self.Results_file)
            self.Print("| |",True,self.Results_file)   
            DNS_Result = CheckDNS(ip_to_analyze[i], self.verbose)
            if DNS_Result <= 0:
                self.Print("| | IP cannot be resolved.",True,self.Results_file)
                self.Print("| |",True,self.Results_file)
                self.Print("| | Category: Spoofed message",True,self.Results_file)
                self.AddCategory("Spoofed message")
            else:
                if (DNS_Result.find("WHOIS data not found") != -1 or DNS_Result.find("none") != -1) and DNS_Result.find("not DNS") == -1:
                    DNS_Result = DNS_Result.splitlines()
                    for line in DNS_Result:
                        self.Print("| | " + line,True,self.Results_file) 
                    self.Print("| |",True,self.Results_file)
                    self.Print("| | Category: Spoofed message",True,self.Results_file)
                    self.AddCategory("Spoofed message")
                elif DNS_Result.find("not DNS") != -1:
                    self.Print("| | This is already an IP address. Nothing done.",True,self.Results_file)
                else:
                    DNS_Result = DNS_Result.splitlines()
                    for line in DNS_Result:
                        self.Print("| | " + line,True,self.Results_file) 
                    self.Print("| |",True,self.Results_file)
                    self.Print("| | Category: Interactive attack",True,self.Results_file)
                    self.AddCategory("Interactive attack")
    
        self.Print("",True,self.Results_file)

        # ---------------------------------------------------------------------------------
        # Check if SIP ports are opened
        # ---------------------------------------------------------------------------------

        self.Print("+ Checking if SIP port is opened...",True,self.Results_file)

        self.Print("|",True,self.Results_file)
        self.Print("| + Checking " + self.Contact_IP + ":" + self.Contact_Port + "/" + self.Contact_Transport + "...",True,self.Results_file)
        self.Print("| |",True,self.Results_file)   
            
        strResult = CheckPort(self.Contact_IP, self.Contact_Port, self.Contact_Transport, self.verbose)
            
        if strResult == 0 or strResult < 0:
            self.Print("| | Error while scanning the port.",True,self.Results_file)
            self.Print("| |",True,self.Results_file)
            self.Print("| | Category: -",True,self.Results_file)
        else:
            if strResult.find("closed") != -1:
                strResult = strResult.splitlines()
                for line in strResult:
                    self.Print("| | " + line,True,self.Results_file)  
                #self.Print("| | Result: Port closed",True,self.Results_file) 
                self.Print("| |",True,self.Results_file)
                self.Print("| | Category: Spoofed message",True,self.Results_file)
                self.AddCategory("Spoofed message")
            else:
                strResult = strResult.splitlines()
                for line in strResult:
                    self.Print("| | " + line,True,self.Results_file)
                #self.Print("| | Result: Port opened",True,self.Results_file) 
                self.Print("| |",True,self.Results_file)
                self.Print("| | Category: Interactive attack",True,self.Results_file)
                self.AddCategory("Interactive attack")
                
        self.Print("",True,self.Results_file)

        # ---------------------------------------------------------------------------------
        # Check if media ports are opened
        # ---------------------------------------------------------------------------------

        self.Print("+ Checking if media port is opened...",True,self.Results_file)

        # FIXME: this parsing could be improved
        strRTPPort = GetSIPHeader("m=audio", self.SIP_Message)
        
        if strRTPPort == "": # Could happen that no RTP was delivered
            self.Print("|",True,self.Results_file) 
            self.Print("| No RTP info delivered.",True,self.Results_file)
            self.Print("|",True,self.Results_file)
            self.Print("| Category: Spoofed message",True,self.Results_file)
            self.AddCategory("Spoofed message")
        else:
            strRTPPort = strRTPPort.split(" ")[1]

            self.Print("|",True,self.Results_file)
            self.Print("| + Checking " + self.Contact_IP + ":" + strRTPPort + "/" + "udp" + "...",True,self.Results_file)
            self.Print("| |",True,self.Results_file)   
                
            strResult = CheckPort(self.Contact_IP, strRTPPort, "udp", self.verbose)
                
            if strResult == 0 or strResult < 0:
                self.Print("| | Error while scanning the port.",True,self.Results_file)
                self.Print("| |",True,self.Results_file)
                self.Print("| | Category: -",True,self.Results_file)
            else:
                if strResult.find("closed") != -1:
                    strResult = strResult.splitlines()
                    for line in strResult:
                        self.Print("| | " + line,True,self.Results_file)   
                    #self.Print("| | Result: Port closed",True,self.Results_file) 
                    self.Print("| |",True,self.Results_file)
                    self.Print("| | Category: Spoofed message",True,self.Results_file)
                    self.AddCategory("Spoofed message")
                else:
                    strResult = strResult.splitlines()
                    for line in strResult:
                        self.Print("| | " + line,True,self.Results_file)  
                    #self.Print("| | Result: Port opened",True,self.Results_file) 
                    self.Print("| |",True,self.Results_file)
                    self.Print("| | Category: Interactive attack",True,self.Results_file)
                    self.AddCategory("Interactive attack")
                
        self.Print("",True,self.Results_file)

        # ---------------------------------------------------------------------------------
        # Check request URI
        # ---------------------------------------------------------------------------------

        bRequestURI = False # Flag to know if this test gives a positive or negative result

        self.Print("+ Checking request URI...",True,self.Results_file)
        self.Print("|",True,self.Results_file)
        self.Print("| Extension in field To: " + self.To_Extension,True,self.Results_file)
        self.Print("|",True,self.Results_file)
        
        # Now it checks if the extension contained in the "To" field is one of the honeypot's registered
        # extesions.
        bFound = False
        for i in range(len(self.Extensions)):
            if str(self.Extensions[i].Extension) == self.To_Extension:
                # The extension contained in the "To" field is an extension of the honeypot.
                bFound = True
                self.Print("| Request addressed to the honeypot? Yes",True,self.Results_file)
                bRequestURI = True
                break
                
        if bFound == False:
            self.Print("| Request addressed to the honeypot? No",True,self.Results_file)
            bRequestURI = False

        self.Print("",True,self.Results_file)

        # ---------------------------------------------------------------------------------
        # Check if proxy in Via
        # ---------------------------------------------------------------------------------

        # This entire tests depends on the result of the previous
        if bRequestURI == False:

            # Via[0] is the first Via field, so that it has the IP of the last proxy.
            
            self.Print("+ Checking if proxy in Via...",True,self.Results_file)
            self.Print("|",True,self.Results_file)
            self.Print("| + Checking " + self.Via[0][0] + ":" + self.Via[0][1] + "/" + self.Via[0][2] + "...",True,self.Results_file)
            self.Print("| |",True,self.Results_file)   
    
            # We determine the existence of the proxy by checking the port with nmap
            strResult = CheckPort(self.Via[0][0], self.Via[0][1], self.Via[0][2], self.verbose)
                
            if strResult == 0 or strResult < 0:
                self.Print("| | Error while scanning.",True,self.Results_file)
                self.Print("| |",True,self.Results_file)
                self.Print("| | Category: -",True,self.Results_file)
            else:
                if strResult.find("closed") != -1: 
                    self.Print("| | Result: There is no SIP proxy",True,self.Results_file) 
                    self.Print("| |",True,self.Results_file)
                    self.Print("| | Category: DialPlan fault",True,self.Results_file)
                    self.AddCategory("DialPlan fault")
                else:
                    self.Print("| | Result: There is a SIP proxy",True,self.Results_file) 
                    self.Print("| |",True,self.Results_file)
                    self.Print("| | Category: Direct attack",True,self.Results_file)
                    self.AddCategory("Direct attack")
        
            self.Print("",True,self.Results_file)

        # ---------------------------------------------------------------------------------
        # Check for ACK
        # ---------------------------------------------------------------------------------
        
        self.Print("+ Checking for ACK...",True,self.Results_file)
        self.Print("|",True,self.Results_file)
        
        if self.bACKReceived == True:
            self.Print("| ACK received: Yes",True,self.Results_file)
        else:
            self.Print("| ACK received: No",True,self.Results_file)
            self.Print("|",True,self.Results_file)
            self.Print("| Category: Scanning",True,self.Results_file)
            self.AddCategory("Scanning")

        self.Print("",True,self.Results_file)

        # ---------------------------------------------------------------------------------
        # Check received media
        # ---------------------------------------------------------------------------------

        self.Print("+ Checking for received media...",True,self.Results_file)
        self.Print("|",True,self.Results_file)
        
        if self.bMediaReceived == True:
            self.Print("| Media received: Yes",True,self.Results_file)
            self.Print("|",True,self.Results_file)
            self.Print("| Category: SPIT",True,self.Results_file)
            self.AddCategory("SPIT")
        else:
            self.Print("| Media received: No",True,self.Results_file)
            self.Print("|",True,self.Results_file)
            self.Print("| Category: Ringing",True,self.Results_file)
            self.AddCategory("Ringing")       

        self.Print("",True,self.Results_file)

        self.Running = False
        
        return


    # def GetCallData
    #
    # This function extracts information from the SIP message.
    
    def GetCallData(self):
        
        self.INVITE_IP = GetIPfromSIP(GetSIPHeader("INVITE",self.SIP_Message))
        self.INVITE_Port = GetPortfromSIP(GetSIPHeader("INVITE",self.SIP_Message))
        if self.INVITE_Port == "": self.INVITE_Port = "5060" # By default
        self.INVITE_Extension = GetExtensionfromSIP(GetSIPHeader("INVITE",self.SIP_Message))
        if GetSIPHeader("INVITE",self.SIP_Message).find("udp") != -1 or GetSIPHeader("INVITE",self.SIP_Message).find("UDP") != -1: 
            self.INVITE_Transport = "udp"
        elif GetSIPHeader("INVITE",self.SIP_Message).find("tcp") != -1 or GetSIPHeader("INVITE",self.SIP_Message).find("TCP") != -1:
            self.INVITE_Transport = "tcp"
        else:
            self.INVITE_Transport = "udp" # By default
            
        self.To_IP = GetIPfromSIP(GetSIPHeader("To",self.SIP_Message))
        self.To_Extension = GetExtensionfromSIP(GetSIPHeader("To",self.SIP_Message))
        
        self.From_IP = GetIPfromSIP(GetSIPHeader("From",self.SIP_Message))
        self.From_Extension = GetExtensionfromSIP(GetSIPHeader("From",self.SIP_Message))
        
        self.Contact_IP = GetIPfromSIP(GetSIPHeader("Contact",self.SIP_Message))
        self.Contact_Port = GetPortfromSIP(GetSIPHeader("Contact",self.SIP_Message))
        if self.Contact_Port == "": self.Contact_Port = "5060" # By default
        self.Contact_Extension = GetExtensionfromSIP(GetSIPHeader("Contact",self.SIP_Message))
        if GetSIPHeader("Contact",self.SIP_Message).find("udp") != -1 or GetSIPHeader("Contact",self.SIP_Message).find("UDP") != -1: 
            self.Contact_Transport = "udp"
        elif GetSIPHeader("Contact",self.SIP_Message).find("tcp") != -1 or GetSIPHeader("Contact",self.SIP_Message).find("TCP") != -1:
            self.Contact_Transport = "tcp"
        else:
            self.Contact_Transport = "udp" # By default
            
        self.Connection = GetIPfromSIP(GetSIPHeader("c=",self.SIP_Message))
        self.Owner = GetIPfromSIP(GetSIPHeader("c=",self.SIP_Message))

        self.UserAgent = GetSIPHeader("User-Agent",self.SIP_Message)
    
        #self.Record_Route = GetSIPHeader("Record-Route",self.SIP_Message)
        
        strTemp = self.SIP_Message.splitlines()
    
        for line in strTemp:
            if line[0:4] == "Via:":
                if line.find("UDP") != -1 or line.find("udp") != -1:
                    strTransport = "udp"
                elif line.find("TCP") != -1 or line.find("tcp") != -1:
                    strTransport = "tcp"
                else:
                    strTransport = "other" #FIXME: this should be changed
                                    
                self.Via.append([GetIPfromSIP(line.strip()), GetPortfromSIP(line.strip()), strTransport])
        
        
    # def AddCategory
    
    def AddCategory(self, strCategory):
        
        bFound = False
        
        for i in range(len(self.Classification)):
            if self.Classification[i] == strCategory:
                bFound = True
                break

        if bFound == True: return

        self.Classification.append(strCategory)

    
