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

        self.Print("")
        self.Print("===================================================================")
        self.Print("| Information about the call                                      |")
        self.Print("===================================================================")
        self.Print("")
        self.Print("From: " + self.From_Extension + " in " + self.From_IP)
        self.Print("To: "  + self.To_Extension + " in " + self.To_IP)
        self.Print("Contact: "  + self.Contact_Extension + " in " + self.Contact_IP + ":" + self.Contact_Port + "/" + self.Contact_Transport)
        self.Print("Connection: " + self.Connection)
        self.Print("Owner: " + self.Owner)
        
        for i in range(len(self.Via)):
            self.Print("Via " + str(i) + ": " + self.Via[i][0] + ":" + self.Via[i][1] + "/" + self.Via[i][2])
            
        self.Print(self.UserAgent)
        self.Print("")

        self.Print("===================================================================")
        self.Print("| Information about the classification                            |")
        self.Print("===================================================================")
        self.Print("")
                
        # ---------------------------------------------------------------------------------
        # Check fingerprint
        # ---------------------------------------------------------------------------------
        
        self.Print("+ Checking fingerprint...")
        self.Print("|")
        self.Print("| " + self.UserAgent)
        
        ToolName = CheckFingerprint(self.UserAgent)
        if ToolName < 0:
            self.Print("|")
            self.Print("| Fingerprint check failed.")
            self.Print("")
        elif ToolName == 0:
            self.Print("|")
            self.Print("| No fingerprint found.")
            self.Print("")
        else:
            self.Print("|")
            self.Print("| Fingerprint found. The following attack tool was employed: " + ToolName)
            self.Print("|")            
            self.Print("| Category: Attack tool")
            self.Print("")
            self.AddCategory("Attack tool")
        
        
        # ---------------------------------------------------------------------------------
        # Check DNS
        # ---------------------------------------------------------------------------------
        
        self.Print("+ Checking DNS...")
        
        ip_to_analyze = [] # IPs that will be analyzed
                
        ip_to_analyze.append(self.From_IP)
        if ip_to_analyze.count(self.Contact_IP) == 0: ip_to_analyze.append(self.Contact_IP) # This is to avoid having repeated IPs
        if ip_to_analyze.count(self.Connection) == 0: ip_to_analyze.append(self.Connection)
        if ip_to_analyze.count(self.Owner) == 0: ip_to_analyze.append(self.Owner)
        
        for i in range(len(self.Via)):
                if ip_to_analyze.count(self.Via[i][0]) == 0: ip_to_analyze.append(self.Via[i][0])
       
        
        # Analyze each IP address 
       
        for i in range(len(ip_to_analyze)):
            self.Print("|")
            self.Print("| + Checking " + ip_to_analyze[i] + "...")
            self.Print("| |")   
            DNS_Result = CheckDNS(ip_to_analyze[i])
            if DNS_Result == 0 or DNS_Result < 0:
                self.Print("| | DNS/IP cannot be resolved.")
                self.Print("| |")
                self.Print("| | Category: Spoofed message")
                self.AddCategory("Spoofed message")
            else:
                self.Print("| | " + DNS_Result) 
                self.Print("| |")
                self.Print("| | Category: Interactive attack")
                self.AddCategory("Interactive attack")
    
        self.Print("")

        # ---------------------------------------------------------------------------------
        # Check if SIP ports are opened
        # ---------------------------------------------------------------------------------

        self.Print("+ Checking if SIP port is opened...")

        self.Print("|")
        self.Print("| + Checking " + self.Contact_IP + ":" + self.Contact_Port + "/" + self.Contact_Transport + "...")
        self.Print("| |")   
            
        strResult = CheckPort(self.Contact_IP, self.Contact_Port, self.Contact_Transport)
            
        if strResult == 0 or strResult < 0:
            self.Print("| | Error while scanning the port.")
            self.Print("| |")
            self.Print("| | Category: -")
            self.Print("")
        else:
            if strResult.find("closed") != -1: 
                self.Print("| | Result: Port closed") 
                self.Print("| |")
                self.Print("| | Category: Spoofed message")
                self.Print("")
                self.AddCategory("Spoofed message")
            else:
                self.Print("| | Result: Port opened") 
                self.Print("| |")
                self.Print("| | Category: Interactive attack")
                self.Print("")
                self.AddCategory("Interactive attack")

        # ---------------------------------------------------------------------------------
        # Check if media ports are opened
        # ---------------------------------------------------------------------------------

        self.Print("+ Checking if media port is opened...")

        # FIXME: this parsing could be improved
        strRTPPort = GetSIPHeader("m=audio", self.Message)
        
        if strRTPPort == "": # Could happen that no RTP was delivered
            self.Print("|") 
            self.Print("| No RTP info delivered.")
            self.Print("|")
            self.Print("| Category: Spoofed message")
            self.Print("")
            self.AddCategory("Spoofed message")
        else:
            strRTPPort = strRTPPort.split(" ")[1]

            self.Print("|")
            self.Print("| + Checking " + self.INVITE_IP + ":" + strRTPPort + "/" + "udp" + "...")
            self.Print("| |")   
                
            strResult = CheckPort(self.INVITE_IP, strRTPPort, "udp")
                
            if strResult == 0 or strResult < 0:
                self.Print("| | Error while scanning the port.")
                self.Print("| |")
                self.Print("| | Category: -")
                self.Print("")
            else:
                if strResult.find("closed") != -1: 
                    self.Print("| | Result: Port closed") 
                    self.Print("| |")
                    self.Print("| | Category: Spoofed message")
                    self.Print("")
                    self.AddCategory("Spoofed message")
                else:
                    self.Print("| | Result: Port opened") 
                    self.Print("| |")
                    self.Print("| | Category: Interactive attack")
                    self.Print("")
                    self.AddCategory("Interactive attack")
                

        # ---------------------------------------------------------------------------------
        # Check request URI
        # ---------------------------------------------------------------------------------

        bRequestURI = False # Flag to know if this test gives a positive or negative result

        self.Print("+ Checking request URI...")
        self.Print("|")
        self.Print("| Extension in field To: " + self.To_Extension)
        self.Print("|")
        
        # Now it checks if the extension contained in the "To" field is one of the honeypot's registered
        # extesions.
        bFound = False
        for i in range(len(self.Extensions)):
            if str(self.Extensions[i].Extension) == self.To_Extension:
                # The extension contained in the "To" field is an extension of the honeypot.
                bFound = True
                self.Print("| Request addressed to the honeypot? Yes")
                self.Print("")
                bRequestURI = True
                break
                
        if bFound == False:
            self.Print("| Request addressed to the honeypot? No")
            self.Print("")
            bRequestURI = False

        # ---------------------------------------------------------------------------------
        # Check if proxy in Via
        # ---------------------------------------------------------------------------------

        # This entire tests depends on the result of the previous
        if bRequestURI == False:

            # Via[0] is the first Via field, so that it has the IP of the last proxy.
            
            self.Print("+ Checking if proxy in Via...")
            self.Print("|")
            self.Print("| + Checking " + self.Via[0][0] + ":" + self.Via[0][1] + "/" + self.Via[0][2] + "...")
            self.Print("| |")   
    
            # We determine the existence of the proxy by checking the port with nmap
            strResult = CheckPort(self.Via[0][0], self.Via[0][1], self.Via[0][2])
                
            if strResult == 0 or strResult < 0:
                self.Print("| | Error while scanning.")
                self.Print("| |")
                self.Print("| | Category: -")
                self.Print("")
            else:
                if strResult.find("closed") != -1: 
                    self.Print("| | Result: There is no SIP proxy") 
                    self.Print("| |")
                    self.Print("| | Category: DialPlan fault")
                    self.Print("")
                    self.AddCategory("DialPlan fault")
                else:
                    self.Print("| | Result: There is a SIP proxy") 
                    self.Print("| |")
                    self.Print("| | Category: Direct attack")
                    self.Print("")
                    self.AddCategory("Direct attack")
        

        # ---------------------------------------------------------------------------------
        # Check for ACK
        # ---------------------------------------------------------------------------------
        
        self.Print("+ Checking for ACK...")
        self.Print("|")
        
        if self.bACKReceived == True:
            self.Print("| ACK received: Yes")
            self.Print("")
        else:
            self.Print("| ACK received: No")
            self.Print("|")
            self.Print("| Category: Scanning")
            self.Print("")
            self.AddCategory("Scanning")

        # ---------------------------------------------------------------------------------
        # Check received media
        # ---------------------------------------------------------------------------------

        self.Print("+ Checking for received media...")
        self.Print("|")
        
        if self.bMediaReceived == True:
            self.Print("| Media received: Yes")
            self.Print("|")
            self.Print("| Category: SPIT")
            self.Print("")
            self.AddCategory("SPIT")
        else:
            self.Print("| Media received: No")
            self.Print("|")
            self.Print("| Category: Ringing")
            self.Print("")
            self.AddCategory("Ringing")       


        self.Running = False
        
        return


    # def GetCallData
    #
    # This function extracts information from the SIP message.
    
    def GetCallData(self):
        
        self.INVITE_IP = GetIPfromSIP(GetSIPHeader("INVITE",self.Message))
        self.INVITE_Port = GetPortfromSIP(GetSIPHeader("INVITE",self.Message))
        if self.INVITE_Port == "": self.INVITE_Port = "5060" # By default
        self.INVITE_Extension = GetExtensionfromSIP(GetSIPHeader("INVITE",self.Message))
        if GetSIPHeader("INVITE",self.Message).find("udp") != -1 or GetSIPHeader("INVITE",self.Message).find("UDP") != -1: 
            self.INVITE_Transport = "udp"
        elif GetSIPHeader("INVITE",self.Message).find("tcp") != -1 or GetSIPHeader("INVITE",self.Message).find("TCP") != -1:
            self.INVITE_Transport = "tcp"
        else:
            self.INVITE_Transport = "udp" # By default
            
        self.To_IP = GetIPfromSIP(GetSIPHeader("To",self.Message))
        self.To_Extension = GetExtensionfromSIP(GetSIPHeader("To",self.Message))
        
        self.From_IP = GetIPfromSIP(GetSIPHeader("From",self.Message))
        self.From_Extension = GetExtensionfromSIP(GetSIPHeader("From",self.Message))
        
        self.Contact_IP = GetIPfromSIP(GetSIPHeader("Contact",self.Message))
        self.Contact_Port = GetPortfromSIP(GetSIPHeader("Contact",self.Message))
        if self.Contact_Port == "": self.Contact_Port = "5060" # By default
        self.Contact_Extension = GetExtensionfromSIP(GetSIPHeader("Contact",self.Message))
        if GetSIPHeader("Contact",self.Message).find("udp") != -1 or GetSIPHeader("Contact",self.Message).find("UDP") != -1: 
            self.Contact_Transport = "udp"
        elif GetSIPHeader("Contact",self.Message).find("tcp") != -1 or GetSIPHeader("Contact",self.Message).find("TCP") != -1:
            self.Contact_Transport = "tcp"
        else:
            self.Contact_Transport = "udp" # By default
            
        self.Connection = GetIPfromSIP(GetSIPHeader("c=",self.Message))
        self.Owner = GetIPfromSIP(GetSIPHeader("c=",self.Message))

        self.UserAgent = GetSIPHeader("User-Agent",self.Message)
    
        #self.Record_Route = GetSIPHeader("Record-Route",self.Message)
        
        strTemp = self.Message.splitlines()
    
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

    
    # def IfCategory
    #
    # Returns whether a category is found or not
    
    def IfCategory(self, strCategory):

        bFound = False
        
        for i in range(len(self.Classification)):
            if self.Classification[i] == strCategory:
                bFound = True
                break

        if bFound == True: 
            return True
        else:
            return False