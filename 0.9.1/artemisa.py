#!/usr/bin/env python
# -*- coding: UTF-8 -*-

# Artemisa v1.0
# Copyright (C) 2009 Rodrigo do Carmo <rodrigodocarmo@gmail.com> 
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

import sys
from socket import socket, AF_INET, SOCK_DGRAM
import ConfigParser # Read configuration files
import hashlib  # MD5
import random # Random numbers generation
from time import strftime
from logs import Log, TrafficLog, InviteLog # Import functions from logs.py
from commons import GetTime, Search, GetSIPHeader # Import functions from commons.py
from inference import InferenceAnalysis # Inference engine (core of the honeypot)
import threading    # Use of threads

# Variables

strLocal_IP = ""                # Local IP
strLocal_port = ""              # Local port
strRegistrar_IP = ""            # Registrar server IP (Asterisk, SER, etc.)
strRegistrar_port = ""          # Registrar server port
verbose = False
Sessions = []

Extensions = [] # Store the extensions registered to the SIP server in order to pass them to the inference engine

# Constants

intBuffer = 1024




# class Session
#
# Object created in order to keep the user data which an unique extension and related with one profile

class Session():

    Extension = ""
    Username = ""
    Password = ""

    Header_Register = ""            # Store the SIP header of REGISTER message
    Header_Register_auth = ""       # Same with credentials
    Header_Options_ok = ""          # Same for OPTIONS message
    
    Branch = ""
    BranchNum = 0
    MaxForwards = ""
    Tag = ""
    TagNum = 0
    CallID = ""
    CallIDNum = 0
    CSeq = 0
    Nonce = ""               
    Realm = ""
    Response = ""
    
    def GetProfile(self,strFile):
  
        global strLocal_IP
        global strLocal_port
        global strRegistrar_IP
        global strRegistrar_port
    
        reading_register = False # Flag to know which part is being read
        reading_register_auth = False # Same
        reading_options_ok = False # Same
        
        f = open("./profiles/" + strFile, "r")
                
        for line in f:

            if line.find("}") != -1:
                reading_register = False
                reading_register_auth = False
                
            # Each variable must be replaced by its value
            # Python has a method to replace strings!!!
            line = line.replace("$registrar_ip$", strRegistrar_IP)
            line = line.replace("$registrar_port$", strRegistrar_port)
            line = line.replace("$local_ip$", strLocal_IP)
            line = line.replace("$local_port$", strLocal_port)
            line = line.replace("$user$", self.Username)
            line = line.replace("$extension$", self.Extension)

            if reading_register == True:
                self.Header_Register += line.strip() + "\r\n"

            if reading_register_auth == True:
                self.Header_Register_auth += line.strip() + "\r\n" 

            if reading_options_ok == True:
                self.Header_Options_ok += line.strip() + "\r\n"
                           
            if line[0:7] == "branch=":
                self.BranchNum = int(line.partition("=")[2])
                # The 7 first characters of the branch value must be z9hG4bK as is specified in the RFC 3261
                self.Branch = "z9hG4bK" +  hashlib.md5(str(random.randint(10000,99999)) + strLocal_IP + "SIP/2.0" + strRegistrar_IP + self.Username).hexdigest()[0:self.BranchNum]
            if line[0:4] == "tag=":
                self.TagNum = int(line.partition("=")[2])
                self.Tag = GenerateRandomString()[0:self.TagNum]
            if line[0:8] == "call-id=":
                self.CallIDNum = int(line.partition("=")[2])
                self.CallID = GenerateRandomString()[0:self.CallIDNum] 
            if line[0:5] == "cseq=":
                self.CSeq = int(line.partition("=")[2])
            
            if line.find("register{") <> -1:
                reading_register = True
                reading_register_auth = False
                reading_options_ok = False
                
            if line.find("register_auth{") <> -1:
                reading_register = False
                reading_register_auth = True   
                reading_options_ok = False
                
            if line.find("options_ok{") <> -1:
                reading_register = False
                reading_register_auth = False
                reading_options_ok = True
        
        f.close()
                
    

        

# class thrLeerSocket
#
# Object thread witch receive data from socket

class thrSocket(threading.Thread):
    
    global intBuffer
    
    def __init__(self):
        
        threading.Thread.__init__(self)
        
        self.Stop = False # Flag to stop the thread when neccesary
        
    def run(self):
        
        while not self.Stop:
            strData,(strRecServer,intRecPort) = UDPSock.recvfrom(intBuffer)
            
            TrafficLog(strData)

            # The content of the packet is analyzed
            
            if strData.find("401 Unauthorized") != -1:
                AnswerUnauthorized(strData)
                
            if GetSIPHeader("CSeq",strData).find("OPTIONS") != -1:
                AnswerOPTIONS(strData)  

            if GetSIPHeader("CSeq",strData).find("INVITE") != -1:
                InviteLog(strData)
                AnalyzeINVITE(strData)

            if strData.find("200 OK") != -1:
                AnalyzeOK(strData)              
            
# def LoadConfiguration
#
# Load configurations from file artemisa.conf

def LoadConfiguration():
    
    global strLocal_IP
    global strLocal_port
    global strRegistrar_IP
    global strRegistrar_port
    global Sessions
    
    config = ConfigParser.ConfigParser()
    strTemp = config.read("./artemisa.conf")
    
    if strTemp == []:
        print GetTime() + " CRITICAL The configuration file artemisa.conf cannot be read."
        Log("CRITICAL The configuration file artemisa.conf cannot be read.")
        sys.exit(0)
    else:
        #try:
        strLocal_IP = config.get("environment", "local_ip")
        strLocal_port = config.get("environment", "local_port")
        strRegistrar_IP = config.get("environment", "registrar_ip")
        strRegistrar_port = config.get("environment", "registrar_port")
                        
        # Now it reads each user stored in the file and generates a Session object for each one,
        # and they have at the same time a Profile object wich the profile settings        
                
        for item in config.sections():
            if item <> "environment":
                Sessions.append(Session())
                Sessions[len(Sessions)-1].Extension = item
                Sessions[len(Sessions)-1].Username = config.get(item, "username")
                Sessions[len(Sessions)-1].Password = config.get(item, "password")
                Sessions[len(Sessions)-1].GetProfile(config.get(item, "profile"))           
            
        #except:
            #print "The configuration file cannot be correctly read. Check it out carefully."
            #sys.exit(0)

    del config


# def Register
#
# This function registers the honeypot at the SIP server

def Register():

    global strRegistrar_IP
    global strRegistrar_port
    global Sessions
    
    # Initialize the socket
    UDPSock2 = socket(AF_INET, SOCK_DGRAM)
    
    for i in range(len(Sessions)):
        Extensions.append(Sessions[i].Extension)
        strDataToSend = Sessions[i].Header_Register.replace("$cseq$", str(Sessions[i].CSeq)) + "\r\n"
        strDataToSend = strDataToSend.replace("$tag$", Sessions[i].Tag) + "\r\n"
        strDataToSend = strDataToSend.replace("$branch$", Sessions[i].Branch) + "\r\n"
        strDataToSend = strDataToSend.replace("$call-id$", Sessions[i].CallID) + "\r\n"
        UDPSock2.sendto(strDataToSend,(strRegistrar_IP,int(strRegistrar_port)))
        TrafficLog(strDataToSend)
        print GetTime() + " NOTICE REGISTER request sent with extension " + Sessions[i].Extension + "..."
        Log("NOTICE REGISTER request sent with extension " + Sessions[i].Extension + "...")
        
    UDPSock2.close()
    
    # When the first REGISTRAR is sent, the answer is waited. An UNAUTHORIZED is expected with a
    # "nonce" code. If it is, the REGISTRAR is sent again with the authorization information.

    # UDPSock2 has been closed because the registrar server will send the data to the socket at 
    # port intPuerto
    
    

# def AnswerUnauthorized
#
# This function answers the message Unauthorized.

def AnswerUnauthorized(strData):    
    
    global strRegistrar_IP
    global strRegistrar_port
    global strLocal_IP
    global strLocal_port
    global UDPSock
    global Sessions
    
    bFound = False
    # The session is identified with the Tag
    strTag = GetSIPHeader("From",strData).partition("tag=")[len(GetSIPHeader("From",strData).partition("tag="))-1]
    for i in range(len(Sessions)):
        if strTag == Sessions[i].Tag:
            bFound = True
            break # The value contained in i is the session value
    if bFound == False:
        return
    
    print GetTime() + " NOTICE The server demands authorization for extension " + Sessions[i].Extension 
    Log( "NOTICE The server demands authorization for extension " + Sessions[i].Extension)
        
    # Get "realm" and "nonce", which are needed in order to make the hash and send the MD5 authentication back.
    
    Sessions[i].Realm = Search("realm",strData)
    Sessions[i].Nonce = Search("nonce",strData)
    
    # The hash to send is calculated. This technique is known as "digest".
    
    A1 = hashlib.md5(Sessions[i].Extension + ":" + Sessions[i].Realm  + ":" + Sessions[i].Password).hexdigest()
    A2 = hashlib.md5("REGISTER:sip:" + strRegistrar_IP).hexdigest()
    Sessions[i].Response = hashlib.md5(A1 + ":" + Sessions[i].Nonce + ":" + A2).hexdigest()
    
    Sessions[i].CSeq += 1 # Increase CSeq

    Sessions[i].Branch = "z9hG4bK" +  hashlib.md5(str(random.randint(10000,99999)) + strLocal_IP + "SIP/2.0" + strRegistrar_IP + Sessions[i].Username).hexdigest()[0:Sessions[i].BranchNum]

    Sessions[i].Header_Register_auth = Sessions[i].Header_Register_auth.replace("$realm$","\"" + Sessions[i].Realm + "\"")
    Sessions[i].Header_Register_auth = Sessions[i].Header_Register_auth.replace("$nonce$","\"" + Sessions[i].Nonce + "\"")
    Sessions[i].Header_Register_auth = Sessions[i].Header_Register_auth.replace("$response$","\"" + Sessions[i].Response + "\"")
 
    strDataToSend = Sessions[i].Header_Register_auth.replace("$cseq$", str(Sessions[i].CSeq)) + "\r\n"
    strDataToSend = strDataToSend.replace("$tag$", Sessions[i].Tag) + "\r\n"
    strDataToSend = strDataToSend.replace("$branch$", Sessions[i].Branch) + "\r\n"
    strDataToSend = strDataToSend.replace("$call-id$", Sessions[i].CallID) + "\r\n"
        
    Send(strDataToSend, (strRegistrar_IP,int(strRegistrar_port)))
    
    
    print GetTime() + " NOTICE Authorization sent for extension " + Sessions[i].Extension + "..."
    Log("NOTICE Authorization sent for extension " + Sessions[i].Extension + "...")
    
    
    
# def AnswerOPTIONS
#
# The server sends OPTIONS messages to the honeypot within some time. This function answers it.

def AnswerOPTIONS(strData):    
    
    global strRegistrar_IP
    global strRegistrar_port
    global strLocal_IP
    global strLocal_port
    global UDPSock
    global Sessions
    
    # The session is identified using the To label
    # To get it the Contact label must be analyzed
    bFound = False
    strExtension = GetSIPHeader("To",strData).partition("@")[0].partition(":")[2].partition(":")[2]
    for i in range(len(Sessions)):
        if strExtension == Sessions[i].Extension:
            bFound = True
            break # The value contained in i is the session value
    if bFound == False:
        return

    Log("NOTICE OPTIONS message received for extension " + Sessions[i].Extension)
        
    # Watch out!
    # TODO: Here the fields received y rport must still be added!
    
    strRecVia = GetSIPHeader("Via",strData)
    strRecTo = GetSIPHeader("To",strData)
    strTag = str(random.randint(10000,99999))
    strRecFrom = GetSIPHeader("From",strData)
    strRecCallID = GetSIPHeader("Call-ID",strData)
    strRecCSeq = GetSIPHeader("CSeq",strData)
    
    strDataToSend = Sessions[i].Header_Options_ok.replace("$cseq$", strRecCSeq) + "\r\n"
    strDataToSend = strDataToSend.replace("$from-options-received$", strRecFrom) + "\r\n"
    strDataToSend = strDataToSend.replace("$to-options-received$", strRecTo) + "\r\n"
    strDataToSend = strDataToSend.replace("$via-options-received$", strRecVia) + "\r\n"
    strDataToSend = strDataToSend.replace("$call-id-options-received$", strRecCallID) + "\r\n"
    strDataToSend = strDataToSend.replace("$tag$", strTag) + "\r\n"

    Send(strDataToSend, (strRegistrar_IP,int(strRegistrar_port)))
    
    Log("NOTICE An OPTIONS message was answered with an OK.")
    
    
    

# def AnalyzeOK
#
# Analyzes the OK messages.

def AnalyzeOK(strData):    
    
    global strRegistrar_IP
    global strRegistrar_port
    global strLocal_IP
    global strLocal_port
    global UDPSock
    global Sessions
    
    # The session is identified using the To label
    # To get it the Contact label must be analyzed
    bFound = False
    strExtension = GetSIPHeader("To",strData).partition("@")[0].partition(":")[2].partition(":")[2]
    for i in range(len(Sessions)):
        if strExtension == Sessions[i].Extension:
            bFound = True
            break # The value contained in i is the session value
    if bFound == False:
        return
        

    if GetSIPHeader("CSeq",strData).find("REGISTER") != -1:
        print GetTime() + " NOTICE Extension " + Sessions[i].Extension + " successfully registered."
        Log("NOTICE Extension " + Sessions[i].Extension + " successfully registered.")
    


# def AnalizeINVITE
#
# Core of the program. Here is where the honeypot concludes if the packet received is trusted or not.

def AnalyzeINVITE(strData):    

    global verbose
    
    print GetTime() + " NOTICE INVITE detected."
    Log(" NOTICE INVITE detected.")

    InferenceAnalysis(strData, verbose, Extensions)

    
    
# def GenerateRandomString
#
# Generate a random string.

def GenerateRandomString():

    temp = ""
    
    for item in range(100):
        # Two groups of possibilities are generated in order to include low and uppercase letters and
        # anything else. 

        if random.randint(0,1) == 0:
            randchr = random.randint(65,90)
        else:
            randchr = random.randint(97,122)
            
        temp = temp + chr(randchr)
    
    return temp

    
# def Send
#
# Send data to the socket.

def Send(strData, address):

    global UDPSock

    # Send data to the client.    
    UDPSock.sendto(strData,address)

    TrafficLog(strData)






# def EndConnection
#
# Well, it's not really a connection but a socket which is closed.

def EndConnection():

    global UDPSock

    # Finalize the socket
    try:
        UDPSock.close()
    except:
        pass
    
    
def main():

    global UDPSock
    global verbose
    
    print "Artemisa v0.9.1  Copyright (C) 2009 Rodrigo do Carmo and Pablo Masri"
    print ""
    print "This program comes with ABSOLUTELY NO WARRANTY; for details type `show warranty'."
    print "This is free software, and you are welcome to redistribute it under certain"
    print "conditions; type `show license' for details."
    print ""
    print ""
    print "Type \"help\" for help."
    print ""
    
    # Read the configuration file artemisa.conf
    LoadConfiguration()
    
    # Creates a socket socket and initializes it
    UDPSock = socket(AF_INET, SOCK_DGRAM)
    
    try:
        UDPSock.bind((strLocal_IP,int(strLocal_port)))
        
    except:
        print GetTime() + " CRITICAL Can't listen on port " + strLocal_port + ". Check if another program is using it!"
        sys.exit(0)
    
    
    Log("Honeypot started.")
    
    # A thread is initialized in order to receive data from the socket and analyze it
    thrSocket().start()

    print GetTime() + " Starting extensions registration process..."
    Log("Starting extensions registration process...")
    
    # The sessions defined in artemisa.conf are registered to the SIP server
    Register()
        
    # The keyboard is read:
    while True:
        
        s = raw_input("> ")
        
        if s == "help":
            print "Commands list:"
            print ""
            print "verbose on       Turn verbose mode on. It gives more information."
            print "verbose off      Turn verbose mode off."
            print ""
            print "show warranty    Shows the program warrany"
            print "show license     Shows the program license"
            print "s                Exit"
            print "quit             Exit"
            print "exit             Exit"
            print "q                Exit"
        
        if s.find("verbose") != -1 and s.find("on") != -1:

            verbose = True
            
        if s.find("verbose") != -1 and s.find("off") != -1:
            
            verbose = False
                        
        if s == "show warranty":
            print ""
            print "THERE IS NO WARRANTY FOR THE PROGRAM, TO THE EXTENT PERMITTED BY"
            print "APPLICABLE LAW.  EXCEPT WHEN OTHERWISE STATED IN WRITING THE COPYRIGHT"
            print "HOLDERS AND/OR OTHER PARTIES PROVIDE THE PROGRAM \"AS IS\" WITHOUT WARRANTY"
            print "OF ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING, BUT NOT LIMITED TO,"
            print "THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR"
            print "PURPOSE.  THE ENTIRE RISK AS TO THE QUALITY AND PERFORMANCE OF THE PROGRAM"
            print "IS WITH YOU.  SHOULD THE PROGRAM PROVE DEFECTIVE, YOU ASSUME THE COST OF"
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
            
        if s == "show license":
            print ""
            print "This program is free software: you can redistribute it and/or modify"
            print "it under the terms of the GNU General Public License as published by"
            print "the Free Software Foundation, either version 3 of the License, or"
            print "(at your option) any later version."
            print ""
            print "This program is distributed in the hope that it will be useful,"
            print "but WITHOUT ANY WARRANTY; without even the implied warranty of"
            print "MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the"
            print "GNU General Public License for more details."
            print ""
            print "You should have received a copy of the GNU General Public License"
            print "along with this program.  If not, see <http://www.gnu.org/licenses/>."
            print ""
            
        if s == "q" or s == "s" or s == "quit" or s == "exit":
            print ""
            print "Good bye!"
            print ""
            break
    
    thrSocket().Stop = True
    
    Log("Honeypot ended.")
       
    
    EndConnection()
    sys.exit(0)
    
try:
    main()
except KeyboardInterrupt:
    print ""
    print "Good bye!"
    print ""
    EndConnection()
    sys.exit(0)
    
    
