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


################################################################################################
# This is the inference engine and it's the core of the honeypot. Here is where the INVITE     #
# messages are carefully analysed, using tools and mathematical resources, and where the       #
# conclusion about the danger of the message is inferred.                                      #
#                                                                                              #
# The methods used in this part of the program are suggested in the IEEE paper "VoIP honeypot  #
# architecture" published in 2007 by Mohamed Nassar, Radu State and Oliver Festor.             #
#                                                                                              #
# Rodrigo do Carmo                                                                             #
# Pablo Masri                                                                                  #
# Blas Pascal University (www.ubp.edu.ar)                                                      #
# October 2009                                                                                 #
################################################################################################
 
import os
from time import strftime
from math import sqrt, pow
from subprocess import Popen, PIPE
from commons import PrintClass, GetSIPHeader, Search, GetTimeClass, GetIPfromSIP, GetExtensionfromSIP, RemoveComments, GetCPTmatrix
from modules.ip2country.ip2country import IP2Country # Downloaded from http://www.freenet.org.nz/python/ip2country/
from modules.IPy.IPy import *       # Module to deal with IPs
from logs import log                # Import class log from logs.py
import random                       # Random number generator
import ConfigParser                 # Read configuration files

from mail import Email


# class CallData
#
# Store information about the INVITE message.

class CallData():
    
    To_IP = ""
    To_Extension = ""
    
    From_IP = ""
    From_Extension = ""
    
    Contact_IP = ""
    Contact_Extension = ""
    
    Via = []
    
    Record_Route = ""
    
    Connection = ""
    Owner = ""

    UserAgent = ""
    
    def __init__(self):

        self.Via = []

    
    
class InferenceAnalysis(PrintClass, log, GetTimeClass, CallData):
    
    Message = ""
    verbose = False # Flag to know if the verbose mode is set
    Extensions = []
    Behaviour = ""
    Behaviour_actions = []
    
    Results = "" # Store results output information
    
    # Store results
    NormalProb = 0 
    SuspiciousProb = 0
    CraftedProb = 0
    MessageNature = ""

    verbose_results = "" 

    email = None
    
    lambda_to_parent_fingerprint = []
    
    # def Start
    #
    # This function starts the process. 
    #
    # It receives the SIP INVITE message detected, the verbose condition (True or False) and the
    # extensions registered to the SIP server by the honeypot.
    
    def Start(self):

        self.email = Email() # Creates an Email object.

        if self.Behaviour == "passive":
            self.send_results()
        
        if self.Behaviour_actions.count("investigate") == 0:
            return
        
        # ------------------------------------------------------------------------------------------------
        # CALL INVESTIGATION 
        # ------------------------------------------------------------------------------------------------

        self.Print("Performing call analysis... (this may take some minutes)")

        self.GetCallData() # Retrieves all the necessary data from the message

        self.add_results("")
        self.add_results("===================================================================")
        self.add_results("| Information about the call                                      |")
        self.add_results("===================================================================")
        self.add_results("")
        self.add_results("From: " + self.From_Extension + " in " + self.From_IP)
        self.add_results("To: "  + self.To_Extension + " in " + self.To_IP)
        self.add_results("Contact: "  + self.Contact_Extension + " in " + self.Contact_IP)
        self.add_results("Connection: " + self.Connection)
        self.add_results("Owner: " + self.Owner)
        
        for i in range(len(self.Via)):
            self.add_results("Via " + str(i) + ": " + self.Via[i])
            
        self.add_results(self.UserAgent)
        self.add_results("")
        self.add_results("===================================================================")
        self.add_results("| Information about the analysis                                  |")
        self.add_results("===================================================================")        
        self.add_results("")

        # ------------------------------------------------------------------------------------------------
        # "TRUST" PART
        # ------------------------------------------------------------------------------------------------

        if self.Behaviour_actions.count("fingerprint") > 0:
            self.lambda_to_parent_fingerprint = self.fingerprint() # Fingerprint analysis
        else:
            self.lambda_to_parent_fingerprint = (1,1)
        
        ip_to_analyse = [] # IPs that will be analysed
        lambda_trust_array = [] # Contains the lambda_trust vectors returned by the analysis of each IP
                
        ip_to_analyse.append(self.From_IP)
        if ip_to_analyse.count(self.Contact_IP) == 0: ip_to_analyse.append(self.Contact_IP) # This is to avoid having repeated IPs
        if ip_to_analyse.count(self.Connection) == 0: ip_to_analyse.append(self.Connection)
        if ip_to_analyse.count(self.Owner) == 0: ip_to_analyse.append(self.Owner)
        
        for i in range(len(self.Via)):
            if ip_to_analyse.count(self.Via[i]) == 0: ip_to_analyse.append(self.Via[i])
       
        
        # Analyse each IP address and get the lambda_trust vectors 
       
        for i in range(len(ip_to_analyse)):
            self.add_results("")
            self.add_results("+ Analysis of: " + ip_to_analyse[i])
            lambda_trust_array.append(self.TrustAnalysis(ip_to_analyse[i])) 
        
        # Fuse all items in lambda_trust_array
        
        lambda_trust = (1,1)
        
        for i in range(len(lambda_trust_array)):
            lambda_trust = (lambda_trust[0] * lambda_trust_array[i][0], lambda_trust[1] * lambda_trust_array[i][1])
        
        beta = (1/(lambda_trust[0] + lambda_trust[1])) # Normalization constant.
        
        lambda_trust = (lambda_trust[0] * beta, lambda_trust[1] * beta) # After normalization.

        # The lambda_to_parent_trust vector is calculated based on a specific CPT matrix
        CPT_matrix = GetCPTmatrix("trust")
        
        if CPT_matrix == -1: 
            self.Print("CRITICAL Can't read /cptdb/trust.conf. The inference analysis can't be done.")
            self.verbose_results = self.verbose_results + "\n" + ("CRITICAL Can't read /cptdb/trust.conf. The inference analysis can't be done.")
            sys.exit(1)
        
        # Now it calculates the lambda_to_parent_trust
        if lambda_trust[0] >= 0.75:
            lambda_to_parent_trust = (CPT_matrix[0][0],CPT_matrix[0][1],CPT_matrix[0][2])
        
        elif lambda_trust[0] < 0.75 and lambda_trust[0] >= 0.35:
            lambda_to_parent_trust = (CPT_matrix[1][0],CPT_matrix[1][1],CPT_matrix[1][2])

        elif lambda_trust[0] < 0.35:
            lambda_to_parent_trust = (CPT_matrix[2][0],CPT_matrix[2][1],CPT_matrix[2][2])
        
        beta = (1 / (lambda_to_parent_trust[0] + lambda_to_parent_trust[1] + lambda_to_parent_trust[2]))
        
        lambda_to_parent_trust = (lambda_to_parent_trust[0] * beta, lambda_to_parent_trust[1] * beta, lambda_to_parent_trust[2] * beta) # After normalization.
            
            
        
        # ------------------------------------------------------------------------------------------------
        # "TO" PART
        # ------------------------------------------------------------------------------------------------
        
        if self.Behaviour_actions.count("to") > 0:
            lambda_to_parent_to = self.checkto() # "To" analysis. It returns the to_parent value, so there's no need to calculate it.
        else:
            lambda_to_parent_to = (1,1,1)
               
                
        # ------------------------------------------------------------------------------------------------
        # "DISPERSION OF SOURCE POINTS" PART
        # ------------------------------------------------------------------------------------------------

        if self.Behaviour_actions.count("dispersion") > 0:
            lambda_to_parent_dispersion = self.dispersion() # Dispersion analysis. It returns the to_parent value, so there's no need to calculate it.
        else:
            lambda_to_parent_dispersion = (1,1,1)
            

        # ------------------------------------------------------------------------------------------------
        # FINAL INFERENCE
        # ------------------------------------------------------------------------------------------------
                        
        # Now it calculates the lambda_nature value, which is the multiplication of all the to_parent lambdas.
        lambda_nature = (lambda_to_parent_trust[0] * lambda_to_parent_to[0] * lambda_to_parent_dispersion[0], lambda_to_parent_trust[1] * lambda_to_parent_to[1] * lambda_to_parent_dispersion[1], lambda_to_parent_trust[2] * lambda_to_parent_to[2] * lambda_to_parent_dispersion[2])
    
        beta = (1/(lambda_nature[0] + lambda_nature[1] + lambda_nature[2])) # Normalization constant.
        
        lambda_nature = (lambda_nature[0] * beta, lambda_nature[1] * beta, lambda_nature[2] * beta) # After normalization.
        
        pi_nature = (0.3,0.4,0.4) # This is value is set in order to give more importance to the "Crafted" possibility.
    
        # Now the final result is calculated (it's called BEL_Nature vector).
        bel_nature = (lambda_nature[0] * pi_nature[0], lambda_nature[1] * pi_nature[1], lambda_nature[2] * pi_nature[2])
        
        beta = (1/(bel_nature[0] + bel_nature[1] + bel_nature[2])) # Normalization constant.
        
        bel_nature = (bel_nature[0] * beta, bel_nature[1] * beta, bel_nature[2] * beta) # After normalization.

        if self.verbose == True:
            self.add_results("")
            self.add_results("(Verbose) Lambda_to_parent_trust: " + str(round(lambda_to_parent_trust[0],4)) + ", " + str(round(lambda_to_parent_trust[1],4)) + ", " + str(round(lambda_to_parent_trust[2],4)))
            self.add_results("(Verbose) Lambda_Nature: " + str(round(lambda_nature[0],4)) + ", " + str(round(lambda_nature[1],4)) + ", " + str(round(lambda_nature[2],4)))
            self.add_results("(Verbose) BEL_Nature: " + str(round(bel_nature[0],4)) + ", " + str(round(bel_nature[1],4)) + ", " + str(round(bel_nature[2],4)))


        # ------------------------------------------------------------------------------------------------
        # RESULTS
        # ------------------------------------------------------------------------------------------------
        
        # And show the results...
        
        if self.Behaviour_actions.count("inference") == 0: # Unless "inference" command is not specified in behaviour.conf
            
            self.Print(self.Results)
            self.Print("\n")
    
            # Then save the results in a file.
            self.save_results()
            
            # Send the results by mail.
            self.send_results()
            del self.email
            
            return
        
        self.NormalProb = round(bel_nature[0],8)
        self.SuspiciousProb = round(bel_nature[1],8)
        self.CraftedProb = round(bel_nature[2],8)
        
        self.add_results("")
        self.add_results("===================================================================")
        self.add_results("| Results                                                         |")
        self.add_results("===================================================================")        
        self.add_results("")
        self.add_results("The probability of the message of being normal is = " + str(self.NormalProb))
        self.add_results("The probability of the message of being suspicious is = " + str(self.SuspiciousProb))
        self.add_results("The probability of the message of being crafted is = " + str(self.CraftedProb))
        self.add_results("")
        
        if self.NormalProb > self.SuspiciousProb and self.NormalProb > self.CraftedProb:
             self.MessageNature = "normal"
             
             # Execute a script
             Process = Popen("bash ./scripts/on_normal.sh", shell=True, stdout=PIPE)
             
        elif self.SuspiciousProb > self.NormalProb and self.SuspiciousProb > self.CraftedProb:
             self.MessageNature = "suspicious"
             
             # Execute a script
             Process = Popen("bash ./scripts/on_suspicious.sh", shell=True, stdout=PIPE)

             # When a message is considered suspicious some actions are taken:
             self.alarm(self.From_IP, "SUSPICIOUS")
             
        elif self.CraftedProb > self.NormalProb and self.CraftedProb > self.SuspiciousProb:
             self.MessageNature = "crafted"
             
             # Execute a script
             Process = Popen("bash ./scripts/on_crafted.sh", shell=True, stdout=PIPE)
             
             # When a message is considered crafted some actions are taken:
             self.alarm(self.From_IP, "CRAFTED")
             
        self.add_results("The message is therefore considered " + self.MessageNature + ".")
        self.add_results("")
        self.add_results("===================================================================")
        self.add_results("")

        self.Print(self.Results)

        # Then save the results in a file.
        self.save_results()
        
        # Send the results by mail.
        self.send_results()
        del self.email
        

        
        
    # def TrustAnalysis
    #
    # Performs the trust analysis.
    
    def TrustAnalysis(self, strIP):
        
        if self.Behaviour_actions.count("historical") > 0:
            lambda_to_parent_historical = self.historical(strIP) # Perform the historical analysis
        else:
            lambda_to_parent_historical = (1,1)
            
        if self.Behaviour_actions.count("whois") > 0:
            lambda_to_parent_whois = self.whois(strIP) # Whois analysis
        else:
            lambda_to_parent_whois = (1,1)
            
        if self.Behaviour_actions.count("gl") > 0:
            lambda_to_parent_gl = self.gl(strIP) # Graphical location analysis
        else:
            lambda_to_parent_gl = (1,1)
                        
        if self.Behaviour_actions.count("reliability") > 0:
            lambda_to_parent_ipreliability = self.ipreliability(strIP) # Reliability analysis
        else:
            lambda_to_parent_ipreliability = (1,1)
            
        if self.Behaviour_actions.count("dns") > 0:    
            lambda_to_parent_dns = self.dns(strIP) # Valid DNS analysis
        else:
            lambda_to_parent_dns = (1,1)
            
        # The lambda_to_parent_fingerprint is multiplied hereunder
        
        # Now calculate the lambda_trust, which is the result of the analyses made before.
        lambda_trust = (lambda_to_parent_historical[0]*lambda_to_parent_whois[0]*lambda_to_parent_gl[0]*lambda_to_parent_ipreliability[0]*lambda_to_parent_dns[0]*self.lambda_to_parent_fingerprint[0],lambda_to_parent_historical[1]*lambda_to_parent_whois[1]*lambda_to_parent_gl[1]*lambda_to_parent_ipreliability[1]*lambda_to_parent_dns[1]*self.lambda_to_parent_fingerprint[1])
    
        beta = 1
        
        if lambda_trust > 0:
            beta = (1 / (lambda_trust[0] + lambda_trust[1])) # Normalization constant
        
        lambda_trust = (lambda_trust[0] * beta, lambda_trust[1] * beta) # After normalization
    
        if self.verbose == True:
            self.add_results("|")
            self.add_results("| (Verbose) Lambda_trust: " + str(round(lambda_trust[0],4)) + ", " + str(round(lambda_trust[1],4)))
                  
        return lambda_trust
        
    # def GetCallData
    #
    # This function gets information from the INVITE message.
    
    def GetCallData(self):
        
        self.To_IP = GetIPfromSIP(GetSIPHeader("To",self.Message))
        self.To_Extension = GetExtensionfromSIP(GetSIPHeader("To",self.Message))
        
        self.From_IP = GetIPfromSIP(GetSIPHeader("From",self.Message))
        self.From_Extension = GetExtensionfromSIP(GetSIPHeader("From",self.Message))
        
        self.Contact_IP = GetIPfromSIP(GetSIPHeader("Contact",self.Message))
        self.Contact_Extension = GetExtensionfromSIP(GetSIPHeader("Contact",self.Message))
        
        self.Connection = GetIPfromSIP(GetSIPHeader("c=",self.Message))
        self.Owner = GetIPfromSIP(GetSIPHeader("c=",self.Message))

        self.UserAgent = GetSIPHeader("User-Agent",self.Message)
    
        #self.Record_Route = GetSIPHeader("Record-Route",self.Message)
        
        
        strTemp = self.Message.splitlines()
    
        for line in strTemp:
            if line[0:4] == "Via:":
                self.Via.append(GetIPfromSIP(line.strip()))
 
# Remove # for debugging        
#        print self.To_IP
#        print self.From_IP
#        print self.Contact_IP
#        print self.Connection
#        print self.Owner
#        if len(self.Via) > 0:
#            for i in range(len(self.Via)):
#                print self.Via[i]
    
    # def whois
    #
    # Uses the whois tool and compare the result with the whois trusted table stored in the whois 
    # directory.
    #
    # Returns the vector lambda to_parent whois.
    
    def whois(self, strIP):
    
        CPT_matrix = GetCPTmatrix("whois")
        
        if CPT_matrix == -1: return (1,1)
        
        # Try to use the whois command. If it fails, perhaps the command is not installed.
        # TODO: here there should be a better error handling.
        try:
            # Store the whois' return in a variable.
            Process = Popen("whois " + strIP, shell=True, stdout=PIPE)
            Process.wait()
            strData = Process.communicate()[0]
            
        except OSError:
            self.Print("WARNING whois is not installed.")
            return (1,1)
        
        # Now the program should read the securelist.txt in order to get the strings to search and compare
        # with the whois' results.
        try:
            File = open("./whois/securelist.txt", "r")
    
        except:
            self.Print("WARNING Can't read /whois/securelist.txt. The whois analysis is not completed.")
            return (1,1)
        
        self.add_results("|")
        self.add_results("| + Whois analysis")
        self.add_results("| |")
            
        #This is the syntaxis (generally for all lambdas): lambda_whois = (trusted value, distrusted value)
        lambda_whois = (0, 1) # If nothing matches, this is the default value. 
            
        for line in File:
            line = line.strip()
            line = RemoveComments(line)
            if line == "": continue
            if strData.find(line) != -1:
                # Some part of the whois matches with some value in the trusted list, so the 
                # lambda_whois must be now:
                strTemp = line.strip()
                lambda_whois = (1, 0)
                break
            
        File.close()

        # And it calculates the to_parent to return back.
        if lambda_whois[0] == 1:
            self.add_results("| | Data found: " + strTemp)
            lambda_to_parent = (CPT_matrix[0][0]*lambda_whois[0],CPT_matrix[0][1]*lambda_whois[0])
        else:
            self.add_results("| | No data found.")
            lambda_to_parent = (CPT_matrix[1][0]*lambda_whois[1],CPT_matrix[1][1]*lambda_whois[1])

        if self.verbose == True:
            self.add_results("| |")
            self.add_results("| | (Verbose) Lambda_to_parent_whois: " + str(round(lambda_to_parent[0],4)) + ", " + str(round(lambda_to_parent[1],4)))
    
        return lambda_to_parent
        
        
    # def gl
    #
    # Get the geographic location of an IP address.
    #
    # Returns the vector lambda to_parent gl.
    
    def gl(self, strIP):
        
        # Check if strIP is an IP or a host name
        bDNS = False
        try:
            temp = IP(strIP)
        except:
            bDNS = True
            
        if bDNS == True:
            try:        
                Process = Popen("dig " + strIP + " A +noall +answer +short", shell=True, stdout=PIPE)
                Process.wait()
                strData = Process.communicate()[0].strip().split("\n")[0]
                
                strIP = strData
                
                if strIP == "":
                    return (0.2,0.8) # If the IP is not resolved...
                
            except OSError:
                self.Print("WARNING dig command is not installed.")
                return (1,1)  
        
        # Now the IP address is given to a special function that gets the geographical location from it.
        # The value returned is a two letter code which represents a country, e.g. "AR" for Argentina.
        # In order to know what the codes are, see ip2country.py.
        # Note: this function was not developed by us, so see ip2country.py for credits.
        
        ip2c = IP2Country(verbose=False)
        strIP2C = str(ip2c.lookup(strIP)[0])
        strIP2C_long = str(ip2c.lookup(strIP)[1])
        
        CPT_matrix = GetCPTmatrix("gl")
        
        if CPT_matrix == -1: return (1,1)
    
        self.add_results("|")
        self.add_results("| + Geographical analysis")
        self.add_results("| |")
        self.add_results("| | Location: " +  strIP2C_long + " (Code: " + strIP2C + ")")
            
        # Now it must check if the geographical location code matches one of the codes contained in the
        # gl.conf file.
        
        for item in CPT_matrix:

            strCountry = item[0]

            if strCountry == "ANY":
                lambda_to_parent = (item[1], item[2])
                    
            if strIP2C == strCountry:
                lambda_to_parent = (item[1], item[2])
                break
            
        
        if self.verbose == True:
            self.add_results("| |")
            self.add_results("| | (Verbose) Lambda_to_parent_gl: " + str(round(lambda_to_parent[0],4)) + ", " + str(round(lambda_to_parent[1],4)))
    
    
        return lambda_to_parent
        
        
    # def ipreliability
    #
    # Checks if the IP or host name matches some line written in file ipreliability.conf.
    #
    # Returns the vector lambda to_parent ipreliability
    
    def ipreliability(self,strIP):
    
        CPT_matrix = GetCPTmatrix("reliability")
        
        if CPT_matrix == -1: return (1,1)
        
        self.add_results("|")
        self.add_results("| + Reliability analysis")
        self.add_results("| |")
                
        lambda_to_parent = (1,1)
        
        # Now the file ipreliability.conf is read, and each item is compared with the IP or host name given.

        bFound = False
        for item in CPT_matrix:

            strItem = item[0]

            if strItem == "default":
                lambda_to_parent = (item[1], item[2])
                    
            if strIP.find(strItem) != -1:
                self.add_results("| | Item found: " + strItem)
                lambda_to_parent = (item[1], item[2])
                bFound = True
                break
            
        if bFound == False:
            self.add_results("| | No item found.")
        
        if self.verbose == True:
            self.add_results("| |")
            self.add_results("| | (Verbose) Lambda_to_parent_reliability: " + str(round(lambda_to_parent[0],4)) + ", " + str(round(lambda_to_parent[1],4)))
    
        return lambda_to_parent
        
        
    # def dns
    #
    # Checks if a DNS is valid.
    #
    # Returns the vector lambda to_parent dns.
    
    def dns(self, strIP):

        CPT_matrix = GetCPTmatrix("validdns")
        
        if CPT_matrix == -1: return (1,1)
        
        self.add_results("|")
        self.add_results("| + Valid DNS analysis")
        self.add_results("| |")
        self.add_results("| | IP or host name to analyse: " + strIP)
        
        # Check if strIP is an IP or a host name
        bDNS = False
        try:
            temp = IP(strIP)
        except:
            bDNS = True
            
        if bDNS == False:
            try:        
                Process = Popen("dig -x " + strIP + " +short", shell=True, stdout=PIPE)
                Process.wait()
                strData = Process.communicate()[0].strip().split("\n")[0]
                
                strIP = strData
                
                self.add_results("| | Is a host name?: No")
                self.add_results("| | Host name resolved: " + strIP)
                
            except OSError:
                self.Print("WARNING dig command is not installed.")
                return (1,1)
        else:
            
            try:        
                Process = Popen("dig " + strIP + " A +noall +answer +short", shell=True, stdout=PIPE)
                Process.wait()
                strData = Process.communicate()[0].strip().split("\n")[0]
                
                strIP = strData
                
                self.add_results("| | Is a host name?: Yes")
                self.add_results("| | IP resolved: " + strIP)
                
            except OSError:
                self.Print("WARNING dig command is not installed.")
                return (1,1)    

        # And it calculates the to_parent to return back.
        if  strIP != "":
            lambda_to_parent = (CPT_matrix[0][0],CPT_matrix[0][1])
        else:
            lambda_to_parent = (CPT_matrix[1][0],CPT_matrix[1][1])


        if self.verbose == True:
            self.add_results("| |")
            self.add_results("| | (Verbose) Lambda_to_parent_dns: " + str(round(lambda_to_parent[0],4)) + ", " + str(round(lambda_to_parent[1],4)))
        
        return lambda_to_parent
    
    # def fingerprint
    #
    # Checks some fingerprint.
    #
    # Returns the vector lambda to_parent fingerprint.
    
    def fingerprint(self):
        
        CPT_matrix = GetCPTmatrix("fingerprint")
        
        if CPT_matrix == -1: return (1,1)
        
        self.add_results("+ Fingerprint analysis")
        self.add_results("|")
        
        bFound = False
        for item in CPT_matrix:

            strFingerprint = item[0]

            if strFingerprint == "not_found":
                lambda_to_parent = (item[1], item[2])
                    
            if self.Message.find(strFingerprint) != -1:
                lambda_to_parent = (item[1], item[2])
                bFound = True
                break
            
        if bFound == False:
            self.add_results("| No fingerprint found.")
        else:
            self.add_results("| Fingerprint found: " + strFingerprint)
        
        beta = (1 / (lambda_to_parent[0] + lambda_to_parent[1])) # Normalization constant
        
        lambda_to_parent = (lambda_to_parent[0] * beta, lambda_to_parent[1] * beta) # After normalization
        
        if self.verbose == True:
            self.add_results("|")
            self.add_results("| (Verbose) Lambda_to_parent_fingerprint: " + str(round(lambda_to_parent[0],4)) + ", " + str(round(lambda_to_parent[1],4)))
        
        return lambda_to_parent
    
    
    # def historical
    #
    # Checks if the IP has been seen before.
    #
    # Returns the vector lambda to_parent historical.
    
    def historical(self, strIP):
        
        CPT_matrix = GetCPTmatrix("historical")
        
        if CPT_matrix == -1: return (1,1)
        
        # This variable store the number of times that the SIP message was found in the database. The more times, the less trusted 
        # probability assigned.
        nMatches = 0
                
        # If the database exists do the analysis. If not, it makes no sense.
        if os.path.isfile("./historical/database.txt") == True:
    
            try:
                File = open("./historical/database.txt", "r")
        
            except:
                self.Print("WARNING Can't read /historical/database.txt. The historical analysis is not completed.")
                return (1,1)
        
            # Read line by line and match each one with the IP
            for line in File:
                line = line.strip()
                line = RemoveComments(line)
                if line == "": continue
                
                if line.find(strIP) != -1:
                    # The IP matches the line read in the database file, so the nMatches variable is increased.
                    nMatches += 1    
            
            File.close()
            
            # Assigns values to lambda_to_parent according to the number of times that the IP was found in the database.
            if nMatches == 0:
                lambda_historical = (CPT_matrix[0][0],CPT_matrix[0][1])
                
            elif nMatches >= 1 and nMatches <= 2:
                lambda_historical = (CPT_matrix[1][0],CPT_matrix[1][1])
                
            elif nMatches >= 3:
                lambda_historical = (CPT_matrix[2][0],CPT_matrix[2][1])

        else: # If the database file doesn't exist
            
            # The database file was not found, so it's assumed that the SIP INVITE message was never seen
            # before, and it's likely to be trusted.
            lambda_historical = (CPT_matrix[0][0],CPT_matrix[0][1])
 
        beta = (1 / (lambda_historical[0] + lambda_historical[1])) # Normalization constant
        
        lambda_to_parent = (lambda_historical[0] * beta, lambda_historical[1] * beta) # After normalization
                                 
                   
        self.add_results("|")
        self.add_results("| + Historical analysis")
        self.add_results("| |")
        self.add_results("| | Number of times seen: " + str(nMatches))
                
        # Store tha information of the current SIP INVITE message for future analyses.
        try:
            File = open("./historical/database.txt", "a")
        
        except:
            self.Print("WARNING Can't read /historical/database.txt. The historical analysis is not completed.")
            return (1,1)
            
        strDataToStore = strIP + "\n"
            
        File.write(strDataToStore)
            
        File.close()

        if self.verbose == True:
            self.add_results("| |")
            self.add_results("| | (Verbose) Lambda_to_parent_historical: " + str(round(lambda_to_parent[0],4)) + ", " + str(round(lambda_to_parent[1],4)))
    
        return lambda_to_parent
    
    
    
    # def checkto
    #
    # Checks if the To field of the SIP headers matches with a registered extension of the honeypot.
    #
    # Returns the vector lambda to_parent to.
    
    def checkto(self):
       
        CPT_matrix = GetCPTmatrix("to")
        
        if CPT_matrix == -1: return (1,1)
        
        self.add_results("")
        self.add_results("+ \"To\" field coherence analysis")
        self.add_results("|")
        self.add_results("| Extension in field To: " + self.To_Extension)
        
        lambda_whois = (0, 1) # By default the "To" doesn't match.
        
        # Now it checks if the extension contained in the "To" field is one of the honeypot's registered
        # extesions. If it does, the message is likely to be normal (human dialing error).
        for i in range(len(self.Extensions)):
            if str(self.Extensions[i].Extension) == self.To_Extension:
                # The extension contained in the "To" field is an extension of the honeypot.
                lambda_whois = (1, 0)
                self.add_results("| Result: valid registered extension.")
                lambda_to_parent = (CPT_matrix[0][0], CPT_matrix[0][1], CPT_matrix[0][2])
                
        if lambda_whois == (0, 1):
            self.add_results("| Result: NOT valid registered extension.")
            lambda_to_parent = (CPT_matrix[1][0], CPT_matrix[1][1], CPT_matrix[1][2])
            
            
        beta = (1 / (lambda_to_parent[0] + lambda_to_parent[1] + lambda_to_parent[2])) # Normalization constant
        
        lambda_to_parent = (lambda_to_parent[0] * beta, lambda_to_parent[1] * beta, lambda_to_parent[2] * beta) # After normalization
        
        if self.verbose == True:
            if self.Behaviour_actions.count("to") > 0:
                self.add_results("| (Verbose) Lambda_to_parent_to: " + str(round(lambda_to_parent[0],4)) + ", " + str(round(lambda_to_parent[1],4)) + ", " + str(round(lambda_to_parent[2],4)))
                
        return lambda_to_parent 
        
        
    # def dispersion
    #
    # Evaluates the dispersion of the source points.
    #
    # Returns the vector lambda to_parent dispersion.
    
    def dispersion(self):
    
        # First check if Artemisa is running as root. This is needed because the "traceroute"
        # command needs it. If another traceroute implementation is added, this requirement
        # could be removed.
        
        if not os.geteuid()==0:
            self.Print("WARNING In order to perform the dispersion analysis, Artemisa must be launched with root privileges. The disperion analysis is omitted.")
            return (1,1,1)
    
        CPT_matrix = GetCPTmatrix("dispersion")

        if CPT_matrix == -1: return (1,1,1)
                
        self.add_results("")
        self.add_results("+ Dispersion of source points analysis")
        self.add_results("|")
        
        nHopsA = self.gethops(self.From_IP)
        nHopsB = self.gethops(self.Owner)
        nHopsC = self.gethops(self.Connection)
        nHopsD = self.gethops(self.Contact_IP)
        
        nHopsE = []
        
        if len(self.Via) > 0:
            for i in range(len(self.Via)):
                nHopsE.append(self.gethops(self.Via[i]))
                if nHopsE[i] < 0:
                    return (1,1,1) # Means that traceroute failed
            
        if nHopsA < 0 or nHopsB < 0 or nHopsC < 0 or nHopsD < 0 or nHopsE < 0:
            return (1,1,1) # Means that traceroute failed


        self.add_results("| Number of hops to the IP in From field: " + str(nHopsA))
        self.add_results("| Number of hops to the IP in Owner field: " + str(nHopsB))
        self.add_results("| Number of hops to the IP in Connection field: " + str(nHopsC))
        self.add_results("| Number of hops to the IP in Contact field: " + str(nHopsD))
        
        if len(nHopsE) > 0:
            for i in range(len(nHopsE)):
                self.add_results("| Number of hops to the IP in Via " + str(i) + " field: " + str(nHopsE[i]))

        # Mean
        #nMean = (nHopsA + nHopsB + nHopsC + nHopsD + nHopsE) / 5

        nMean = nHopsA + nHopsB + nHopsC + nHopsD

        nStandardDeviation = 0

        if len(nHopsE) > 0:
            for i in range(len(nHopsE)):
                nMean = nMean + nHopsE[i]

            nMean = nMean / (4 + i)

            for i in range(len(nHopsE)):
                nStandardDeviation = nStandardDeviation + pow((nHopsE[i] - nMean),2)

            # Calculates the standard deviation
            nStandardDeviation = sqrt(nStandardDeviation + (pow((nHopsA - nMean),2) + pow((nHopsB - nMean),2) + pow((nHopsC - nMean),2) + pow((nHopsD - nMean),2))/(4+i))
                        
        else:
            nMean = nMean / 4
            
            # Calculates the standard deviation
            nStandardDeviation = sqrt((pow((nHopsA - nMean),2) + pow((nHopsB - nMean),2) + pow((nHopsC - nMean),2) + pow((nHopsD - nMean),2))/4)                    

        self.add_results("|")
        self.add_results("| Dispersion of source points = " + str(nStandardDeviation))
        
        if nStandardDeviation <= 1:
            lambda_to_parent = (CPT_matrix[0][0],CPT_matrix[0][1],CPT_matrix[0][2])
        elif nStandardDeviation > 1 and nStandardDeviation <= 4:
            lambda_to_parent = (CPT_matrix[1][0],CPT_matrix[1][1],CPT_matrix[1][2])
        elif nStandardDeviation > 4:
            lambda_to_parent = (CPT_matrix[2][0],CPT_matrix[2][1],CPT_matrix[2][2])     
    
        beta = (1 / (lambda_to_parent[0] + lambda_to_parent[1] + lambda_to_parent[2])) # Normalization constant
        
        lambda_to_parent = (lambda_to_parent[0] * beta, lambda_to_parent[1] * beta, lambda_to_parent[2] * beta) # After normalization
        
        if self.verbose == True:
            if self.Behaviour_actions.count("dispersion") > 0:
                self.add_results("| (Verbose) Lambda_to_parent_dispersion: " + str(round(lambda_to_parent[0],4)) + ", " + str(round(lambda_to_parent[1],4)) + ", " + str(round(lambda_to_parent[2],4)))
                
        return lambda_to_parent 
    
    
    # def gethops
    #
    # Perform a traceroute and obtain the number of hops to a host.
    
    def gethops(self, strIP):
        
        #TODO: this part could be improved, using another type of traceroute.
        
        try:
            Process = Popen("traceroute -4 -I -N 1 -n -q 1 -w 2 " + strIP + " | wc -l", shell=True, stdout=PIPE)
            Process.wait()
            return (int(Process.communicate()[0].strip()) - 1)
        
        except OSError:
            self.Print("WARNING traceroute command is not installed.")
            return -1

        except Exception, e:
            self.Print("CRITICAL Error on gethops function: " + str(e))
            return (1,1,1)
                
    # def alarm
    #
    # Store information about the analysis in ./alarms/
    
    def alarm(self, strIP, strNature):
        
        try:
            
            a = 0
            while 1:
                
                strFilename = strftime("%Y-%m-%d") + "_alarm_" + str(a) + ".txt"
                
                if os.path.isfile("./alarms/" + strFilename) == True:
                    a += 1
                else:
                    break
            
            File = open("./alarms/" + strFilename, "w")
                
            File.write(self.GetTime() + " " + "An INVITE message considered " + strNature + " arrived from " + strIP + ". Check the log files for details.")
        
            File.close()
            
        except:
            self.Print("WARNING Can't write the alarm file!")
        
    
    # def add_results
    #
    # Store information about the results.
    
    def add_results(self, strData):
        
        if self.Results == "":
            if strData == "":
                self.Results = "\n"
            else:
                self.Results = strData
        
        else:
            self.Results = self.Results + strData + "\n"
            
        
    # def save_results
    #
    # Save the results in a file.
    
    def save_results(self):
        
        try:
            
            a = 0
            while 1:
                
                strFilename = strftime("%Y-%m-%d") + "_" + str(a) + ".txt"
                
                if os.path.isfile("./results/" + strFilename) == True:
                    a += 1
                else:
                    break
                   
            File = open("./results/" + strFilename, "w")
                
            File.write("Artemisa results\n")
            File.write("----------------\n\n")
            File.write("INVITE message detected on " + strftime("%A, %d %B %Y %H:%M") + "\n\n")    
            File.write("The probability of the message of being normal is = " + str(self.NormalProb) + "\n")
            File.write("The probability of the message of being suspicious is = " + str(self.SuspiciousProb) + "\n")
            File.write("The probability of the message of being crafted is = " + str(self.CraftedProb) + "\n")
            File.write("\n")
            File.write("The message is therefore considered " + self.MessageNature + "." + "\n")
            File.write("========================================================================================\n")
            File.write("\nRaw INVITE message:\n\n")
            File.write(self.Message)
            File.close()
            
        except:
            pass
        
        
    # def send_results
    #
    # Send the results by e-mail.
    
    def send_results(self):

        if self.email.Enabled == False: 
            self.Print("NOTICE E-mail notification is disabled.")
            return

        if self.Behaviour == "passive":
            strData = "\nDear Administrator, \n\nThis mail was automatically generated by Artemisa in order to inform you that an INVITE message has arrived. Since Artemisa is configured in passive mode, just the raw message is shown herein:\n\n"
            
            strData = strData + "Raw INVITE message:\n\n"
             
            strData = strData + self.Message
            
        else:
            strData = "\nDear Administrator, \n\nThis mail was automatically generated by Artemisa in order to inform you that an INVITE message has arrived with the following results:\n\n"
             
            strData = strData + self.Results
                
            strData = strData + "\n\nRaw INVITE message:\n\n"
             
            strData = strData + self.Message
            
        self.Print("NOTICE Sending this report by e-mail... (please wait)")
        self.Print(self.email.sendemail(strData))
        
        
    