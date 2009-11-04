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
# messages are carefully analyzed, using tools and mathematical resources, and where the       #
# conclusion about the danger of the message is done.                                          #
#                                                                                              #
# The methods used in this part of the program are suggested in the IEEE paper "VoIP Honeypot  #
# Architecture" published in 2007 by Mohamed Nassar, Radu State and Oliver Festor.             #
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
from commons import PrintClass, GetSIPHeader, Search, GetTimeClass
import ip2country                   # Downloaded from http://www.freenet.org.nz/python/ip2country/
from IPy import *                   # Module to deal with IPs
from logs import log                # Import class log from logs.py
import random                       # Random numbers generation
from traceroute import getnumberofhops # Contains the traceroute function used in dispersion analysis


class InferenceAnalysis(PrintClass, log, GetTimeClass):
    
    Message = ""
    verbose = False # Flag to know if the verbose mode is set
    Extensions = []
    
    strResults = "" # Store output information
    
    # def Start
    #
    # This function starts the process. 
    #
    # It receives the SIP INVITE message detected, the verbose condition (True or False) and the
    # extensions registered to the SIP server by the honeypot.
    
    def Start(self):

        strAddress = GetSIPHeader("From",self.Message) # Get the From field of the INVITE message
        
        # The next long command extract the IP address or dns name from the "From" field
        strAddress = strAddress.split("<")[len(strAddress.split("<"))-1].split("@")[len(strAddress.split("<")[len(strAddress.split("<"))-1].split("@"))-1].split(">")[0].split(":")[0]
        
        strContact_c = GetSIPHeader("c=",self.Message) # Get the IP address of the INVITE message
        
        if strContact_c != "": # Could happen that the "c" value was not included in the message
            strContact_c = strContact_c.split(" ")[len(strContact_c.split(" "))-1]
        else:
            strContact_c = strAddress # In this case, adopt the IP or name of the From field
    
            
        self.Print("Performing SIP INVITE message analysis...")
    
        # ------------------------------------------------------------------------------------------------
        # "TRUST" PART
        # ------------------------------------------------------------------------------------------------
    
        self.Print("Checking historical information...", self.verbose)
        lambda_to_parent_historical = self.historical() # Perform the historical analysis
        
        self.Print("Performing whois to: " + strAddress, self.verbose)
        lambda_to_parent_whois = self.whois(strAddress) # Whois analysis
    
        self.Print("Getting geographic location of: " + strAddress, self.verbose)
        lambda_to_parent_gl = self.gl(strAddress) # Graphical location analysis
        
        self.Print("Performing reverse DNS to: " + strContact_c, self.verbose)
        lambda_to_parent_rdns = self.rdns(strContact_c) # Reverse DNS analysis    
        
        self.Print("Checking DNS coherence...", self.verbose)
        lambda_to_parent_dns = self.dns() # DNS analysis
    
        self.Print("Checking fingerprint...", self.verbose)
        lambda_to_parent_fingerprint = self.fingerprint() # Fingerprint analysis 
    
        # Now calculate the lambda_trust, which is the result of the analyses made before.
        lambda_trust =(lambda_to_parent_historical[0]*lambda_to_parent_whois[0]*lambda_to_parent_gl[0]*lambda_to_parent_rdns[0]*lambda_to_parent_dns[0]*lambda_to_parent_fingerprint[0],lambda_to_parent_historical[1]*lambda_to_parent_whois[1]*lambda_to_parent_gl[1]*lambda_to_parent_rdns[1]*lambda_to_parent_dns[1]*lambda_to_parent_fingerprint[1])
    
        beta = (1 / (lambda_trust[0] + lambda_trust[1])) # Normalization constant
        
        lambda_trust = (lambda_trust[0] * beta, lambda_trust[1] * beta) # After normalization
    
    
        # CPT (Trust/Nature)
        #
        #               |    T > 0.75    | 0.35 < T < 0.75|    T < 0.35    |
        # --------------|----------------|----------------------------------
        #   Normal      |      0.8       |      0.15      |      0.05      |
        #   Suspicious  |      0.1       |      0.5       |      0.4       |
        #   Crafted     |      0.05      |      0.15      |      0.8       |
        #
    
        # Now it calculates the lambda_to_parent_trust based on the lambda_trust value.
        if lambda_trust[0] >= 0.75:
            
            lambda_to_parent_trust = (0.8,0.1,0.05)
            beta = (1 / (lambda_to_parent_trust[0] + lambda_to_parent_trust[1] + lambda_to_parent_trust[2]))
            lambda_to_parent_trust = (lambda_to_parent_trust[0] * beta, lambda_to_parent_trust[1] * beta, lambda_to_parent_trust[2] * beta) # After normalization.
            
        elif lambda_trust[0] < 0.75 and lambda_trust[0] >= 0.35:
    
            lambda_to_parent_trust = (0.15,0.5,0.15)
            beta = (1 / (lambda_to_parent_trust[0] + lambda_to_parent_trust[1] + lambda_to_parent_trust[2]))
            lambda_to_parent_trust = (lambda_to_parent_trust[0] * beta, lambda_to_parent_trust[1] * beta, lambda_to_parent_trust[2] * beta) # After normalization.
            
        elif lambda_trust[0] < 0.35:
            
            lambda_to_parent_trust = (0.05,0.4,0.8)
            beta = (1 / (lambda_to_parent_trust[0] + lambda_to_parent_trust[1] + lambda_to_parent_trust[2]))
            lambda_to_parent_trust = (lambda_to_parent_trust[0] * beta, lambda_to_parent_trust[1] * beta, lambda_to_parent_trust[2] * beta) # After normalization.
            
    
        # ------------------------------------------------------------------------------------------------
        # "TO" PART
        # ------------------------------------------------------------------------------------------------
        
        self.Print("Checking \"To\" field coherence...", self.verbose)
        lambda_to_parent_to = self.checkto() # "To" analysis. It returns the to_parent value, so there's no need to calculate it.
    
    
    
        # ------------------------------------------------------------------------------------------------
        # "DISPERSION OF SOURCE POINTS" PART
        # ------------------------------------------------------------------------------------------------
            
        self.Print("Getting dispersion of source points...", self.verbose)
        lambda_to_parent_dispersion = self.dispersion() # Dispersion analysis. It returns the to_parent value, so there's no need to calculate it.
        
        
        # ------------------------------------------------------------------------------------------------
        # VERBOSE RESULTS PART
        # ------------------------------------------------------------------------------------------------
            
        strOut = "\n"
        strOut = strOut + "-------------------------------------------------------------------" + "\n"
        strOut = strOut + "| Results (verbose)                                               |" + "\n"
        strOut = strOut + "-------------------------------------------------------------------" + "\n"
        strOut = strOut + "Lambda_to_parent_historical: " + str(lambda_to_parent_historical[0]) + ", " + str(lambda_to_parent_historical[1]) + "\n"
        strOut = strOut + "Lambda_to_parent_whois: " + str(lambda_to_parent_whois[0]) + ", " + str(lambda_to_parent_whois[1]) + "\n"
        strOut = strOut + "Lambda_to_parent_gl: " + str(lambda_to_parent_gl[0]) + ", " + str(lambda_to_parent_gl[1]) + "\n"
        strOut = strOut + "Lambda_to_parent_rdns: " + str(lambda_to_parent_rdns[0]) + ", " + str(lambda_to_parent_rdns[1]) + "\n"
        strOut = strOut + "Lambda_to_parent_dns: " + str(lambda_to_parent_dns[0])  + ", " + str(lambda_to_parent_dns[1]) + "\n"
        strOut = strOut + "Lambda_to_parent_fingerprint:" + str(lambda_to_parent_fingerprint[0]) + ", " + str(lambda_to_parent_fingerprint[1]) + "\n"
        strOut = strOut + "-------------------------------------------------------------------" + "\n"
        strOut = strOut + "Lambda_trust: " + str(lambda_trust[0]) + ", " + str(lambda_trust[1]) + "\n"
        strOut = strOut + "Lambda_to_parent_trust: " + str(lambda_to_parent_trust[0]) + ", " + str(lambda_to_parent_trust[1]) + ", " + str(lambda_to_parent_trust[2]) + "\n"
        strOut = strOut + "-------------------------------------------------------------------" + "\n"
        strOut = strOut + "Lambda_to_parent_to: " + str(lambda_to_parent_to[0]) + ", " + str(lambda_to_parent_to[1]) + ", " + str(lambda_to_parent_to[2]) + "\n"
        strOut = strOut + "-------------------------------------------------------------------" + "\n"
        strOut = strOut + "Lambda_to_parent_dispersion: " + str(lambda_to_parent_dispersion[0]) + ", " + str(lambda_to_parent_dispersion[1]) + ", " + str(lambda_to_parent_dispersion[2]) + "\n"
        strOut = strOut + "-------------------------------------------------------------------"
    
        # These lambda values are just shown if verbose mode is on.
        self.Print(strOut, self.verbose)
    
        # Not it calculates the lambda_nature value, which is the multiplication of all the to_parent lambdas.
        lambda_nature = (lambda_to_parent_trust[0] * lambda_to_parent_to[0] * lambda_to_parent_dispersion[0], lambda_to_parent_trust[1] * lambda_to_parent_to[1] * lambda_to_parent_dispersion[1], lambda_to_parent_trust[2] * lambda_to_parent_to[2] * lambda_to_parent_dispersion[2])
    
        beta = (1/(lambda_nature[0] + lambda_nature[1] + lambda_nature[2])) # Normalization constant.
        
        lambda_nature = (lambda_nature[0] * beta, lambda_nature[1] * beta, lambda_nature[2] * beta) # After normalization.
        
        pi_nature = (0.3,0.4,0.4) # This is value is set in order to give more importance to the "Crafted" possibility.
    
        # Now the final result is calculated (it's called BEL_Nature vector).
        bel_nature = (lambda_nature[0] * pi_nature[0], lambda_nature[1] * pi_nature[1], lambda_nature[2] * pi_nature[2])
        
        beta = (1/(bel_nature[0] + bel_nature[1] + bel_nature[2])) # Normalization constant.
        
        bel_nature = (bel_nature[0] * beta, bel_nature[1] * beta, bel_nature[2] * beta) # After normalization.
        
        # And show the results...
        
        strOut = "\n"
        strOut = strOut + "-------------------------------------------------------------------" + "\n" 
        strOut = strOut + "| Results                                                         |" + "\n"
        strOut = strOut + "-------------------------------------------------------------------" + "\n"
        strOut = strOut + "\n"
        strOut = strOut + "The probability of the message of being normal is = " + str(round(bel_nature[0],4)) + "\n"
        strOut = strOut + "The probability of the message of being suspicious is = " + str(round(bel_nature[1],4)) + "\n"
        strOut = strOut + "The probability of the message of being crafted is = " + str(round(bel_nature[2],4)) + "\n"
        strOut = strOut + "\n"
        
        if bel_nature[0] > bel_nature[1] and bel_nature[0] > bel_nature[2]:
             strOut = strOut + "The message is therefore considered normal." + "\n"
        elif bel_nature[1] > bel_nature[0] and bel_nature[1] > bel_nature[2]:
             strOut = strOut + "The message is therefore considered suspicious." + "\n"
             self.alarm(strAddress, "SUSPICIOUS")
        elif bel_nature[2] > bel_nature[0] and bel_nature[2] > bel_nature[1]:
             strOut = strOut + "The message is therefore considered crafted." + "\n"
             self.alarm(strAddress, "CRAFTED")
            
        strOut = strOut + "\n"
        strOut = strOut + "-------------------------------------------------------------------" + "\n"
        
        self.Print(strOut, self.verbose)
        self.results(strOut)
        
        # Then save the results in a file.
        self.save_results()
        
        self.Print("Analysis completed. See the results file for details.")
        
    # def whois
    #
    # Uses the whois tool and compare the result with the whois trusted table stored in the whois 
    # directory.
    #
    # Returns the vector lambda to_parent whois.
    
    def whois(self,strAddress):
    
        # CPT (whois/trust)
        #
        #               | In secure list | Not in secure list
        # --------------|----------------|-----------------------
        #   Trusted     |      0.7       |      0.3
        #   Distrusted  |      0.3       |      0.7
        #
    
        CPT_matrix = [(0.7,0.3),(0.3,0.7)]
    
        # Try to use the whois command. If it fails, perhaps the command is not installed.
        # TODO: here there should be a better error handling.
        try:
            # Store the whois' return in a variable.
            Process = Popen("whois " + strAddress, shell=True, stdout=PIPE)
            Process.wait()
            strData = Process.communicate()[0]
            
        except OSError:
            self.Print("WARNING whois is not installed")
            return (1,1)
        
        # Now the program should read the securelist.txt in order to get the strings to search and compare
        # with the whois' results.
        try:
            File = open("./whois/securelist.txt", "r")
    
        except:
            self.Print("WARNING Can't read securelist.txt. The whois analysis is not completed.")
            return (0.3,0.7)
        
        self.Print("WHOIS IP: " + strAddress, self.verbose)
        self.Print("WHOIS Data: " + strData, self.verbose)        
    
        if self.verbose == True:
            self.results("WHOIS IP: " + strAddress)
            self.results("WHOIS Data: " + strData)        
            
        #This is the syntaxis (generally for all lambdas): lambda_whois = (trusted value, distrusted value)
        lambda_whois = (0, 1) # If nothing matches, this is the default value. 
            
        for line in File:
            line = line.replace("\n","") # Remove some special characters
            line = line.replace("\r","") # Remove some special characters
            if line.find("#") == -1 and len(line) > 2:
                if strData.find(line) != -1:
                    # Some part of the whois matches with some value in the trusted list, so the 
                    # lambda_whois must be now:
                    lambda_whois = (1, 0)
            
        File.close()
            
        # And it calculates the to_parent to return back.
        if lambda_whois[0] == 1:
            lambda_to_parent = (CPT_matrix[0][0]*lambda_whois[0],CPT_matrix[0][1]*lambda_whois[0])
        else:
            lambda_to_parent = (CPT_matrix[1][0]*lambda_whois[1],CPT_matrix[1][1]*lambda_whois[1])
            
        return lambda_to_parent
        
        
    # def gl
    #
    # Get the geographic location of the IP address.
    #
    # Returns the vector lambda to_parent gl.
    
    def gl(self,strAddress):
        
        # Check if strAddress is a IP or a DNS name
        bDNS = True
        try:
            temp = IP(strAddress)
        except:
            bDNS = False
            
        # These instructions converts an IP to a DNS name, using GNU/Linux nslookup tool.
        if bDNS == False:
            try:        
                Process = Popen("nslookup " + strAddress, shell=True, stdout=PIPE)
                Process.wait()
                strAddress = Process.communicate()[0].strip().split("\n")
    
                strAddress = strAddress[len(strAddress)-1]
                strAddress = strAddress.split(" ")[len(strAddress.split(" "))-1]
                strAddress = strAddress.split("\t")[len(strAddress.split("\t"))-1]
                
            except OSError:
                self.Print("WARNING nslookup command is not installed")
                return (1,1)
            
        # Now the IP address is given to a special function that gets the geographical location from it.
        # The value returned is a two letter code which represents a country, e.g. "AR" for Argentina.
        # In order to know what the codes are, see ip2country.py.
        # Note: this function was not developed by us, so see ip2country.py for credits.
        
        ip2c = ip2country.IP2Country(verbose=self.verbose)
        strIP2C = str(ip2c.lookup(strAddress)[0])
        
        try:
            File = open("./cptdb/gl.conf", "r")
    
        except:
            self.Print("WARNING Can't read /cptdb/gl.conf. The gl analysis is not completed.")
            self.results("WARNING Can't read /cptdb/gl.conf. The gl analysis is not completed.")
            return (1,1)
    
        self.Print("GL IP: " + strAddress, self.verbose)
        self.Print("GL Loc: " + strIP2C, self.verbose)
    
        if self.verbose == True:
            self.results("GL IP: " + strAddress)
            self.results("GL Loc: " + strIP2C)
            
        lambda_to_parent = (0.7,0.3) # By default
        
        # Now it must check if the geographical location code matchs one of the codes contained in the
        # gl.conf file.
        for line in File:
            line = line.replace("\n","")
            line = line.replace("\r","")
            if line.find("#") == -1 and len(line) > 2:
                if line.find("=") != -1:
                    strCountry = line.split("=")[0]
                    nTrusted = float(line.split("=")[1].split(",")[0])
                    nDistrusted = float(line.split("=")[1].split(",")[1])
    
                    if strCountry == "ANY":
                        lambda_to_parent = (nTrusted, nDistrusted)
                    
                    if strIP2C == strCountry:
                        lambda_to_parent = (nTrusted, nDistrusted)
            
        File.close()
            
        return lambda_to_parent
        
        
    # def rdns
    #
    # Performs a reverse dns (using the GNU/Linux "host" command) to an IP address, and checks if
    # the name obtained matches some wrote in file rdns.conf.
    #
    # Returns the vector lambda to_parent rdns
    
    def rdns(self,strAddress):
    
        # The DNS name contained in strAddress is converted to an IP address using "host" tool.
        try:
            Process = Popen("host " + strAddress, shell=True, stdout=PIPE)
            Process.wait()
            strIP = Process.communicate()[0].strip()
            
            if strIP.find("not found") != -1:
                
                self.Print("RDNS IP: " + strAddress, self.verbose)
                self.Print("RDNS NAME: NOT FOUND", self.verbose)
    
                if self.verbose == True:
                    self.results("RDNS IP: " + strAddress)
                    self.results("RDNS NAME: NOT FOUND")
                    
                # The DNS name was not resolved. So this function returns 0.2 for trusted.
                return (0.2,0.8)
    
            # Trim the string returned by the host command in order to obtain the DNS name.
            # TODO: here we could use another tool or method to get the DNS name, because not only
            # the honeypot depends on the "host" tool, but alse the output of it could change and we
            # would have to rewrite this part.
            strIP = strIP.split(" ")[len(strIP.split(" "))-1]
            
        except OSError:
            self.Print("WARNING host command is not installed")
            return (1,1) # If the tools is not installed, this analysis is not taken into account.
    
        try:
            File = open("./cptdb/rdns.conf", "r")
    
        except:
            self.Print("WARNING Can't read /cptdb/rdns.conf. The reverse dsn analysis is not completed.")
            return (1,1)
    
        self.Print("RDNS IP: " + strAddress, self.verbose)
        self.Print("RDNS NAME: " + strIP, self.verbose)
        
        if self.verbose == True:
            self.results("RDNS IP: " + strAddress)
            self.results("RDNS NAME: " + strIP)
            
        lambda_to_parent = (0.5,0.5) # By default
        
        # Now the file rdns.conf is read, and each item is compared with the dns obtained. In this way,
        # one can assign belief values to certain dns names.
        for line in File:
            line = line.strip()
            if line.find("#") == -1 and len(line) > 2:
                if line.find("=") != -1:
                    strDNS = line.split("=")[0]
                    strDNS = strDNS[0:len(strDNS)-1]
                    nTrusted = float(line.split("=")[1].split(",")[0])
                    nDistrusted = float(line.split("=")[1].split(",")[1])
    
                    if strIP.find(strDNS) != -1:
                        lambda_to_parent = (nTrusted, nDistrusted)
            
        File.close()
            
        return lambda_to_parent
        
        
    # def dns
    #
    # Checks if the IP address in the contact information corresponds with the calling uri.
    #
    # Returns the vector lambda to_parent dns
    
    def dns(self):
    
        strDNS = GetSIPHeader("From",self.Message) # Get the From field of the SIP INVITE message.
        
        # The next long command extract the IP address or dns name from the "From" field
        strDNS = strDNS.split("<")[len(strDNS.split("<"))-1].split("@")[len(strDNS.split("<")[len(strDNS.split("<"))-1].split("@"))-1].split(">")[0].split(":")[0]
        
        strIP = GetSIPHeader("Contact:",self.Message) # Get the Contact field.
        strIP = strIP.split("<")[len(strIP.split("<"))-1].split("@")[len(strIP.split("<")[len(strIP.split("<"))-1].split("@"))-1].split(">")[0].split(":")[0]
    
        self.Print("DNS or IP From: " + strDNS, self.verbose)
        self.Print("DNS or IP Contact: " + strIP, self.verbose)
    
        if self.verbose == True:
            self.results("DNS or IP From: " + strDNS)
            self.results("DNS or IP Contact: " + strIP)
    
        # Check if strDNS is a IP or a DNS name
        bDNS = True
        try:
            temp = IP(strDNS)
        except:
            bDNS = False
            
        if bDNS == False:
            try:        
                Process = Popen("nslookup " + strDNS, shell=True, stdout=PIPE)
                Process.wait()
                strData = Process.communicate()[0].strip().split("\n")
                
                strData = strData[len(strData)-1]
                strData = strData.split(" ")[len(strData.split(" "))-1]
                strData = strData.split("\t")[len(strData.split("\t"))-1]
                strDNS = strData
                
            except OSError:
                self.Print("WARNING nslookup command is not installed")
                return (1,1)
    
        # Check if strIP is a IP or a DNS name
        bDNS = True
        try:
            temp = IP(strIP)
        except:
            bDNS = False
            
        if bDNS == False:
            try:        
                Process = Popen("nslookup " + strIP, shell=True, stdout=PIPE)
                Process.wait()
                strData = Process.communicate()[0].strip().split("\n")
            
                strData = strData[len(strData)-1]
                strData = strData.split(" ")[len(strData.split(" "))-1]
                strData = strData.split("\t")[len(strData.split("\t"))-1]
                strIP = strData
                
            except OSError:
                self.Print("WARNING nslookup command is not installed")
                return (1,1)
    
        self.Print("IP From: " + strDNS, self.verbose)
        self.Print("IP Contact: " + strIP, self.verbose)
    
        if self.verbose == True:
            self.results("IP From: " + strDNS)
            self.results("IP Contact: " + strIP)
            
        # And now compares if both IP match.  
        
        if strDNS != strIP:
            return (0.2,0.8) # Don't match-
        else:
            return (0.8,0.2) # Match.
        
    
    # def fingerprint
    #
    # Checks some fingerprint.
    #
    # Returns the vector lambda to_parent fingerprint.
    
    def fingerprint(self):
        
        try:
            File = open("./cptdb/fingerprint.conf", "r")
    
        except:
            self.Print("WARNING Can't read /cptdb/fingerprint.conf. The fingerprint analysis is not completed.")
            return (1,1)
    
        lambda_to_parent = (0.5,0.5) # By default
        
        # This analysis is quite simple. It checks if some line of the file fingerprint.conf (except the
        # comment lines) match with some part of the SIP INVITE message. And it assigns the "trust" and
        # "distrust" values for that part. Doing this, if we know that some secure (or insecure) message
        # contain always the same string (here called fingerprint), we can give it some safaty values.
        # For example, if we know that some SIP scanner uses always in its messages the User-Agent field
        # value "User-Agent: friendly-scanner", we can assign it very low trusteable numbers, so the
        # honeypot will surely conclude that the message is crafted or at least suspicious.
        
        for line in File:
            line = line.replace("\n","")
            line = line.replace("\r","")
            if line.find("#") == -1 and len(line) > 2:
                if line.find("=") != -1:
                    strFingerprint = line.split("=")[0]
                    nTrusted = float(line.split("=")[1].split(",")[0])
                    nDistrusted = float(line.split("=")[1].split(",")[1])
                    
                    if self.Message.find(strFingerprint) != -1:
                        lambda_to_parent = (nTrusted, nDistrusted)
                        self.Print("Fingerprint found: " + strFingerprint, self.verbose)
                        if self.verbose == True: self.results("Fingerprint found: " + strFingerprint)
                        break
            
        File.close()
            
        return lambda_to_parent
    
    
    # def historical
    #
    # Checks if a message has been received before.
    #
    # Returns the vector lambda to_parent historical.
    
    def historical(self):
        
        # These are fields of the SIP INVITE message that will be stored in a database in order to do future historical analyses.
        strFrom = GetSIPHeader("From",self.Message)
        strFrom = strFrom.split(";")[0] # Store the From field without the Tag value.
        strContact = GetSIPHeader("Contact",self.Message)
        # The port is deleted because it changes everytime
        strContact = strContact.split(":")[2]
        strC = GetSIPHeader("c=",self.Message)
        strINVITE = GetSIPHeader("INVITE",self.Message)
        strUA = GetSIPHeader("User-Agent",self.Message)
        strTo = GetSIPHeader("To",self.Message)
        strTo = strTo.split(":")[2]
    
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
        
            # Read line by line and match each one with the values obtained from the SIP INVITE message.
            for line in File:
                line = line.replace("\n","")
                line = line.replace("\r","")
                if line.find("#") == -1 and len(line) > 2:
                    if line.find(strFrom) != -1 and line.find(strContact) != -1 and line.find(strC) != -1 and line.find(strINVITE) != -1 and line.find(strUA) != -1 and line.find(strTo) != -1 :
                        # The fields of the SIP header matches the line read in the database file, so the
                        # nMatches variable is increased.
                        nMatches += 1    
                        
            
            File.close()
            
            # CPT (Historical/Trust)
            #
            #               |  nMatches = 0  | 1 < nMatches < 2 | nMatches > 3  
            # --------------|----------------|------------------|------------------
            #   Trusted     |      0.75      |       0.2        |       0.05
            #   Distrusted  |      0.05      |       0.2        |       0.75
            #
            
            # Assigns values to lambda_to_parent according to the number of times that the SIP INVITE message
            # was found in the database.
            if nMatches == 0:
                lambda_to_parent = (0.75,0.05)
                
            elif nMatches == 1 or nMatches == 2:
                lambda_to_parent = (0.2,0.2)
                
            elif nMatches >= 3:
                lambda_to_parent = (0.05,0.75)
        
        else: # If the database file doesn't exist
            
            # The database file was not found, so it's assumed that the SIP INVITE message was never seen
            # before, and it's likely to be trusted.
            lambda_to_parent = (0.9,0.1)
                   
                   
        self.Print("Historical number of matches: " + str(nMatches), self.verbose)
        
        if self.verbose == True: self.results("Historical number of matches: " + str(nMatches))
                
        # Store tha information of the current SIP INVITE message for future analyses.
        try:
            File = open("./historical/database.txt", "a")
        
        except:
            self.Print("WARNING Can't read /historical/database.txt. The historical analysis is not completed.")
            return (1,1)
            
        strDataToStore = strFrom + "|" + strContact + "|" + strC + "|" + strINVITE + "|" + strUA + "|" + strTo
            
        self.Print("Historical data: " + strDataToStore, self.verbose)
        if self.verbose == True: self.results("Historical data: " + strDataToStore)
                
        File.write(strDataToStore + "\n")
            
        File.close()
    
        return lambda_to_parent
    
    
    
    # def checkto
    #
    # Checks if the To field of the SIP headers matches with a registered extension of the honeypot.
    #
    # Returns the vector lambda to_parent to.
    
    def checkto(self):
       
        # CPT (To/Nature)
        #
        #               |    Yes    |    No     |
        # --------------|-----------|-----------|
        #   Trusted     |    0.9    |    0.1    |
        #   Suspicious  |    0.3    |    0.7    |
        #   Crafted     |    0.1    |    0.9    |
        #
    
        CPT_matrix = [(0.9,0.3,0.1),(0.1,0.7,0.9)]
        
        # Get the "To" field and strip it to get the extension number.
        strMessageExtension = GetSIPHeader("To",self.Message).partition("@")[0].partition(":")[2].partition(":")[2]
        
        self.Print("Extension in To: " + str(strMessageExtension), self.verbose)
        if self.verbose == True: self.results("Extension in To: " + str(strMessageExtension))
        
        lambda_whois = (0, 1) # By default the "To" doesn't match.
        
        # Now it checks if the extension contained in the "To" field is one of the honeypot's registered
        # extesions. If it does, the message is likely to be normal (human dialing error).
        for i in range(len(self.Extensions)):
            if str(self.Extensions[i]) == str(strMessageExtension):
                # The extension contained in the "To" field is an extension of the honeypot.
                lambda_whois = (1, 0)
            
        # Calculates the to_parent lambda and returns it back.
        if lambda_whois[0] == 1:
            lambda_to_parent = (CPT_matrix[0][0]*lambda_whois[0],CPT_matrix[0][1]*lambda_whois[0],CPT_matrix[0][2]*lambda_whois[0])
        else:
            lambda_to_parent = (CPT_matrix[1][0]*lambda_whois[1],CPT_matrix[1][1]*lambda_whois[1],CPT_matrix[1][2]*lambda_whois[1])
            
        beta = (1 / (lambda_to_parent[0] + lambda_to_parent[1] + lambda_to_parent[2])) # Normalization constant
        
        lambda_to_parent = (lambda_to_parent[0] * beta, lambda_to_parent[1] * beta, lambda_to_parent[2] * beta) # After normalization
        
        return lambda_to_parent 
        
        
    # def dispersion
    #
    # Evaluates the dispersion of the source points.
    #
    # Returns the vector lambda to_parent dispersion.
    
    def dispersion(self):
    
        strIP_A = ""    # Host in the first Via header
        strIP_B = ""    # Host in the Contact header
        strIP_C = ""    # Host in Connection parameter
        strIP_D = ""    # Host in Owner parameter 
        strIP_E = ""    # Host in the From header
    
        strIP_A = GetSIPHeader("Via:",self.Message).split(" ")[2].split(":")[0]
        strIP_B = GetSIPHeader("Contact:",self.Message).split("@")[1].split(":")[0] 
        strIP_C = GetSIPHeader("c=",self.Message)
        strIP_C = strIP_C.split(" ")[len(strIP_C.split(" "))-1]
        strIP_D = GetSIPHeader("o=",self.Message)
        strIP_D = strIP_D.split(" ")[len(strIP_D.split(" "))-1]
        strIP_E = GetSIPHeader("From",self.Message) 
        strIP_E = strIP_E.split("<")[len(strIP_E.split("<"))-1].split("@")[len(strIP_E.split("<")[len(strIP_E.split("<"))-1].split("@"))-1].split(">")[0].split(":")[0]
            
    
        # The port used in the traceroute will be 80 
        # FIXME: this part must be fixed because the port 80 would not be opened
         
        strPort = "80"
    
        nHopsA = getnumberofhops(strIP_A, strPort)
        nHopsB = getnumberofhops(strIP_B, strPort)
        nHopsC = getnumberofhops(strIP_C, strPort)
        nHopsD = getnumberofhops(strIP_D, strPort)
        nHopsE = getnumberofhops(strIP_E, strPort)
        
        strData =  "Number of hops to host in Via (" + strIP_A + "): " + str(nHopsA) + "\n"
        strData = strData + "Number of hops to host in Contact (" + strIP_B + "): " + str(nHopsB) + "\n"
        strData = strData + "Number of hops to host in Connection (" + strIP_C + "): " + str(nHopsC) + "\n"
        strData = strData + "Number of hops to host in Owner (" + strIP_D + "): " + str(nHopsD) + "\n"
        strData = strData + "Number of hops to host in From (" + strIP_E + "): " + str(nHopsE) + "\n"
        self.Print(strData, self.verbose)
        if self.verbose == True: self.results(strData)
            
        # Mean
        nMean = (nHopsA + nHopsB + nHopsC + nHopsD + nHopsE) / 5
    
        # Calculates the standard deviation
        nStandardDeviation = sqrt((pow((nHopsA - nMean),2) + pow((nHopsB - nMean),2) + pow((nHopsC - nMean),2) + pow((nHopsD - nMean),2) + pow((nHopsE - nMean),2))/4)
        
        self.Print("Dispersion = " + str(nStandardDeviation), self.verbose)
        if self.verbose == True: self.results("Dispersion = " + str(nStandardDeviation))
    
        # CPT (Trust/Dispersion)
        #
        #               |     d < 1      |   1 < d < 4    |     d > 4      |
        # --------------|----------------|----------------------------------
        #   Normal      |      0.6       |      0.3       |      0.1       |
        #   Suspicious  |      0.5       |      0.4       |      0.1       |
        #   Crafted     |      0.05      |      0.15      |      0.8       |
        #
        
        if nStandardDeviation <= 1:
            lambda_to_parent = (0.6,0.5,0.05)
        elif nStandardDeviation > 1 and nStandardDeviation < 4:
            lambda_to_parent = (0.3,0.4,0.15)
        elif nStandardDeviation >= 4:
            lambda_to_parent = (0.1,0.1,0.8)     
    
        beta = (1 / (lambda_to_parent[0] + lambda_to_parent[1] + lambda_to_parent[2])) # Normalization constant
        
        lambda_to_parent = (lambda_to_parent[0] * beta, lambda_to_parent[1] * beta, lambda_to_parent[2] * beta) # After normalization
        
        return lambda_to_parent 
    
    
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
        
    # def results
    #
    # This function store the results given in a global variable. This variable is saved into a 
    # file in save_results.    
    
    def results(self, strData):
        
        if self.strResults == "":
            self.strResults = strData
        else:
            self.strResults = self.strResults + "\n" + strData
    
    # def save_results
    #
    # Save the results in a file.
    
    def save_results(self):
        
        strTemp = self.strResults.splitlines()
            
        try:
            
            a = 0
            while 1:
                
                strFilename = strftime("%Y-%m-%d") + "_" + str(a) + ".txt"
                
                if os.path.isfile("./results/" + strFilename) == True:
                    a += 1
                else:
                    break
                   
            File = open("./results/" + strFilename, "w")
                
            for i in range(len(strTemp)):
                File.write(self.GetTime() + " " + strTemp[i].strip() + "\n")
        
            File.close()
            
        except:
            pass
        
    