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

from modules.ip2country.ip2country import IP2Country # Downloaded from http://www.freenet.org.nz/python/ip2country/
from commons import PrintClass

class InvestigationTools(PrintClass):

    # def whois
    #
    # Uses the whois tool and compare the result with the whois trusted table stored in the whois 
    # directory.
    #
    # Returns the vector lambda to_parent whois.
    
    def whois(self, strIP):
    
        self.Print("Executing whois " + strIP)
        
        # Try to use the whois command. If it fails, perhaps the command is not installed.
        # TODO: here there should be a better error handling.
        try:
            # Store the whois' return in a variable.
            Process = Popen("whois " + strIP, shell=True, stdout=PIPE)
            Process.wait()
            strData = Process.communicate()[0]
            
        except OSError:
            
            return -1
        
        self.Print(strData)
        
        return strData
    
    
    # def gl
    #
    # Get the geographic location of an IP address.
    #
    # Returns the vector lambda to_parent gl.
    
    def gl(self, strIP):
        
        self.Print("Executing ip2country " + strIP)
        
        # Now the IP address is given to a special function that gets the geographical location from it.
        # The value returned is a two letter code which represents a country, e.g. "AR" for Argentina.
        # In order to know what the codes are, see ip2country.py.
        # Note: this function was not developed by us, so see ip2country.py for credits.
        
        ip2c = IP2Country(verbose=False)
        strIP2C = str(ip2c.lookup(strIP)[0])
        strIP2C_long = str(ip2c.lookup(strIP)[1])
        
        self.Print(strIP2C)
        
        return strIP2C
    
if __name__ == '__main__':
    
    # run a demo
    print "I2PCountry demo"

    