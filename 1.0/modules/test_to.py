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

from commons import GetSIPHeader, GetIPfromSIP, GetExtensionfromSIP

# def Do_Test
#
# Performs the current tests based on the received data (usually the INVITE message).

def Do_Test(strData, strRegisteredExtensions):
    
    CPT_matrix = GetCPTmatrix("to")
        
    if CPT_matrix == -1: return (1,1)
        
    print ""
    print "+ \"To\" field coherence analysis"
    print "|"
    print "| Extension in field To: " + GetExtensionfromSIP(GetSIPHeader("To",strData))
    
    lambda_whois = (0, 1) # By default the "To" doesn't match.
        
    # Now it checks if the extension contained in the "To" field is one of the honeypot's registered
    # extensions. If it does, the message is likely to be normal (human dialing error).
    for i in range(len(self.Extensions)):
        if str(self.Extensions[i].Extension) == self.To_Extension:
            # The extension contained in the "To" field is an extension of the honeypot.
            lambda_whois = (1, 0)
            self.add_results("| Is the extension registered? Yes")
            lambda_to_parent = (CPT_matrix[0][0], CPT_matrix[0][1], CPT_matrix[0][2])
                
    if lambda_whois == (0, 1):
        self.add_results("| Is the extension registered? No")
        lambda_to_parent = (CPT_matrix[1][0], CPT_matrix[1][1], CPT_matrix[1][2])
            
            
    beta = (1 / (lambda_to_parent[0] + lambda_to_parent[1] + lambda_to_parent[2])) # Normalization constant
        
    lambda_to_parent = (lambda_to_parent[0] * beta, lambda_to_parent[1] * beta, lambda_to_parent[2] * beta) # After normalization
        
    if self.verbose == True:
        if self.Behaviour_actions.count("to") > 0:
            self.add_results("| |")
            self.add_results("| (Verbose) Lambda_to_parent_to: " + str(round(lambda_to_parent[0],4)) + ", " + str(round(lambda_to_parent[1],4)) + ", " + str(round(lambda_to_parent[2],4)))
                
    return lambda_to_parent 
    
    return