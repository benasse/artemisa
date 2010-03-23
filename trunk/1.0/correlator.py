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

from commons import PrintClass

# def Correlator

def Correlator(Classification, bFlood, Results_file):
    
    Output = PrintClass()

    #Output.Print("===================================================================")
    #Output.Print("| Correlation                                                     |")
    #Output.Print("===================================================================")

    Output.Print("************************************** Correlation ***************************************",True,Results_file)
    Output.Print("",True,Results_file)
    Output.Print("Artemisa concludes that the arrived message is likely to be:",True,Results_file)
    Output.Print("",True,Results_file)
    
    ####################################################################################
    ####################################################################################
    ##                                                                                ##
    ## FIXME: For now, this is a very simple correlator that should be improved.      ##
    ##                                                                                ##
    ####################################################################################
    ####################################################################################
    
    if bFlood == True:
        Output.Print("* A flooding attack.",True,Results_file)
        Output.Print("",True,Results_file)
        return
     
    if IfCategory("SPIT", Classification) == True:
        Output.Print("* A SPIT call.",True,Results_file)
        Output.Print("",True,Results_file)
        return

    if IfCategory("Scanning", Classification) == True:
        Output.Print("* A scanning attempt.",True,Results_file)

    if IfCategory("Ringing", Classification) == True:
        Output.Print("* The message belongs to a ringing attack.",True,Results_file)
        
            
    #Output.Print("No conclusion arrived!",True,Results_file)
        
    Output.Print("",True,Results_file)
        
        
# def IfCategory
#
# Returns whether a category is found or not.
    
def IfCategory(strCategory, Classification):

    bFound = False
        
    for i in range(len(Classification)):
        if Classification[i] == strCategory:
            bFound = True
            break

    if bFound == True: 
        return True
    else:
        return False