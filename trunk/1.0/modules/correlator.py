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

def Correlator(Classification, bFlood, Results_file, ToolName):
    
	Output = PrintClass()
	Output.PrintFile = Results_file
	Output.Print("************************************** Correlation ***************************************",True)
	Output.Print("",True)
	Output.Print("Artemisa concludes that the arrived message is likely to be:",True)
	Output.Print("",True)
    
	####################################################################################
	####################################################################################
	##                                                                                ##
	## FIXME: For now, this is a very simple correlator that should be improved.      ##
	##                                                                                ##
	####################################################################################
	####################################################################################
    
	if IfCategory("Attack tool", Classification) == True:
		Output.Print("* The attack was created employing the tool " + ToolName + ".",True)
        
	if bFlood == True:
		Output.Print("* A flooding attack.",True)
		Output.Print("",True)
		return
     
	if IfCategory("SPIT", Classification) == True:
		Output.Print("* A SPIT call.",True)
		Output.Print("",True)
		return

	if IfCategory("Scanning", Classification) == True:
		Output.Print("* A scanning attempt.",True)

	if IfCategory("Ringing", Classification) == True:
		Output.Print("* The message belongs to a ringing attack.",True)
        
	Output.Print("",True)
        
        
def IfCategory(strCategory, Classification):
	"""
	Returns whether a category is found or not.
	"""
	bFound = False
       
	for i in range(len(Classification)):
		if Classification[i] == strCategory:
			bFound = True
			break

	if bFound == True: 
		return True
	else:
		return False
