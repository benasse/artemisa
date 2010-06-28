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

from modules.logger import logger

def Correlator(Results, Flood):
	"""
	Keyword Arguments:
	Results -- an instance of commons.CallData
	Flood -- flag from core.py

	"""
	
	prtString = "************************************** Correlation ***************************************"; Results.Results_File_Buffer += "\n" + prtString; logger.info(prtString)
	prtString = ""; Results.Results_File_Buffer += "\n" + prtString; logger.info(prtString)
	prtString = "Artemisa concludes that the arrived message is likely to be:"; Results.Results_File_Buffer += "\n" + prtString; logger.info(prtString)
	prtString = ""; Results.Results_File_Buffer += "\n" + prtString; logger.info(prtString)

	####################################################################################
	####################################################################################
	##                                                                                ##
	## FIXME: For now, this is a very simple correlator that should be improved.      ##
	##                                                                                ##
	####################################################################################
	####################################################################################
    
	if IfCategory("Attack tool", Results.Classification) == True:
		prtString = "* The attack was created employing the tool " + Results.ToolName + "."; Results.Results_File_Buffer += "\n" + prtString; logger.info(prtString)
        
	if Flood == True:
		prtString = "* A flooding attack."; Results.Results_File_Buffer += "\n" + prtString; logger.info(prtString)
		prtString = ""; Results.Results_File_Buffer += "\n" + prtString; logger.info(prtString)
		return
     
	if IfCategory("SPIT", Results.Classification) == True:
		prtString = "* A SPIT call."; Results.Results_File_Buffer += "\n" + prtString; logger.info(prtString)
		prtString = ""; Results.Results_File_Buffer += "\n" + prtString; logger.info(prtString)
		return

	if IfCategory("Scanning", Results.Classification) == True:
		prtString = "* A scanning attempt."; Results.Results_File_Buffer += "\n" + prtString; logger.info(prtString)
		prtString = ""; Results.Results_File_Buffer += "\n" + prtString; logger.info(prtString)

	if IfCategory("Ringing", Results.Classification) == True:
		prtString = "* The message belongs to a ringing attack."; Results.Results_File_Buffer += "\n" + prtString; logger.info(prtString)
        
	prtString = ""; Results.Results_File_Buffer += "\n" + prtString; logger.info(prtString)
        
        
def IfCategory(Category, Classification):
	"""
	Returns whether a category is found or not.
	"""
	Found = False
       
	for i in range(len(Classification)):
		if Classification[i] == Category:
			Found = True
			break

	if Found == True: 
		return True
	else:
		return False
