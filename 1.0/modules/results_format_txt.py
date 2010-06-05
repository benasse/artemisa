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

from time import strftime

def get_results_txt(strFilename, strTempResultsFile, Message, VERSION, LocalIP, LocalPort):
	"""
	Keyword Arguments:
	strFilename -- results file
	strTempResultsFile -- temporary file which contain the results
	Message -- the SIP message analyzed
	VERSION -- version of Artemisa
	LocalIP -- local address where Artemisa is listening	
	LocalPort -- local port where Artemisa is listening

	This function returns the results in plain text format.
	"""
	
	strPage = "Artemisa's report" + "\n"
	strPage = strPage + "******************************************************************************************" + "\n"
	strPage = strPage + "Results" + "\n"
	strPage = strPage + "******************************************************************************************" + "\n"
	strPage = strPage + "\n"
	
	# Here it opens the temporary file which contain the results
	File = open(strTempResultsFile, "r")
	strData = File.read()
	File.close()
	   	   
	strPage = strPage + strData + "\n"
	
	strPage = strPage + "******************************************************************************************" + "\n"
	strPage = strPage + "Raw SIP message" + "\n"
	strPage = strPage + "******************************************************************************************" + "\n"
	strPage = strPage + "\n"

	strPage = strPage + Message + "\n"
	strPage = strPage + "\n"
	strPage = strPage + strFilename + ": This is an automatically generated report by Artemisa version " + VERSION + " on " + strftime("%b %d %Y %H:%M:%S") + " running at " + LocalIP + ":" + LocalPort + "."  + "\n"

	return strPage
