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

def get_results_html(strFilename, strTempResultsFile, ForEmail, Message, VERSION, LocalIP, LocalPort):
	"""
	Keyword Arguments:
	strFilename -- results file
	strTempResultsFile -- temporary file which contain the results
	ForEmail -- boolean to determine whether the HTML should or not be formatted to be sent by e-mail
	Message -- the SIP message analyzed
	VERSION -- version of Artemisa
	LocalIP -- local address where Artemisa is listening	
	LocalPort -- local port where Artemisa is listening

	This function returns the results in HTML format.
	"""
	
	Message = Message.replace("<", "&lt;")
	Message = Message.replace(">", "&gt;")	
	Message = Message.replace("\n", "<br>")
	Message = Message.replace("\r", "<br>")
	
	if ForEmail == False:
		strPage = "<!DOCTYPE html PUBLIC \"-//W3C//DTD HTML 4.01 Transitional//EN\">" + "\n"
		strPage = strPage + "<html>" + "\n"
		strPage = strPage + "<head>" + "\n"
		strPage = strPage + "<meta content=\"text/html;charset=ISO-8859-1\" http-equiv=\"Content-Type\">" + "\n"
		strPage = strPage + "<title>Artemisa's report of results</title>" + "\n"
		strPage = strPage + "</head>" + "\n"
		strPage = strPage + "<body>" + "\n"
	
	if ForEmail == False:
		strPage = strPage + "<img style=\"width: 300px; height: 114px;\" alt=\"\" src=\"../res/weblogo.gif\"><br>" + "\n"
	else:
		strPage = "<img style=\"width: 300px; height: 114px;\" alt=\"\" src=\"cid:weblogo\"><br>" + "\n"
		
	strPage = strPage + "<br>" + "\n"
	
	strPage = strPage + "<big style=\"color: rgb(165, 148, 137);\"><big>Artemisa's report</big></big><br><br>" + "\n"
	strPage = strPage + "<hr style=\"width: 100%; height: 2px;\"><big>Results<br></big>" + "\n"
	strPage = strPage + "<hr style=\"width: 100%; height: 2px;\"><br>"
	
	# Here it opens the temporary file which contain the results
	File = open(strTempResultsFile, "r")
	strData = File.read()
	File.close()
	   	   
	strData = strData.replace("<", "&lt;")
	strData = strData.replace(">", "&gt;")	
	strData = strData.replace("\n", "<br>")
	strData = strData.replace("\r", "<br>")
	
	strPage = strPage + "<big><small>" + strData + "</small></big><br>" + "\n"

	strPage = strPage + "<hr style=\"width: 100%; height: 2px;\">"
	strPage = strPage + "<big>Raw SIP message</big><br>" + "\n"
	strPage = strPage + "<hr style=\"width: 100%; height: 2px;\"><br>"
	strPage = strPage + "<big><small>" + Message + "</small></big><br>" + "\n"
	strPage = strPage + "<hr style=\"width: 100%; height: 2px;\">"
	strPage = strPage + "<small><span dir=\"ltr\" id=\":3s\">" + strFilename + ": This is an automatically generated report by Artemisa version " + VERSION + " on " + strftime("%b %d %Y %H:%M:%S") + " running at " + LocalIP + ":" + LocalPort + ". </span></small><br>"  + "\n"
	strPage = strPage + "</body>" + "\n"
	strPage = strPage + "</html>" + "\n"

	return strPage

