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

def get_results_txt(Filename, VERSION, Results, LocalIP, LocalPort):
    """
    Keyword Arguments:
    Filename -- results file
    VERSION -- version of Artemisa
    Results -- an instance of commons.CallData
    LocalIP -- local address where Artemisa is listening    
    LocalPort -- local port where Artemisa is listening

    This function returns the results in plain text format.
    """
    
    Page = "Artemisa's report" + "\n"
    Page = Page + "******************************************************************************************" + "\n"
    Page = Page + "Results" + "\n"
    Page = Page + "******************************************************************************************" + "\n"
    Page = Page + "\n"
    
    Page = Page + Results.Results_File_Buffer + "\n"
    
    Page = Page + "******************************************************************************************" + "\n"
    Page = Page + "Raw SIP message" + "\n"
    Page = Page + "******************************************************************************************" + "\n"
    Page = Page + "\n"

    Page = Page + Results.SIP_Message + "\n"
    Page = Page + "\n"
    Page = Page + Filename + ": This is an automatically generated report by Artemisa version " + VERSION + " on " + strftime("%b %d %Y %H:%M:%S") + " running at " + LocalIP + ":" + LocalPort + "."  + "\n"

    return Page

def get_results_html(Filename, VERSION, Results, ForEmail, LocalIP, LocalPort):
    """
    Keyword Arguments:
    Filename -- results file
    VERSION -- version of Artemisa
    Results -- an instance of commons.CallData
    ForEmail -- flag to know if the html is for e-mail sending
    LocalIP -- local address where Artemisa is listening    
    LocalPort -- local port where Artemisa is listening

    This function returns the results in HTML format.
    """
    
    Message = Results.SIP_Message
    Message = Message.replace("<", "&lt;")
    Message = Message.replace(">", "&gt;")    
    Message = Message.replace("\n", "<br>")
    Message = Message.replace("\r", "<br>")
    
    # Some inforation should not be present if the HTML is designed to be sent by e-mail
    if not ForEmail:
        Page = "<!DOCTYPE html PUBLIC \"-//W3C//DTD HTML 4.01 Transitional//EN\">" + "\n"
        Page = Page + "<html>" + "\n"
        Page = Page + "<head>" + "\n"
        Page = Page + "<meta content=\"text/html;charset=ISO-8859-1\" http-equiv=\"Content-Type\">" + "\n"
        Page = Page + "<title>Artemisa's report of results</title>" + "\n"
        Page = Page + "</head>" + "\n"
        Page = Page + "<body>" + "\n"
        Page = Page + "<img style=\"width: 300px; height: 114px;\" alt=\"\" src=\"../res/weblogo.gif\"><br>" + "\n"
    else:
        Page = "<img style=\"width: 300px; height: 114px;\" alt=\"\" src=\"cid:weblogo\"><br>" + "\n"
        
    Page = Page + "<br>" + "\n"
    
    Page = Page + "<big style=\"color: rgb(165, 148, 137);\"><big>Artemisa's report</big></big><br><br>" + "\n"
    Page = Page + "<hr style=\"width: 100%; height: 2px;\"><big>Results<br></big>" + "\n"
    Page = Page + "<hr style=\"width: 100%; height: 2px;\"><br>"
    
    Data = Results.Results_File_Buffer
              
    Data = Data.replace("<", "&lt;")
    Data = Data.replace(">", "&gt;")    
    Data = Data.replace("\n", "<br>")
    Data = Data.replace("\r", "<br>")
    
    Page = Page + "<big><small>" + Data + "</small></big><br>" + "\n"

    Page = Page + "<hr style=\"width: 100%; height: 2px;\">"
    Page = Page + "<big>Raw SIP message</big><br>" + "\n"
    Page = Page + "<hr style=\"width: 100%; height: 2px;\"><br>"
    Page = Page + "<big><small>" + Message + "</small></big><br>" + "\n"
    Page = Page + "<hr style=\"width: 100%; height: 2px;\">"
    Page = Page + "<small><span dir=\"ltr\" id=\":3s\">" + Filename + ": This is an automatically generated report by Artemisa version " + VERSION + " on " + strftime("%b %d %Y %H:%M:%S") + " running at " + LocalIP + ":" + LocalPort + ". </span></small><br>"  + "\n"

    if not ForEmail:    
        Page = Page + "</body>" + "\n"
        Page = Page + "</html>" + "\n"

    return Page
