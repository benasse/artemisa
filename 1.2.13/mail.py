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

from smtplib import *
from email.mime.image import MIMEImage
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

import ConfigParser                 # Read configuration files.

# class Email
#
# This class is used to handle the email part.

class Email():
    
    Enabled = True
          
    SMTP_IP = ""
    SMTP_PORT = ""
    SMTP_USERNAME = ""
    SMTP_PASSWORD = ""

    From = ""
    Recipients = ""
    
    Subject = ""
    To_header = ""
    TSLSSL = False
    
    def __init__(self):
        
        config = ConfigParser.ConfigParser()
        strTemp = config.read("./conf/artemisa.conf")
        
        if strTemp == []:
            return "WARNING The configuration file artemisa.conf cannot be read."
        else:
            try:

                if config.get("email", "enabled") == "true":
                    self.Enabled = True
                else:
                    self.Enabled = False

                self.SMTP_IP = config.get("email", "smtp_server_ip")
                self.SMTP_PORT = config.get("email", "smtp_server_port")
                self.SMTP_USERNAME = config.get("email", "smtp_server_username")
                self.SMTP_PASSWORD = config.get("email", "smtp_server_password")
                self.From = config.get("email", "from_mail")
                self.Recipients = config.get("email", "recipients_mail")
                self.To_header = config.get("email", "to_header")
                self.Subject = config.get("email", "subject")
                
                if config.get("email", "smtp_server_use_tsl_ssl") == "true":
                    self.TSLSSL = True
                else:
                    self.TSLSSL = False
     
            except:
                return "WARNING E-mail account configuration cannot be correctly read. E-mail reports cannot be sent."
    
        del config

    def sendemail(self, strData):
        
        if self.Enabled == False: return "NOTICE E-mail notification is disabled."
        if self.SMTP_IP == "": return "NOTICE No SMTP server address configured."
        if self.SMTP_PORT == "": return "NOTICE SMTP server port is not configured."
        if self.Recipients == "": return "NOTICE No recipient address is configured."
        
        msg = MIMEMultipart()
        msg['To'] = self.To_header
        msg['From'] = self.From
        msg['Subject'] = self.Subject
        
        text = MIMEText(strData)
        text.add_header("Content-Disposition", "inline")
        
        msg.attach(text)
        
        try:
            if self.TSLSSL == True:
                server = SMTP(self.SMTP_IP, int(self.SMTP_PORT))
                server.ehlo()
                server.starttls()
                server.ehlo()
                server.login(self.SMTP_USERNAME, self.SMTP_PASSWORD)
            else:
                server = SMTP(self.SMTP_IP, int(self.SMTP_PORT))
                server.ehlo()
                server.login(self.SMTP_USERNAME, self.SMTP_PASSWORD)
            
            server.sendmail(self.From, self.Recipients.split(","), msg.as_string())
            server.quit()
      
            return "NOTICE E-mail notification sent."
        
        except SMTPAuthenticationError:
            return "WARNING E-mail account username and/or password refused by SMTP server."
        except Exception, e:
            return "WARNING E-mail notification wasn't able to be sent. Error: " + str(e)
        