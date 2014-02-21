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

from threading import Thread		# Import Thread object from higher-level threading interface.	
from modules.xml_server import *

class ThreadXml(Thread):			# Class to generate artemisa XML-RPC Servers as a thread
    def run(self):
        xml_listen = xml_serv()
        xml_listen.xml_server_run(a=True)
        if(xml_listen.xml_arte_reload()=='reload'):
            return 'reload'
        else:
            return ':)'
            
            
        
