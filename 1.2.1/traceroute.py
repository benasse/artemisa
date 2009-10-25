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

import socket
import struct

# def getnumberofhops
#
# This function performs a traceroute in order to get the number of hops to the strIP host.

# NOTE: For simplicity reasons this function performs a TCP SYN traceroute. In future implementations,
# it would be interesting to send SIP OPTIONS messages to the host, and decrement the TTL of the IP
# header as well.

def getnumberofhops(IP, Port):
    
    Address = (IP, int(Port))
    
    if IP == "127.0.0.1":
        return 1
    
    for nTTL in range(1, 30):
        TCPSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        TCPSock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, struct.pack('I', nTTL))
        TCPSock.settimeout(2)
        
        try:
        
            try:
                TCPSock.connect(Address)
            except:
                continue
            
        finally:
            TCPSock.close()
            
        break
    
    return nTTL