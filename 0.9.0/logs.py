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

import os
from time import strftime

# TODO: the log system could be better. In fact, the logging module which comes
# with Python could be a good choice. 

# def Log
#
# Save logs in a log file.

def Log(strData):
    
    strLines = strData.split("\n")
        
    try:
        strFilename = strftime("%Y-%m-%d") + ".log"
        
        if os.path.isfile("./logs/" + strFilename) == True:
            File = open("./logs/" + strFilename, "a")
        else:
            File = open("./logs/" + strFilename, "w")
            
        strTime = strftime("%Y-%m-%d %H:%M:%S")

        for i in range(len(strLines)):
            File.write(strTime + " " + strLines[i] + "\n")
    
        File.close()
        
    except:
        pass


# def TrafficLog
#
# Save logs in a log file.

def TrafficLog(strData):
    
    try:
        if os.path.isfile("./logs/traffic.log") == True:
            File = open("./logs/traffic.log", "a")
        else:
            File = open("./logs/traffic.log", "w")
            
        strTime = strftime("%Y-%m-%d %H:%M:%S")

        File.write(strTime + "\n" + strData + "\n")
    
        File.close()
        
    except:
        pass