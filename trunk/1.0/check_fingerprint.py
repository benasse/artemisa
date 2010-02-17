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

import sys

from commons import PrintClass, RemoveComments

# def CheckFingerprint

def CheckFingerprint(UserAgent):

    # Now the program should read the fingerprint.txt in order to get the strings to search and compare.

    try:
        File = open("./fingerprint/fingerprint.txt", "r")
        
    except:
        print "WARNING Can't read /fingerprint/fingerprint.txt."
        return -1
        
    bFound = False
        
    for line in File:
        line = line.strip()
        line = RemoveComments(line)
        if line == "": continue
        ToolName = line.split("=")[0]
        Fingerprint = line.split("=")[1]
        if UserAgent.find(Fingerprint) != -1:
            bFound = True
            break
            
    File.close()
        
    if bFound == True:
        return ToolName
    else:
        return 0
    

if __name__ == '__main__':
    if len(sys.argv) > 1:
         print CheckFingerprint(sys.argv[1])
    else:
        print "Arguments are required!"
        sys.exit(1)