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

FINGERPRINT_PATH = "./fingerprint/fingerprint.txt"

import sys

# Set a path to the main root
sys.path.append("../")

from commons import RemoveComments
from modules.logger import logger

def CheckFingerprint(SourceData):
    """
    Keyword Arguments:
    SourceData -- the data to where the signature will be searched

    This scripts searchs signatures in a set of data.
    """
    # Now the program should read the fingerprint.txt in order to get the strings to search and compare.
    try:
        File = open(FINGERPRINT_PATH, "r")
        
    except:
        logger.warning("Can't read " + FINGERPRINT_PATH)
        return ""
        
    Found = False
        
    for line in File:
        line = line.strip()
        line = RemoveComments(line)
        if line == "": continue
        ToolName = line.split("=")[0]
        Fingerprint = line.split("=")[1]
        if SourceData.find(Fingerprint) != -1:
            Found = True
            break
            
    File.close()
        
    if Found:
        return ToolName
    else:
        return ""
    

if __name__ == '__main__':
    if len(sys.argv) > 1:
         print CheckFingerprint(sys.argv[1])
    else:
        print "Arguments are required!"
        sys.exit(1)
