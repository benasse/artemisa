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


from time import strftime
from logs import log                # Import class log from logs.py

# class GetTimeClass
#
# Returns the time in a specific format.

class GetTimeClass:
	def GetTime(self):
		return "[" + str(strftime("%Y-%m-%d %H:%M:%S")) + "]"

# def Search
#
# Search a value in a bunch of data and return its content. The values to search have the
# structure "label=value"

def Search(strLabel, strData):

	strTemp = strData.splitlines()
	
	for line in strTemp:
	   if line.search(strLabel + "=") != -1:
	   	   return strData.split("=")[1]

	return ""


# def GetSIPHeader
#
# Search a line of the SIP header and returns it.

def GetSIPHeader(strKeyword, strData):

	strTemp = strData.splitlines()

	for line in strTemp:
		if line[0:len(strKeyword)] == strKeyword:
			return line.strip()

	return ""


# class PrintClass
#
# This simple class prints strData in console (unless bPrint is False) and log it.

class PrintClass(log, GetTimeClass):
	
	def Print(self, strData, bPrint=True):
	
		strTemp = ""	
		strTemp = strData.splitlines()
		
		if bPrint == True:
		   for line in strTemp:
		   	   print self.GetTime() + " " + line.strip()
		   	   
		self.Log(strData)
		