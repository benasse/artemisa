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

# def GetTime
#
# Returns the time in a specific format.

def GetTime():
	return "[" + str(strftime("%Y-%m-%d %H:%M:%S")) + "]"

# def Search
#
# Search a value in a bunch of data and return its content. The values to search have the
# structure "label=value"

def Search(strLabel, strData):

	strTemp = strData.splitlines(True)
	
	for line in strTemp:
	   if line.search(strLabel + "=") != -1:
	   	   return strData.split("=")[1]

	return ""


# def GetSIPHeader
#
# Search a line of the SIP header and returns it.

def GetSIPHeader(strKeyword, strData):

	strTemp = strData.splitlines(True)

	for line in strTemp:
		if line[0:len(strKeyword)] == strKeyword:
			return line.strip()

	return ""

