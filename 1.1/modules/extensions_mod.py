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

def AddExt(ext,user,passwd):
    b = False
    archi=open('./conf/extensions.conf','r')
    lineas=archi.readlines()
    for i in range(1,len(lineas)):
        a = str(lineas[i])
        if a == ext+'\n':    
            print 'Extension '+ext+ ' already logged'
            b = True
    if b == False:
        WriteExt(ext,user,passwd)
        print 'Extension '+ext+' added'
       
    archi.close()
    
def DelExt(ext):
    b = False
    archi=open('./conf/extensions.conf','r')
    lineas=archi.readlines()
    
    for i in range(1,len(lineas)):
        a = str(lineas[i])
        if a == ext+'\n':
            print 'Extension '+ext+' deleted'
            lineas[i] = ''
            lineas[i+1] = ''
            lineas[i+2] = ''
            b = True    
            
    archiRw=open('./conf/extensions.conf','w')
    for i in range(0,len(lineas)):
        archiRw.write(lineas[i])
    archiRw.close()    
    
    if b == False:
        print 'Extension '+ext+' does not exists'
    
    archi.close()
    
def WriteExt(ext,user,passwd):
    archi=open('./conf/extensions.conf','a')
    archi.write('\n')
    archi.write(ext + '\n')
    archi.write('username='+user + '\n')
    archi.write('password='+passwd + '\n')
    archi.close()    
        
'''
######################################################
'''

ext = '[phone_5]'
user = '"phone_5"'
passwd = '1005'

ext1 = '[phone_6]'
user1 = '"phone_6"'
passwd1 = '1006'

ext2 = '[phone_4]'
user2 = '"phone_4"'
passwd2 = '1004'

AddExt(ext1,user1,passwd1)
AddExt(ext2,user2,passwd2)
DelExt(ext)