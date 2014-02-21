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

from SimpleXMLRPCServer import SimpleXMLRPCServer
from SimpleXMLRPCServer import SimpleXMLRPCRequestHandler
### Restrict to a particular path.
class RequestHandler(SimpleXMLRPCRequestHandler):
    rpc_paths = ('/RPC2',)

### Create xml_serv
class xml_serv():
    def xml_server_run(self,a=False):
        if a==True:
            xml_serv = SimpleXMLRPCServer(("10.10.0.6", 8000), requestHandler=RequestHandler)
            ### funcion para permitir a los clientes utilizar metodos que esten implementados en el servidor
            xml_serv.register_introspection_functions()

            ### Register pow() function; this will use the value of
            #### pow.__name__ as the name, which is just 'pow'.
            xml_serv.register_function(pow)

            #### Register a function under a different name
            def adder_function(x,y):
                return x + y
            xml_serv.register_function(adder_function, 'add')

            #### Register an instance; all the methods of the instance are
            #### published as XML-RPC methods (in this case, just 'div').
            class MyFuncs:
                def div(self, x, y):
                    return x // y

            xml_serv.register_instance(MyFuncs())

            #### Run the xml_serv's main loop
            print 'XML xml_serv Running...'
            xml_serv.serve_forever()
        
        else:
            print 'XML Server not running'

