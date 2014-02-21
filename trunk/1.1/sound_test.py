import pjsua
import _pjsua
import thread
import threading
import weakref
import time
 # If the command line parameter "-g" has been given then:
print ""
print ""
print "List of available sound devices:"
print ""
if len(_pjsua.enum_snd_devs()) == 0:
    print "No sound device detected."