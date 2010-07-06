#!/bin/bash

# This script is executed when a scanning is detected. It may be used to activate some firewall rule.

# Launch svcrash if SIPVicious tool is detected
if [ $4 == "SIPVicious" ]; then
    python $HOME/sipvicious/svcrash.py -d $1 -p $2
    exit
fi



