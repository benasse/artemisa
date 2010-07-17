#!/bin/bash

# This script is executed when flooding is detected. It may be used to activate some firewall rule and avoid a DoS attack.

#You can use this to set a rule in iptables and block the attacker
#iptables -I INPUT -s $1 -j DROP
