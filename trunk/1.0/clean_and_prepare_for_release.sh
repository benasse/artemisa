#!/bin/bash

# WARNING:
# 
# USE THIS COMMAND CAREFULLY. THIS COMMAND WILL ERASE MANY FILES THAT ARE UNNECESSARY FOR REALEASE.

find -name "*.pyc" -print0 | xargs -0 rm -rf
find -name "*.log" -print0 | xargs -0 rm -rf
rm -f ./logs/invite_msgs/*
rm -f ./recorded_calls/*
rm -f ./results/*
rm -f ./test.py
rm -f ./modules/inference.py
rm -f ./clean_and_prepare_for_release.sh
find -name .svn -print0 | xargs -0 rm -rf
echo "Clean done!"
