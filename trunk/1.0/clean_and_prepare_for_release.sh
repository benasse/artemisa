#!/bin/bash

# WARNING:
# 
# USE THIS SCRIPT CAREFULLY. THIS SCRIPT WILL ERASE MANY FILES THAT ARE UNNECESSARY FOR REALEASE.

echo -e "Are you sure you want to proceed? (y/n): \c "
read word

if [ "$word" = "y" ]; then
    find -name "*.pyc" -print0 | xargs -0 rm -rf
    find -name "*.log" -print0 | xargs -0 rm -rf
    rm -f ./recorded_calls/*
    rm -f ./results/*
    rm -f ./test.py
    rm -f ./modules/inference.py
    rm -f ./clean_and_prepare_for_release.sh
    find -name .svn -print0 | xargs -0 rm -rf
    echo "Clean done!"
else
    echo "Cancelled"
fi