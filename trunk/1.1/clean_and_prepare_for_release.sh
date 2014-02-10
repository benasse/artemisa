#!/bin/bash

# This script will delete logging files, compiled python code, results files, and any
# other files which are not supposed to be in the released package. Thus, when you
# have a version ready for release, just run this script (which will be also deleted).
# This script will also create a compressed package of Artemisa.
#
# Rodrigo do Carmo
# 02 July 2010

echo -e "Are you sure you want to proceed? (y/n): \c "
read word

if [ "$word" = "y" ]; then
    
    # Here it replaces the 
    
    ver=""
    while [  "$ver" = ""  ]; do
        echo -e "Please, enter the revision number (e.g. 1.0.55): \c "
        read ver
    done
    
    sed -i "s/repvernumber/$ver/g" core.py
    echo "The version number in core.py was changed to: $ver"
    echo
    
    echo "Cleaning all the .svn directories..."
    find -name .svn -print0 | xargs -0 rm -rf
    echo "Cleaning .pyc files..."
    find -name "*.pyc" -print0 | xargs -0 rm -rf
    echo "Cleaning .log files..."
    find -name "*.log" -print0 | xargs -0 rm -rf
    echo "Cleaning all files inside ./recorded_calls..."
    rm -f ./recorded_calls/*
    echo "Cleaning all files inside ./results..."
    rm -f ./results/*
    echo "Cleaning old files..."
    rm -f ./test.py
    rm -f ./modules/inference.py
    echo "Cleaning this script..."
    rm -f ./clean_and_prepare_for_release.sh
    echo

    echo "Creating a compressed package: ../artemisa_$ver.tar.gz..."
    mkdir ../artemisa_$ver
    cp -R * ../artemisa_$ver/
    tar czf ../artemisa_$ver.tar.gz ../artemisa_$ver
    rm -Rf ../artemisa_$ver
    echo
    
    echo "Done!"
else
    echo "Cancelled"
fi