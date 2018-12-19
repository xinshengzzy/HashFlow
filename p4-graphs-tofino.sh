#!/bin/bash

#
# Function: check_environment
#
# Ensure that $SDE and $SDE_INSTALL are properly set. Use reasonable defaults
#
packages=packages         # The SDE subdirectory SDE where package tarballs are
pkgsrc=pkgsrc             # The SDE subdirectory, where tarbals are untarred
build=build               # The SDE subdirectory, where the builds are done
logs=logs                 # The SDE subdirectory, where build logs are stored

check_environment() {
    if [ -z $SDE ]; then
        echo "WARNING: SDE Environment variable is not set"
        echo "         Assuming $PWD"
        export SDE=$PWD
    else 
        echo "Using SDE ${SDE}"
    fi

    #
    # Basic Checks that SDE is valid
    #
    if [ ! -d $SDE ]; then
        echo "  ERROR: \$SDE ($SDE) is not a directory"
        exit 1
    fi

    if SDE_MANIFEST=`ls $SDE/*.manifest >& /dev/null`; then 
        echo Found `basename $SDE_MANIFEST .manifest`
    else
        echo "  ERROR: SDE manifest file not found in \$SDE"
        exit 1
    fi
    
    if [ -z $SDE_INSTALL ]; then
        echo "WARNING: SDE_INSTALL Environment variable is not set"
        echo "         Assuming $SDE/install"
        export SDE_INSTALL=$SDE/install
    else
        echo "Using SDE_INSTALL ${SDE_INSTALL}"
    fi
    
    if [[ ":$PATH:" == *":$SDE_INSTALL/bin:"* ]]; then
        echo "Your path contains \$SDE_INSTALL/bin. Good"
    else
        echo "Adding $SDE_INSTALL/bin to your PATH"
        PATH=$SDE_INSTALL/bin:$PATH
    fi

    SDE_PACKAGES=$SDE/$packages
    SDE_PKGSRC=$SDE/$pkgsrc
    SDE_BUILD=$SDE/$build
    SDE_LOGS=$SDE/$logs

    return 0
}

check_environment

exec $SDE_INSTALL/bin/p4-graphs -D__TARGET_TOFINO__ -I$SDE_INSTALL/share/p4_lib --primitives $SDE_INSTALL/share/p4_lib/tofino/primitives.json "$@"
