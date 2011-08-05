#!/bin/sh
# This script is meant to work around the differences on Fedora Core-based
# distributions (Redhat, CentOS, ...) compared to other common Linux
# distributions.
# 
# Usage: ./fedora_setup.sh [setup.py options]
#

arch=`uname -m`
for i in SWIG/_{ec,evp}.i; do
  sed -i -e "s/opensslconf\./opensslconf-${arch}\./" "$i"
done

SWIG_FEATURES=-cpperraswarn python setup.py $*

