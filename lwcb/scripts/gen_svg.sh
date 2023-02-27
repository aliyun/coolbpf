#!/bin/bash
set -eu

current=$(cd "$(dirname "$0")";pwd)

# if [ ! $VCG_PATH ]; then
#     echo "vcg source file path is not set"
#     exit -1
# fi

# if [ ! $SVG_PATH ]; then 
#     echo "svg file path is not set"
#     exit -1
# fi
# java -Xmx512m -jar ./scripts/yComp-1.3.19/yComp.jar --export ./out.svg ./a.vcg
java -Xmx512m -jar $current/yComp-1.3.19/yComp.jar --export $SVG_PATH $VCG_PATH