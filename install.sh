#!/bin/bash
set -e
root=$(cd "$(dirname "$0")";pwd)
cd $root && mkdir -p build && cd build && cmake .. && make install
