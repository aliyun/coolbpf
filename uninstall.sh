#!/bin/bash
set -e
root=$(cd "$(dirname "$0")";pwd)
cd ${root}/build && cat install_manifest.txt | sudo xargs rm