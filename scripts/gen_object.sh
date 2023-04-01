#!/bin/bash
set -e


# generate bpf object
# ./scripts/gen_object.sh <PATH>

source_path=$1
source_list=()
arch=$(uname -m | sed 's/x86_64/x86/')

scan_files() {
    for filename in $(ls $source_path)
    do
        if [ "${filename#*.}" = "bpf.c" ]; then 
            source_list="$filename $source_list"
        fi
    done
}

if [ -d "$source_path" ]; then
    scan_files
elif [ -f "$source_path" ]; then
  echo "$source_path is a file"
fi

echo "Detected architecture: $arch"

for source in $source_list 
do
    echo "Compiling ${source}"
    clang -g -O2 -target bpf -D__TARGET_ARCH_$(arch) -I${source_path} -Ithird/ -c $source_path/$source -o $source_path/test.bpf.o
    echo $source
done
