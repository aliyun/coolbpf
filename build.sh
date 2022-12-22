#!/bin/bash
set -e


root=$(cd "$(dirname "$0")";pwd)

if [ -z $OBJDIR ]; then
    OBJDIR=${root}/build/coolbpf
fi

if [ -z $DESTDIR ]; then
    DESTDIR=${root}/build 
fi


make -C ${root}/third/libbpf/src OBJDIR=${OBJDIR} DESTDIR=${DESTDIR} INCLUDEDIR= LIBDIR= UAPIDIR= install
make -C ${root}/src OBJDIR=${OBJDIR} DESTDIR=${DESTDIR} INCLUDEDIR= LIBDIR= UAPIDIR= install
