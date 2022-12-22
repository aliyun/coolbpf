#!/bin/bash
set -e

if [ -z $OBJDIR ]; then
    OBJDIR=$(pwd)/build/coolbpf
fi

if [ -z $DESTDIR ]; then
    DESTDIR=$(pwd)/build 
fi


make -C third/libbpf/src OBJDIR=${OBJDIR} DESTDIR=${DESTDIR} INCLUDEDIR= LIBDIR= UAPIDIR= install
make -C src/ OBJDIR=${OBJDIR} DESTDIR=${DESTDIR} INCLUDEDIR= LIBDIR= UAPIDIR= install
