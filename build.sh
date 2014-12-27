#!/bin/sh
make clean
PKG_CONFIG=/opt/local/bin/pkg-config PKG_CONFIG_PATH=/usr/local/lib/pkgconfig CFLAGS="-mmacosx-version-min=10.5 -arch i386 -arch x86_64" ./configure --disable-dependency-tracking --prefix=/usr/local
make -j4

