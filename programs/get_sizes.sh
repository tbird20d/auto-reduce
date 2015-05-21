#!/bin/sh

if [ -z "$1" ] ; then
	echo "Usage: get_size.sh <extension>"
	echo
	echo "where <extension> is put at the end of each output filename"
	exit 1
fi

build_dir=../../build/nut-torvalds/
cp $build_dir/vmlinux vmlinux.$1
cp $build_dir/System.map System.map.$1
cp $build_dir/.config config.$1
size $build_dir/vmlinux $build_dir/*/built-in.o >sizes.$1
