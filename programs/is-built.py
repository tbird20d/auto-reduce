#!/usr/bin/python
# is_built.py - prints whether a C file is built in the build directory
# for a kernel
#
# this is intended to be used to prune optimization passes
# Copyright 2012 Sony Corporation

import sys, os

if len(sys.argv)<2:
	print "Missing filename: Usage: is_built.sh <filename>"
	sys.exit(1)

if not os.path.exists("MAINTAINERS"):
	print "Missing MAINTAINERS file.  You must run this command from the"
	print "root of the kernel source tree."
	sys.exit(1)
	

filename = sys.argv[1]
if not os.path.exists(filename):
	print "No such file: %s" % filename
	sys.exit(1)

if filename.endswith(".c"):
	filename = filename[:-2]
try:
	KBUILD_OUTPUT = os.environ["KBUILD_OUTPUT"]
except:
	print "WARNING: missing KBUILD_OUTPUT in environment, using '.'"
	KBUILD_OUTPUT = "."
path = KBUILD_OUTPUT+"/"+filename+".o"

print "checking for path:", path

if os.path.exists(path):
	print "%s has a .o file in the build directory" % filename
	sys.exit(0)
else:
	print "could not find %s object in the build directory" % filename
	sys.exit(1)
