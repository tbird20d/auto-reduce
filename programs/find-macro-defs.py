#!/usr/bin/python
#
# Copyright 2012 Sony Corporation

import os, sys

try:
	macro_name = sys.argv[1]
except:
	print "Usage: find-macros-defs.py <macro_name>"
	sys.exit(1)

# check for whitespace before, optional whitespace and '(' after <macro_name>
cgrep = "cgrep \"\s%s\s*\(\"" % macro_name

# look for #defines
cmd = cgrep + " | grep :#define"
os.system(cmd)

# look for inlines
cmd = cgrep + " | grep inline"
os.system(cmd)
