#!/usr/bin/python
#
# find_assign_froms.py - a program to find references to a variable
# that appear to be assignments to a new variable
#
# This program collects all such assignments, and prints them
# this program uses find_refs.py
#
# This is part of the auto-reduce project by Sony.
# Copyright 2012 Sony Corporation

# outline:
# check for assignment and duplicates
# print lines of code

import os, sys
from subprocess import Popen, PIPE
import re
import find_refs

# declare the patterns here
# in the following pattern, %s is replaced by the field_name
assign_from_pat_fmt = "([a-zA-Z_\-\>\.]+?)\s*=.+%s"
assign_from_pat_fmt = "([a-zA-Z_\-\>\.]+?)\s*=[^=]+%s"

def usage():
	print """Usage: find_assign_froms.py [options] <field_name>

find_assign_froms.py tries to analyze the output from find_refs.py
to find direct assignments to other data variables.

-h        show usage help
"""
	sys.exit(1)

def main():
	if '-h' in sys.argv or '--help' in sys.argv:
		usage()

	if len(sys.argv)!=2:
		print "Error: Missing <field_name>\n"
		usage()

	field_name = sys.argv[1]
	lines = find_refs.get_compile_errors(keep_tempfiles=1)
	ref_list = find_refs.parse_errors(lines, field_name)

	assign_from_pat = assign_from_pat_fmt % field_name

	for ref in ref_list:
		print "src_line='%s'" % ref.src_line
		m = re.search(assign_from_pat, ref.src_line)
		if m:
			print " at %s:%s" % (ref.filename, ref.line_no)
			assign_target = m.groups()[0]
			print " possible assignment to '%s' from '%s'" % (assign_target, field_name)

if __name__=="__main__":
	main()	

