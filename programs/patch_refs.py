#!/usr/bin/python
#
# patch_refs.py - a program to patch references to a variable
#
# This program uses find_refs.py to find the references
#
# This is part of the auto-reduce project by Sony.
#
# Copyright 2012 Sony Corporation

# outline:
# find references
# for each reference, patch it

import os, sys
import find_refs
import re

# declare the patterns here
# in the following pattern, %s is replaced by the field_name

def usage():
	print """Usage: patch_refs.py [options] <field_name> <subst_str>

patch_refs.py tries to analyze the output from find_refs.py
apply a constraint to each reference.  (Substitute the reference,
in this first pass).

<field_name> should be the name of a field to pass to find_refs, and
<substr_str> should be the string used to replace the field_name in
each reference found.  It may include exactly one '%%s' which will
be used to add the original field_name into the source.

A common subst_str is something like: '/*%s*/ 0' (sans quotes)

-h        show usage help
"""
	sys.exit(1)

def patch_ref(ref, subst_str):
	#print ref

	print "patching %s" % ref.filename

	fd = open(ref.filename,"r")
	data = fd.read()
	fd.close()

	# find the line
	lines = data.split('\n')
	file_line = lines[ref.line_no-1]
	if ref.src_line != file_line:
		print "WARNING: file line in %s doesn't match expected line" % ref.filename
		print "  src line='%s'" % ref.src_line
		print "  file line='%s'" % file_line


	# now do the change
	count = 0
	patc = re.compile(ref.pat)
	pos = 0
	m = patc.search(file_line, pos)
	while m:
        	# found a reference - replace it
		orig = m.group(0)
		#print "orig=", orig
		s = m.start(0)
		e = m.end(0)

		# not an assignment, use the user-supplied subs_str
		try:
			replacement = subst_str % orig
		except:
			replacement = subst_str

		#print "replacement=", replacement

		# handle specially if it's an assignment
		if ref.is_assign:
			next_part = file_line[e:]
			# check that next part starts with optional
			# whitespace and a single '='
			# (an '=' not followed by another '=')
			ma = re.match("(\s*=)(?!=)", next_part)
			print "patch_ref: checking for assignment"
			print "next_part='%s'" % next_part
			if ma:
				print "patch_ref: found it, adjusting values"
				orig += ma.group(0)
				e += ma.end(0)
				# just remove the assigment
				replacement = "/*replaced =*/"

		new_line = file_line[:s]+replacement+file_line[e:]
		print "new_line='%s'" % new_line
		file_line = new_line
		count += 1
		pos = s+len(replacement)
		m = patc.search(file_line, pos)

        if count != ref.find_count:
		print "Didn't replace all instances of references found!!"

	if count:
		lines[ref.line_no-1] = file_line
		data = "\n".join(lines)
	
		fd = open(ref.filename,"w")
		fd.write(data)
		fd.close()

def main():
	if '-h' in sys.argv or '--help' in sys.argv:
		usage()

	if len(sys.argv)!=3:
		print "Error: Missing argument(s)\n"
		usage()

	field_name = sys.argv[1]
	subst_str = sys.argv[2]
	lines = find_refs.get_compile_errors(field_name, 0, keep_tempfiles=1)
	ref_list = find_refs.parse_errors(lines, field_name, field_name)

	for ref in ref_list:
		patch_ref(ref, subst_str)

	# try building the kernel and see if it worked

if __name__=="__main__":
	main()	

