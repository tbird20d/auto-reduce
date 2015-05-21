#!/usr/bin/python
#
# find_refs.py - a program to find references to a variable
#
# This is part of the auto-reduce project by Sony.
#
# Copyright 2012 Sony Corporation

# outline:
# (manually) alter code to remove variable
# build kernel, saving off error messages
# parse error messages
# check for exceptional cases (not matching a regular reference)
# check for assignment and duplicates
# print lines of code

# 2nd phase - automatic replacement
# match lines of code to template
# replace code

import os, sys
from subprocess import Popen, PIPE
import re

# declare the patterns here
# in the following patterns, %s is replaced by the field_name
	# [^a-zA-Z0-9_] is same as \W
	# '->var' followed by non-alphanumeric
ref_pat_fmt = "([a-zA-Z0-9_\->.]+)\s*([.]|->)\s*%s(?![a-zA-Z0-9_])"
	# '->var' followed by optional whitespace and '='
assign_pat_fmt = "\w+\s*([.]|->)\s*%s\s*=[^=]"

def usage():
	print """Usage: find_refs.py [options] <field_name> [<src_field_name>]

find_refs.py tries to analyze the error output from gcc to find
references to structure elements that are missing (have been removed)
from their respective structure definitions.
<field_name> is the name of the variable as recognized by the compiler,
which might be different (due to preprocessing) from the name in the main
body of the source.  <src_field_name> is the name of the variable to
scan for in the source.

If not specified by the user, <src_field_name> defaults to the same value 
as <field_name>.

-h        show usage help
-f        force rebuild (do not use cached reference data)
-a        show all found references
-x        show only direct references 

By default, find_refs.py omits the references that are of
the form foo->bar (where 'bar' is the variable of interest)
Direct references such as these are easily patched.
"""
	sys.exit(1)


# define a class for reference points found in the code
class ref_point:
	def __init__(self, filename, line_no, src_line):
		self.filename = filename
		self.line_no = line_no
		self.src_line = src_line
		self.notes = []
		self.find_count = 1
		self.matches = []
		self.pat = ""
		self.is_assign = 0
	def add_note(self, note):
		self.notes.append(note)
	def __str__(self):
		return "ref_point instance: filename=%s, line_no=%d, src_line=%s, notes=%s, line_count=%d matches=%s" % (self.filename, self.line_no, self.src_line, self.notes, self.find_count, self.matches)

def get_compile_errors(field_name, force_rebuild, keep_tempfiles=0):
	#command = "make -i uImage"
	command = "make -i bzImage"

	# FIXTHIS - gather stderr as we go, to avoid blocking
	# for the duration of the whole compile
	"""
	process = Popen(command, stdin=PIPE, stdout=PIPE, stderr=PIPE, \
		close_fds=True, shell=True)
	process.stdin.close()
	cmd_stdout = process.stdout
	cmd_stderr = process.stderr

	rcode = process.poll()
	while rcode==None:
		print "standard output"
		# FIXTHIS - need to do a poll or select here to avoid blocking
		print cmd_stdout.read()
		print "standard error"
		print cmd_stderr.read()
		rcode = process.poll()"""
	
	tmpfile = "/tmp/find-refs-%s.errlog" % field_name
	# generate error list, if not present
	if not os.path.isfile(tmpfile) or force_rebuild:
		os.system(command+" 2>%s" % tmpfile)
	else:
		print "WARNING: using cached temp file: %s" % tmpfile
		print "To generate a new error log, do 'rm %s' and re-run this script" % tmpfile
	fd = open(tmpfile, "r")
	lines = fd.readlines()
	fd.close()
	if not keep_tempfiles:
		os.unlink(tmpfile)
	return lines

def get_source_line(filename, line_no):
	fd = open(filename, "r")
	lines = fd.readlines()
	return lines[line_no-1][:-1]

def parse_errors(lines, compiler_field_name, src_field_name):
	# FIXTHIS - pattern string may be fragile or depend on the compiler
	error_pat = "has no member named '%s'" % compiler_field_name
	error_patc = re.compile(error_pat)
	ref_pat = ref_pat_fmt % src_field_name
	ref_list = []
	for line in lines:
		#print line,
		if error_patc.search(line):
			parts = line.split(':')
			filename = parts[0]
			try:
				line_no = int(parts[1])
			except:
				print "syntax error parsing gcc error line '%s'" % line
			error = parts[2]
			src_line = get_source_line(filename, line_no)
			ref = ref_point(filename, line_no, src_line)
			ref.pat = ref_pat
			# find source line
			# construct the reference regex pattern
			if re.search(ref.pat, src_line):
				# fount a reference - record matches
				ref.matches = re.finditer(ref.pat, src_line)
				ref.find_count = len(re.findall(ref.pat, src_line))
			else:
				ref.add_note("## DOESN'T MATCH SOURCE REFERENCE PATTERN ##")

			# construct the assignment regex pattern
			assign_pat = assign_pat_fmt % src_field_name
			if re.search(assign_pat, src_line):
				ref.add_note("!! POSSIBLE ASSIGNMENT !!")
				ref.is_assign = 1
			ref_list.append(ref)

	return ref_list

# check_dups() - check for lines with multiple matches, that the
# compiler failed to identify.  This could happen due to a field
# name from another structure being referenced on the same line as
# a valid reference to the structure element being scanned for.
# e.g.  'fs_inode->uid = cred->uid'
# this code assumes that the duplicates are adjacent in the list
def check_dups(ref_list):
	i = 0
	while i < len(ref_list):
		ref = ref_list[i]
		dup_count = 0
		if ref.find_count>1:
			# scan ahead find_count entries, looking for duplicates
			# and see if count matches
			j = i+1
			while j-i < ref.find_count and j<len(ref_list):
				if ref_list[j].filename==ref.filename and \
				    ref_list[j].line_no==ref.line_no:
					dup_count = dup_count+1
				j = j+1
			if dup_count != ref.find_count-1:
				ref.add_note("## WARNING: mismatch between compiler (%d) and source references (%d) ##" % (dup_count+1, ref.find_count) )
				# don't let the outer loop skip the entries
				dup_count = 0

		# IMPORTANT: skip past the duplicates
		# (only scan for duplicates from first reference)
		i = i + 1 + dup_count

def main():
	show_all = False
	show_only_normals = False
	force_rebuild = False
	if '-h' in sys.argv or '--help' in sys.argv:
		usage()

	if '-a' in sys.argv:
		show_all = True
		sys.argv.remove('-a')

	if '-x' in sys.argv:
		show_only_normals = True
		sys.argv.remove('-x')

	if '-f' in sys.argv:
		force_rebuild = True
		sys.argv.remove('-f')

	if len(sys.argv)<2 or len(sys.argv)>3:
		print "Error: Missing <field_name>\n"
		usage()

	compiler_field_name = sys.argv[1]
	try:
		src_field_name = sys.argv[2]
	except:
		src_field_name = compiler_field_name

	lines = get_compile_errors(src_field_name, force_rebuild,
		keep_tempfiles=1)
	ref_list = parse_errors(lines, compiler_field_name, src_field_name)

	total_refs_count = len(ref_list)

	# check for duplicate pattern matches not found by the compiler 
	# This can happen when a field of the same name
	# in a different structure is present on the
	# same line as the field we're looking for
	check_dups(ref_list)
	dup_refs_count = total_refs_count - len(ref_list)

	for ref in ref_list:
		if show_all or ref.notes:
			print " at %s:%s" % (ref.filename, ref.line_no)
			print "    '%s'" % ref.src_line
			if ref.notes and not show_only_normals:
				print "## NOTES: ", ref.notes

	assign_count = 0
	mismatch_count = 0
	for ref in ref_list:
		if ref.notes:
			for note in ref.notes:
				if "ASSIGNMENT" in note:
					assign_count += 1
				if "mismatch" in note:
					mismatch_count += 1
				
	
	# show some stats:
	print "total refs:  ", total_refs_count
	print "duplicates:  ", dup_refs_count
	print "assignments: ", assign_count
	print "mismatches:  ", mismatch_count
	if assign_count or mismatch_count:
		sys.exit(1)
	else:
		sys.exit(0)

if __name__=="__main__":
	main()	

