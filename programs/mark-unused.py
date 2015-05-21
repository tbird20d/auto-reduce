#!/usr/bin/python
#
# Copyright 2012 Sony Corporation
#

import sys, os

def usage():
	print """Usage: make-unused.py [-c|<unused-spec-file>]

where <unused-spec> is a file containing lines describing unused syscalls.
This is usually created by the program find-syscalls.py.
Each line in the file that is of the form:
   unused syscall: xxx (name)

Each line with this pattern is processed, and the matching
syscall in arch/arm/kernel/calls.S is marked with the UNUSED() macro.
This program must be run at the root of the kernel source tree.

-h   show this usage help
-c   clear the UNUSED macros from calls.S
"""
	sys.exit(1)

header_top = """/*
 * unused_syscalls.h - specify a list of syscalls which are not used
 * 
 * !!! This is a generated file - created by 'mark-unused.py' !!!
 * !!! Do not hand edit, unless you know what you are doing. !!!
 */

/* start of list of unused syscalls */

"""

header_bottom = """
/* end of list of unused syscalls */
"""


def print_skip_warning(sc_no, name, line):
	print "Warning: expected line for syscall %d (%s)" % (sc_no, name)
	print "   but saw this line: ", line,
	print "...Skipping this unused syscall!"

def main():
	# parse arguments
	if '-h' in sys.argv:
		usage()
	
	clear_flag = 0
	if '-c' in sys.argv:
		sys.argv.remove('-c')
		clear_flag = 1

	try:
		unused_spec_file = sys.argv[1]
	except:
		pass

	if not clear_flag and unused_spec_file=="":
		usage()


	# read call tablea lines
	call_table_file = "arch/arm/kernel/calls.S"
	unused_syscall_header_file = "include/linux/unused_syscalls.h"

	try:
		call_lines = open(call_table_file).readlines()
	except:
		print "ERROR: Can not process call table file:", call_table_file
		exit(1)

	if clear_flag:
		print "Clearing UNUSED from calls.S file..."
		out_fd = open(call_table_file, "w")
		for line in call_lines:
			if 'USED' in line:
				pre, post = line.split('UNUSED(')
				syscall, rest = post.split(')', 1)
				newline = pre+syscall+rest
				out_fd.write(newline)
			else:
				out_fd.write(line)
		out_fd.close()

		print "Clearing UNUSED from unused_syscalls.h file..."
		out_fd = open(unused_syscall_header_file, "w")
		out_fd.write(header_top)
		out_fd.write(header_bottom)
		out_fd.close()

		exit(0)

	# process the spec file
	try:
		lines = open(unused_spec_file).readlines()
	except:
		print "ERROR: Couldn't find spec file name"
		usage()

	unused_syscalls = []
	for line in lines:
		if line.startswith("unused syscall: "):
			(junk, junk2, sc_no, name) = line.split(' ')
			name = name[1:-2]	# trim off parens and trailing \n
			unused_syscalls.append((sc_no, name))

	# test that we read the lines correctly

	# NOTE - this algorithm relies on exact line numbering in calls.S
	# this is fragile and probably bad

	# find line number base for syscall number
	syscall_0_line = 0
	for i in range(len(call_lines)):
		line = call_lines[i]
		if "sys_restart_syscall" in line:
			syscall_0_line = i

	print "Marking UNUSED syscalls in calls.S file..."
	for us in unused_syscalls:
		#print "doing: unused: %s: %s" % (us[0], us[1])
		sc_no = int(us[0])
		name = "sys_"+us[1]

		# calculate line index
		i = sc_no + syscall_0_line
		line = call_lines[i]

		if (name not in line):
			if "sys_ni_syscall" in line:
				continue
			else:
				print_skip_warning(sc_no, name, line)
				continue

		try:
			pre, post = line.split(name, 1)
		except:
			print_skip_warning(sc_no, name, line)
			continue

		# sanity check that match is followed by valid char (paren or comma)
		if not (post.startswith(')') or post.startswith(',')):
			# the name might match the comment, if this is sys_ni_syscall
			if "sys_ni_syscall" in line:
				continue
			else:
				print_skip_warning(sc_no, name, line)
				continue
			
		# sanity check that line does not already include UNUSED
		if "UNUSED" in pre:
			continue

		call_lines[i] = pre+"UNUSED("+name+")"+post
		#print call_lines[i]


	# write modified lines back out
	out_fd = open(call_table_file, "w")
	for line in call_lines:
		out_fd.write(line)

	print "Marking UNUSED syscalls in unused_syscalls.h file..."
	out_fd = open(unused_syscall_header_file, "w")
	out_fd.write(header_top)

	for us in unused_syscalls:
		name = us[1]
		# make nice columns
		num_tabs=2
		if len(name)<6: num_tabs=3
		if len(name)>13: num_tabs=1
		tabs = "\t"* num_tabs
		out_fd.write("#define IS_UNUSED_%s%s1\n" % (us[1], tabs))

	out_fd.write(header_bottom)
	out_fd.close()
	
if __name__=="__main__":
	main()
