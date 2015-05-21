#!/usr/bin/python
# vim: set expandtab ts=4 sw=4 
#
# Copyright 2012 Sony Corporation

# find file with __setup(.*<search_string>
# replace __setup( with __setup_used(
# usage: -r = reset all __setup_used() to __setup()

import sys
import os
import re

def find(pattern, top='.'):
    patc = re.compile(pattern)
    for dirpath, dirnames, filenames in os.walk(top):
        for f in filenames:
            f = os.path.relpath(os.path.join(dirpath, f), top)
            if patc.match(f):
                yield f

def do_replace(f, func_patc, orig, replacement):
	print "changing",f,
	file_lines = open(f,'r').readlines()
	for i in range(len(file_lines)):
		line = file_lines[i]
		if func_patc.match(line):
			l = len(orig)
			new_line = replacement+line[l:]
			print new_line,
			file_lines[i] = new_line

	fd = open(f, 'w')
	for line in file_lines:
		fd.write(line)
	fd.close()

def do_reset(f):
	print "changing",f,
	file_lines = open(f,'r').readlines()
	for i in range(len(file_lines)):
		line = file_lines[i]
		if line.startswith("__setup_used("):
			new_line = "__setup("+line[13:]
			print new_line,
			file_lines[i] = new_line
		if line.startswith("early_param_used("):
			new_line = "early_param("+line[17:]
			print new_line,
			file_lines[i] = new_line

	fd = open(f, 'w')
	for line in file_lines:
		fd.write(line)
	fd.close()

def reset_setups():
    for f in find(".*[.][ch]"):
        file_lines = open(f,'r').readlines()
        for line in file_lines:
            if line.startswith("__setup_used(") or \
		line.startswith("early_param_sed("):
		    do_reset(f)

def main():
    try:
        func_name = sys.argv[1]
    except:
        print "Error: not enough arguments - missing <func_name>"
        print "Usage: mark-param-used.py -r|<func_name>"
        sys.exit(0)

    if func_name == "-r":
	reset_setups()
    else:
        func_pat = '__setup[\(]".*",\s*%s\s*[\)]' % func_name
        func_patc = re.compile(func_pat)
        func_pat2 = 'early_param[\(]".*",\s*%s\s*[\)]' % func_name
        func_patc2 = re.compile(func_pat2)

    for f in find(".*[.][ch]"):
        file_lines = open(f,'r').readlines()
        for line in file_lines:
            if line.startswith("__setup(") and func_name in line:
	        #print f,line,
		if func_patc.match(line):
		    #print "match"
		    do_replace(f, func_patc, "__setup(", "__setup_used(")
            if line.startswith("early_param(") and func_name in line:
	        #print f,line,
		if func_patc2.match(line):
		    #print "match"
		    do_replace(f, func_patc2, "early_param(", "early_param_used(")

if __name__=="__main__":
	main()

           	
