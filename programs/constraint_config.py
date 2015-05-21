# define a module for reading the constraint configuration file
import sys, os

class map_class(dict):
	def __getattr__(self, attr):
		return self.__getitem__(attr)
		#try:
		#	return self.__getitem__(attr)
		#except KeyError:
		#	return AttributeError
	def __setattr__(self, name, attr):
		if name in self:
			dict.__setattr__(self, name, attr)
		else:
			self.__setitem__(name, attr)


def print_error(message):
	sys.stderr.write("Error: "+message+"\n")
	sys.stderr.flush()

def error_out(message, rcode):
	print_error(message)
	sys.exit(rcode)

# conf file syntax
# map of maps, with constraint attributes in subsidiary map
# key for top level map is constraint name

# constraint configuration (constraints.conf) file syntax:
# ------------------------
# empty lines and lines starting with # are ignored
# section blocks begin with "constraint=<name>" and end when the 
#   next section block is encountered.
# single-line attributes are:
# name=value
# multi-line attributes are:
# name="""value line 1
# value line 2, etc."""

def read_config(config_path):
	# look in configuration directory
	info_file = os.path.basename(config_path)
	try:
		fl = open(config_path)
	except:
		error_out("Cannot open configuration file %s" % config_path, 3)

	sections = {}
	section_name = "not found"
	in_block = 0
	block = ""
	line_no = 0
	for line in fl.readlines():
		line_no += 1
		if line.startswith("#"):
			continue
		if in_block:
			# try to find end of block
			if line.rstrip().endswith('"""'):
				# remove quotes and end block
				line = line.rstrip()
				block += line[:-3] + "\n"
				sections[section_name][attr_name]= block
				in_block = 0
				continue
			else:
				block += line
				continue

		# 'constraint=' inside a block will be confusing to the user
		# but this code (above) ignores it
		# if we're outside a block, look for the start of a new constraint
		if line.startswith("constraint="):
			section_name = line.split("=")[1].strip()
			# start a new constraint map
			sections[section_name]=map_class()
			sections[section_name]["constraint"] = section_name
			sections[section_name]["name"] = section_name
			continue

		# OK, it's not a constraint, comment or middle of a block.
		# check if it's empty
		if not line.strip():
			continue

		# line better have an equals in it
		# (either single line name=value, or multi-line block start)
		if line.find("=")==-1:
			print_error("Syntax error in constraint info file %s: Expected '=' at line %d:\n%s" % (info_file, line_no, line))
			continue
		
		(attr_name, value) = line.split('=', 1)
		attr_name = attr_name.strip()
		value = value.strip()
		if value.find('"""')==-1:
			# this is a single-line, just record the attribute
			sections[section_name][attr_name] = value
		else:
			# this is the start of a multi-line block
			vstart = value.find('"""')
			block = value[vstart+3:] + '\n'
			in_block = 1
			# sanity check for block terminator on same line
			# if triple-quotes end this line, then block begins
			# and ends on the same line.
			if block.endswith('"""\n'):
				block = block[:-3]
				sections[section_name][attr_name] = block
				in_block = 0


	# check to see if any attributes are "homeless"
	if sections.has_key("not found"):
		print_error("Some attributes found outside of constraint blocks in file %s" % info_file)
		
	#print "constraints=", sections
	return sections
