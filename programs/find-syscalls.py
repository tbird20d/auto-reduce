#!/usr/bin/python
#
# find-syscalls.py - read ARM objdump (disaassembly) and generates a list
# of syscalls performed by that code
#
# Copyright 2012 Sony, Inc.
#
# this program searches for 'svc	0x00000000' sequences,
# trying to determine the value of r7 at the time of the instruction.
#
# For the most part (from experiments so far), r7 is set either
# with a mov r7, #<immediate> instruction or a
# ldr r7, [pc, #<immediate>] instruction.
#
# the ldr uses a PC-offset relative address, that resolves to
# a data word, like so:
# .word 0x0000112
#  Unfortunately, this is a forward reference, so it must be fixed-up
# after the fact.
#
# if the instruction that sets r7 is not one of these types, then
# a warning is emitted.  Also, a warning is emitted is no instruction
# is found with sets r7, preceding the 'svc 0x0' in the enclosing function.
#


import sys, os
import re

def usage():
	print """Usage: find-syscalls.py [options] <disassembly-filename>"

The disassembly file should be produced with:
   $(CROSS_COMPILE)objdump -d <program> ><disassembly-filename>
where <program> is the filename of a statically linked binary.

-v     show verbose output
-h     show this usage help
-q     run quietly - omit extraneous text
-w     show detailed warnings (full function context)
--debug  show debugging information

"""
	sys.exit(1)

# define my parsing patterns here
pat_func = "[0-9a-f]{8} [<](.*)[>]"

# ldr instruction looks like: 
# 923c:	e59f7020 	ldr	r7, [pc, #32]	; 9264 <__libc_connect+0
# first field is hex, second field is decimal
pat_ldr_r7 = "\tldr*\tr7,.*"
pat_ldr_r7_extract = " *([0-9a-f]+):.*\tldr\tr7, [[]pc, #([0-9]+)[]]"

pat_mov_r7 = "\tmov[w]*\tr7,.*"
pat_mov_r7_extract = "\tmov[w]*\tr7, #([0-9]+)"

pat_svc = "\tsvc\t0x00000000"

class syscall:
	def __init__(self, function, r7_line, r7_distance, context):
		self.context = context[:]
		self.function = function
		self.r7_line = r7_line
		self.r7_distance = r7_distance
		if 'mov' in r7_line:
			self.is_mov = 1
		else:
			self.is_mov = 0
		# these are used when a forward reference is found
		self.fixup_addr = 0
		self.fixup_value = 0

	def calc_syscall_no(self):
		self.warning = ""
		if self.is_mov:
			m = re.search(pat_mov_r7_extract, self.r7_line)
			if m:
				self.syscall_no = m.group(1)
			else:
				self.syscall_no = "unknown"
				self.warning = "problem parsing r7_line:" + self.r7_line[:-1]
		else:
			self.syscall_no = str(self.fixup_value)
		return self.syscall_no
			
	def show(self):
		print "Found syscall in routine", self.function
		print "r7 instruction=", self.r7_line[:-1]
		print "r7_distance=", self.r7_distance
		self.show_syscall()
		
	def show_syscall(self):
		syscall_no = self.calc_syscall_no()

		if not quiet:
			print "syscall:",
		print syscall_no,
		try:
			name = arm_syscalls[int(syscall_no)]
		except:
			name = syscall_no
		print "(%s)" % name

		if self.warning:
			print self.warning
			print "in function '%s'" % self.function
			if verbose:
				print "Function context:"
				for line in self.context:
					print line,


def try_fixup(fixup_list, line):
	pat_data = " *([0-9a-f]+).*\t.word\t0x([0-9a-f]+)"
	m = re.match(pat_data, line)
	if not m:
		return

	addr = int(m.group(1), 16)

	sc_fixed_list = []
	for sc in fixup_list:
		if debug:
			print "in try_fixup(): addr=%x fixup_addr=%x" % (addr, sc.fixup_addr)
		if addr==sc.fixup_addr:
			if debug:
				print "found a match!!"
			sc.fixup_value = int(m.group(2),16)
			sc_fixed_list.append(sc)
	
	for sc_fixed in sc_fixed_list:
		fixup_list.remove(sc_fixed)
	
def show_sc_no_list(sc_no, sc_no_list, warning=None):
	print "syscall: %s" % sc_no,
	try:
		name = arm_syscalls[int(sc_no)]
	except:
		name = sc_no
	print "(%s)" % name,

	if len(sc_no_list)>1:
		s_suffix = "s"
	else:
		s_suffix = ""
		
	print " called %d time%s" % (len(sc_no_list), s_suffix)

	if verbose or warning:
		print "  from function%s:" % s_suffix
		for sc in sc_no_list:
			print "   ",sc.function
		if warning:
			print "Line containing r7 load:", warning.r7_line,
			if detailed_warnings:
				for line in warning.context:
					print line,
			else:
				print "   (use '-w' to see full context)"
			

def main():
	global verbose
	global debug
	global quiet
	global detailed_warnings

	if "-h" in sys.argv:
		usage()

	verbose = 0
	if "-v" in sys.argv:
		sys.argv.remove("-v")
		verbose = 1

	detailed_warnings = 0
	if "-w" in sys.argv:
		sys.argv.remove("-w")
		detailed_warnings = 1

	quiet = 0
	if "-q" in sys.argv:
		sys.argv.remove("-q")
		quiet = 1

	debug = 0
	if "--debug" in sys.argv:
		sys.argv.remove("--debug")
		debug = 1
		verbose = 1
		detailed_warnings = 1

	# remaining arg must be filename
	try:
		assembly_file = sys.argv[1]
		lines = open(assembly_file).readlines()
	except:
		print "ERROR: couldn't find disassembly-filename"
		usage()


	sc_list = []

	# some syscalls use a forward reference to set r7, of the form:
	#	<addr> 	
	fixup_list = []

	context = []
	function = ""
	last_r7 = ""
	r7_distance = 0
	max_r7_distance = 0
	max_function = ""
	of_warnings = 0
	for line in lines:
		r7_distance += 1
		if debug:
			print line,

		# keep context for debugging (only uncomment on if needed)
		context.append(line)

		# keep track of function
		m = re.match(pat_func, line)
		if m:
			function = m.group(1)
			context = [line]
			continue

		m = re.search(pat_ldr_r7, line)
		if m:
			last_r7 = line
			r7_function = function
			r7_distance = 0
			continue

		m = re.search(pat_mov_r7, line)
		if m:
			last_r7 = line
			r7_function = function
			r7_distance = 0
			continue
		
		m = re.search(pat_svc, line)
		if m:
			sc = syscall(function, last_r7, r7_distance, context)
			sc_list.append(sc)
			if r7_function != function:
				print "!!! Warning: last move to r7 was not in this function!!!"
				of_warnings += 1

				print "Found syscall in routine", function
				print "last_r7=", last_r7
				print "r7_distance=", r7_distance
			if max_r7_distance < r7_distance:
				max_r7_distance = r7_distance
				max_function = function
			if not sc.is_mov:
				fixup_list.append(sc)
				m = re.search(pat_ldr_r7_extract, sc.r7_line)
				addr = int(m.group(1),16)
				relative = int(m.group(2))
				# PC-relative addresses are from 2 words ahead
				sc.fixup_addr = addr + relative + 8
			if debug:
				sc.show()

		if fixup_list:
			try_fixup(fixup_list, line)


	# finally, generate map - with syscall_no as key
	# this is used in some outputs
	sc_numbers = {}
	for sc in sc_list:
		sc_no = sc.calc_syscall_no()
		try:
			sc_numbers[sc_no].append(sc)
		except:
			sc_numbers[sc_no]=[sc]

	
	if debug:
		for sc in sc_list:
			sc.show()

	# this is the main printout loop 
	for num in range(1,arm_syscalls_max):
		sc_no = str(num)
		if sc_numbers.has_key(sc_no):
			show_sc_no_list(sc_no, sc_numbers[sc_no])
		
	for num in range(1,arm_syscalls_max):
		sc_no = str(num)
		if not sc_numbers.has_key(sc_no):
			try:
				name = arm_syscalls[int(sc_no)]
			except:
				name = sc_no
			print "unused syscall: %s (%s)" % (sc_no, name)

	# lastly, print any unknowns
	for sc_no in sc_numbers.keys():
		try:
			sc_no_int = int(sc_no)
		except:
			print "warning:",
			# find matching sc
			scs = sc_numbers[sc_no]
			for sc in scs:
				if sc.warning:
					break
			show_sc_no_list(sc_no, sc_numbers[sc_no], sc)

	# print some trailing warnings
	unknown_warnings = 0
	for sc in sc_list:
		sc.calc_syscall_no()
		if sc.warning:
			unknown_warnings += 1

	if not quiet:
		print "max line count between set of r7 and svc instruction=", max_r7_distance
		print "function where this max occurred=", max_function
	
	if of_warnings or not quiet:
		print "number of times r7 was not set inside the same function as svc=", of_warnings
	if not quiet:
		print "warnings of unknown syscall number=", unknown_warnings


# list of ARM syscall numbers:
# this is derived from the names of the kernel functions listed in arch/arm/kernels/calls.S
arm_syscalls = {
	  0: "restart_syscall",
	  1: "exit",
	  2: "fork_wrapper",
	  3: "read",
	  4: "write",
	  5: "open",
	  6: "close",
	  7: "waitpid",		# already sys_ni_syscall
	  8: "creat",
	  9: "link",
	 10: "unlink",
	 11: "execve",
	 12: "chdir",
	 13: "time",
	 14: "mknod",
	 15: "chmod",
	 16: "lchown16",
	 17: "break",		# already sys_ni_syscall
	 18: "stat",		# already sys_ni_syscall
	 19: "lseek",
	 20: "getpid",
	 21: "mount",
	 22: "oldumount",	# OBSOLETE
	 23: "setuid16",
	 24: "getuid16",
	 25: "stime",
	 26: "ptrace",
	 27: "alarm",
	 28: "fstat",		# already sys_ni_syscall
	 29: "pause",
	 30: "utime",
	 31: "stty",		# already sys_ni_syscall
	 32: "getty",		# already sys_ni_syscall
	 33: "access",
	 34: "nice",
	 35: "ftime",		# already sys_ni_syscall
	 36: "sync",
	 37: "kill",
	 38: "rename",
	 39: "mkdir",
	 40: "rmdir",
	 41: "dup",
	 42: "pipe",
	 43: "times",
	 44: "prof",		# already sys_ni_syscall
	 45: "brk",
	 46: "setgid16",
	 47: "getgid16",
	 48: "signal", 		# already sys_ni_sycall
	 49: "geteuid16",
	 50: "getegid16",
	 51: "acct",
	 52: "umount",
	 53: "lock",		# already sys_ni_syscall
	 54: "ioctl",
	 55: "fcntl",
	 56: "mpx",		# already sys_ni_syscall
	 57: "setpgid",
	 58: "ulimit",		# already sys_ni_syscall		
	 59: "olduname",	# already sys_ni_syscall
	 60: "umask",
	 61: "chroot",
	 62: "ustat",
	 63: "dup2",
	 64: "getppid",
	 65: "getpgrp",
	 66: "setsid",
	 67: "sigaction",
	 68: "sgetmask",	# already sys_ni_syscall
	 69: "ssetmask",	# already sys_ni_syscall
	 70: "setreuid16",
	 71: "setregid16",
	 72: "sigsuspend",
	 73: "sigpending",
	 74: "sethostname",
	 75: "setrlimit",
	 76: "old_getrlimit",
	 77: "getrusage",
	 78: "gettimeofday",
	 79: "settimeofday",
	 80: "getgroups16",
	 81: "setgroups16",
	 82: "old_select",	# OBSOLETE
	 83: "symlink",
	 84: "lstat",		# already sys_ni_syscall
	 85: "readlink",
	 86: "uselib",
	 87: "swapon",
	 88: "reboot",
	 89: "old_readdir",	# OBSOLETE
	 90: "old_mmap",	# OBSOLETE
	 91: "munmap",
	 92: "truncate",
	 93: "ftruncate",
	 94: "fchmod",
	 95: "fchown16",
	 96: "getpriority",
	 97: "setpriority",
	 98: "profil",		# already sys_ni_syscall
	 99: "statfs",
	100: "fstatfs",
	101: "ioperm",		# already sys_ni_sycall
	102: "socketcall",
	103: "syslog",
	104: "setitimer",
	105: "getitimer",
	106: "stat",
	107: "lstat",
	108: "fstat",
	109: "uname",		# already sys_ni_syscall
	110: "iopl",		# already sys_ni_syscall
	111: "vhangup",
	112: "idle",		# already sys_ni_syscall (unlabled in ARM, is 'idle' in x86)
	113: "syscall",
	114: "wait4",
	115: "swapoff",
	116: "sysinfo",
	117: "ipc",
	118: "fsync",
	119: "sigreturn",
	120: "clone",
	121: "setdomainname",
	122: "uname",
	123: "modify_ldt",	# already sys_ni_syscall
	124: "adjtimex",
	125: "mprotect",
	126: "sigprocmask",
	127: "create_module",	# already sys_ni_syscall
	128: "init_module",
	129: "delete_module",
	130: "get_kernel_syms",	# already sys_ni_syscall
	131: "quotactl",
	132: "getpgid",
	133: "fchdir",
	134: "bdflush",
	135: "sysfs",
	136: "personality",
	137: "afs_syscall",	# already sys_ni_syscall
	138: "setfsuid16",
	139: "setfsgid16",
	140: "llseek",
	141: "getdents",
	142: "select",
	143: "flock",
	144: "msync",
	145: "readv",
	146: "writev",
	147: "getsid",
	148: "fdatasync",
	149: "sysctl",
	150: "mlock",
	151: "munlock",
	152: "mlockall",
	153: "munlockall",
	154: "sched_setparam",
	155: "sched_getparam",
	156: "sched_setscheduler",
	157: "sched_getscheduler",
	158: "sched_yield",
	159: "sched_get_priority_max",
	160: "sched_get_priority_min",
	161: "sched_rr_get_interval",
	162: "nanosleep",
	163: "mremap",
	164: "setresuid16",
	165: "getresuid16",
	166: "vm86",		# already sys_ni_syscall
	167: "query_module",	# already sys_ni_syscall
	168: "poll",
	169: "nfsservctl",	# already sys_ni_syscall
	170: "setresgid16",
	171: "getresgid16",
	172: "prctl",
	173: "rt_sigreturn",
	174: "rt_sigaction",
	175: "rt_sigprocmask",
	176: "rt_sigpending",
	177: "rt_sigtimedwait",
	178: "rt_sigqueueinfo",
	179: "rt_sigsuspend",
	180: "pread64",
	181: "pwrite64",
	182: "chown16",
	183: "getcwd",
	184: "capget",
	185: "capset",
	186: "sigaltstack_wrapper",
	187: "sendfile",
	188: "getpmsg",		# already sys_ni_syscall
	189: "putpmsg",		# already sys_ni_syscall
	190: "vfork",
	191: "ugetrlimit",
	192: "mmap2",
	193: "truncate64",
	194: "ftruncate64",
	195: "stat64",
	196: "lstat64",
	197: "fstat64",
	198: "lchown",
	199: "getuid",
	200: "getgid",
	201: "geteuid",
	202: "getegid",
	203: "setreuid",
	204: "setregid",
	205: "getgroups",
	206: "setgroups",
	207: "fchown",
	208: "setresuid",
	209: "getresuid",
	210: "setresgid",
	211: "getresgid",
	212: "chown",
	213: "setuid",
	214: "setgid",
	215: "setfsuid",
	216: "setfsgid",
	217: "getdents64",
	218: "pivot_root",
	219: "mincore",
	220: "madvise",
	221: "fcntl64",
	222: "TUX",		# already sys_ni_syscall
	223: "unused",		# already sys_ni_syscall
	224: "gettid",
	225: "readahead",
	226: "setxattr",
	227: "lsetxattr",
	228: "fsetxattr",
	229: "getxattr",
	230: "lgetxattr",
	231: "fgetxattr",
	232: "listxattr",
	233: "llistxattr",
	234: "flistxattr",
	235: "removexattr",
	236: "lremovexattr",
	237: "fremovexattr",
	238: "tkill",
	239: "sendfile64",
	240: "futex",
	241: "sched_setaffinity",
	242: "sched_getaffinity",
	243: "io_setup",
	244: "io_destroy",
	245: "io_getevents",
	246: "io_submit",
	247: "io_cancel",
	248: "exit_group",
	249: "lookup_dcookie",
	250: "epoll_create",
	251: "epoll_ctl",
	252: "epoll_wait",
	253: "remap_file_pages",
	254: "set_thread_area",		# already sys_ni_syscall
	255: "get_thread_area",		# already sys_ni_syscall
	256: "set_tid_address",
	257: "timer_create",
	258: "timer_settime",
	259: "timer_gettime",
	260: "timer_getoverrun",
	261: "timer_delete",
	262: "clock_settime",
	263: "clock_gettime",
	264: "clock_getres",
	265: "clock_nanosleep",
	266: "statfs64_wrapper",
	267: "fstatfs64_wrapper",
	268: "tgkill",
	269: "utimes",
	270: "arm_fadvise64_64",
	271: "pciconfig_iobase",
	272: "pciconfig_read",
	273: "pciconfig_write",
	274: "mq_open",
	275: "mq_unlink",
	276: "mq_timedsend",
	277: "mq_timedreceive",
	278: "mq_notify",
	279: "mq_getsetattr",
	280: "waitid",
	281: "socket",
	282: "bind",
	283: "connect",
	284: "listen",
	285: "accept",
	286: "getsockname",
	287: "getpeername",
	288: "socketpair",
	289: "send",
	290: "sendto",
	291: "recv",
	292: "recvfrom",
	293: "shutdown",
	294: "setsockopt",
	295: "getsockopt",
	296: "sendmsg",
	297: "recvmsg",
	298: "semop",
	299: "semget",
	300: "semctl",
	301: "msgsnd",
	302: "msgrcv",
	303: "msgget",
	304: "msgctl",
	305: "shmat",
	306: "shmdt",
	307: "shmget",
	308: "shmctl",
	309: "add_key",
	310: "request_key",
	311: "keyctl",
	312: "semtimedop",
	313: "vserver",
	314: "ioprio_set",
	315: "ioprio_get",
	316: "inotify_init",
	317: "inotify_add_watch",
	318: "inotify_rm_watch",
	319: "mbind",
	320: "get_mempolicy",
	321: "set_mempolicy",
	322: "openat",
	323: "mkdirat",
	324: "mknodat",
	325: "fchownat",
	326: "futimesat",
	327: "fstatat64",
	328: "unlinkat",
	329: "renameat",
	330: "linkat",
	331: "symlinkat",
	332: "readlinkat",
	333: "fchmodat",
	334: "faccessat",
	335: "pselect6",
	336: "ppoll",
	337: "unshare",
	338: "set_robust_list",
	339: "get_robust_list",
	340: "splice",
	341: "sync_file_range2",
	342: "tee",
	343: "vmsplice",
	344: "move_pages",
	345: "getcpu",
	346: "epoll_pwait",
	347: "kexec_load",
	348: "utimensat",
	349: "signalfd",
	350: "timerfd_create",
	351: "eventfd",
	352: "fallocate",
	353: "timerfd_settime",
	354: "timerfd_gettime",
	355: "signalfd4",
	356: "eventfd2",
	357: "epoll_create1",
	358: "dup3",
	359: "pipe2",
	360: "inotify_init1",
	361: "preadv",
	362: "pwritev",
	363: "rt_tgsigqueueinfo",
	364: "perf_event_open",
	365: "recvmmsg",
	366: "accept4",
	367: "fanotify_init",
	368: "fanotify_mark",
	369: "prlimit64",
	370: "name_to_handle_at",
	371: "open_by_handle_at",
	372: "clock_adjtime",
	373: "syncfs",
	374: "sendmmsg",
	375: "setns",
	376: "process_vm_readv",
	377: "process_vm_writev"
}
arm_syscalls_max = 377

if __name__=="__main__":
	main()
