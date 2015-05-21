#!/usr/bin/python

import constraint_config

print "Testing constraint_config.py"

cons_map = constraint_config.read_config("constraints.conf")

print cons_map

cons = cons_map["uid0"]

print cons

print "type=", cons["type"]
print "type=", cons.type

cons.foo = "bar"
cons["foo2"] = "bar2"

print "foo=", cons.foo
print "foo=", cons["foo"]

print "foo2=", cons.foo2
print "foo2=", cons["foo2"]


