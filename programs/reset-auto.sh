#!/bin/sh
# reset for the next auto-reduce run
# remove temp files and restore source tree to original state

rm /tmp/find-refs*
git checkout .
