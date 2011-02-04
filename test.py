#!/usr/bin/env python

from DPAPI import *
import sys
from optparse import OptionParser

parser = OptionParser()
parser.add_option("--type")
parser.add_option("--sid", metavar="SID", dest="sid")
parser.add_option("--entropy", metavar="ENTROPY", dest="entropy")
parser.add_option("--strong", metavar="PASSWORD", dest="strong")
parser.add_option("--password", metavar="PASSWORD", dest="password")
(c, args) = parser.parse_args()

f = open(args[0], "r")
buff = f.read()

if c.type == 'b' or c.type == "blob":
	blob = blob.DpapiBlob(buff)
	blob.parse()
	print "%r" % (blob)
	sys.exit(0)

if (c.type == "m" or c.type == "masterkey") and True: #c.sid and c.password:
	mk = masterkey.MasterKey(buff)
	mk.parse()
	mk.decryptWithPassword(c.password, c.sid)
	print "%r" % (mk)
	sys.exit(0)

if (c.type == "c" or c.type == "credhist") and c.password:
	chp = credhist.CredHistPool(buff)
	chp.parse()
	try:
	    chp.decryptWithPassword(c.password)
	except Exception as e:
	    print "oups... ", e
	print "%r" % (chp)
	sys.exit(0)

sys.exit(1)
