#!/usr/bin/env python

from DPAPI import *
import sys, os
from optparse import OptionParser

parser = OptionParser()
parser.add_option("--sid", metavar="SID", dest="sid")
parser.add_option("--entropy", metavar="ENTROPY", dest="entropy")
parser.add_option("--strong", metavar="PASSWORD", dest="strongpwd")
parser.add_option("--masterkey", metavar="DIRECTORY", dest="masterkey")
parser.add_option("--credhist", metavar="FILE", dest="credhist")
parser.add_option("--wordlist", metavar="FILE", dest="wordlist")
parser.add_option("--password", metavar="PASSWORD", dest="password")
(c, args) = parser.parse_args()

if c.entropy == None:
	c.entropy = ""
if c.strongpwd == None:
	c.strongpwd = ""

f = open(c.credhist, "r")
chp = credhist.CredHistPool(f.read())
if c.wordlist != None:
	chp.addWordlist(c.wordlist)
chp.parse()
chp.decryptWithPassword(c.password)

mkp = masterkey.MasterKeyPool()
for k in os.listdir(c.masterkey):
	if k != "Preferred":
		tmpfile = open("%s/%s" % (c.masterkey, k), "r")
		mkp.addMasterKey(tmpfile.read(), c.sid)

for b in args:
	f = open(b, "r")
	blob = blob.DpapiBlob(f.read())
	blob.parse()

	keyid = blob.getMasterkeyGUID()
	mk = mkp.getMasterKey(keyid, c.sid)
	mk.decryptWithPassword(c.password, c.sid)
	if mk.compareHMAC() == False:
		credid = mk.getCredhistGUID()
		cred = chp.lookupGUID(credid)
		mk.decryptWithHash(cred, c.sid)
		if mk.compareHMAC() == False:
			print "ERROR !!!!"
			sys.exit(1)
	blob.decrypt(mk.getValue(), c.entropy, c.strongpwd)

	print blob.getCleartext()

	print "BLOB=%r" % (blob)

sys.exit(0)

