#!/usr/bin/python -u

import binascii
import pprint
import urllib2
import base64

# convert info_hash from binary to ascii hex
def bin2hex (bin_info_hash): return (binascii.b2a_hex(bin_info_hash).lower())

# convert info_hash from ascii hex to binary
def hex2bin (hex_info_hash): return (binascii.a2b_hex(hex_info_hash.upper()))

# convert info_hash from ascii hex to base64 binary
def hex2b32 (hex_info_hash): return (base64.b32encode(hex2bin(hex_info_hash.lower())))

# convert info_hash from ascii hex to base64 binary
def b322hex (b32_info_hash): return (bin2hex(base64.b32decode(b32_info_hash)))

def magnet(info_hash, name = "", trackers = []):
	magnet = "magnet:?xt=urn:btih:%s" % info_hash
	if name: magnet += "&dn=%s" % urllib2.quote(name)
	for tracker in trackers:
		magnet += "&tr=%s" % urllib2.quote(tracker)
	return magnet

# use as command line tool in format <cmd.py> <function_name> <param>
if __name__ == "__main__":
	import sys
	pp = pprint.PrettyPrinter(indent=4)
#	pp.pprint(locals())
	func = locals()[sys.argv[1]]
	pp.pprint (func(str(sys.argv[2])))
