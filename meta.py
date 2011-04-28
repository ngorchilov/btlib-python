import btlib.bcode
import types
import pprint
import hashlib
import StringIO
import urllib2
import os
import zlib
import numpy
import math

class Meta(dict):

	datadir = filename = pp = None
	
	def __init__(self, **kargs):
		torrent = url = None

		if 'torrent' in kargs: meta = kargs.pop('torrent')
		if 'datadir' in kargs:
			self.datadir = str(kargs.pop('datadir')).rstrip('/')
		else:
			self.datadir = "."
		if 'filename' in kargs: self.filename = kargs.pop('filename')
		if 'url' in kargs: url = kargs.pop('url')
		if 'indent' in kargs:
			self.pp = pprint.PrettyPrinter(indent = kargs.pop('indent'))
		else:
			self.pp = pprint.PrettyPrinter(indent = 4)
		if 'key' in kargs: self.key(key = kargs.pop('key'))
		if 'keyfile' in kargs: self.key(filename = kargs.pop('keyfile'))
			

		super(Meta, self).__init__(kargs)

		if torrent: self.set(torrent)
		if self.filename: self.load()
		if url: self.fetch(url)
		
	def set(self, torrent):
		self.clear()
		if torrent:
			if type(torrent) is types.StringType: # bencoded data
				try:
					self.update(btlib.bcode.bdecode(torrent))
				except:
					pass;
			elif type(torrent) is types.DictionaryType: # bdecoded data
				self.update(torrent.copy())
			else:
				raise ValueError

	def key(self, **kargs):
		if 'key' in kargs: self.key_value = kargs.pop('key')
		if 'filename' in kargs:
			f = open(kargs.pop('filename'), 'rb')
			self.key_value = f.read(20);
			f.close()
		return self.key_value

	def obfuscate(self, data, key=None, pos=0):
		if not key: key = self.key()
	
		# rotate the key
		key = key[pos:]+key[:pos]
		
		# multiplicate it in order to match the data's size
		key = (key*int(math.ceil(float(len(data))/float(len(key)))))[:len(data)]
	
		# Select the type size		
		for i in (8,4,2,1):
			if not len(data) % i: break
	
		if i == 8: dt = numpy.dtype('<Q8');
		elif i == 4: dt = numpy.dtype('<L4');
		elif i == 2: dt = numpy.dtype('<H2');
		else: dt = numpy.dtype('B');
		
		return numpy.bitwise_xor(numpy.fromstring(key, dtype=dt), numpy.fromstring(data, dtype=dt)).tostring()
		
	def info_hash(self):
		if 'info' in self:
			return hashlib.sha1(btlib.bcode.bencode(self['info']))
		else:
			return None
	
	def info_hash_obfuscated(self):
		return self.obfuscate(self.info_hash().digest())
		
	def pieces_generator(self, hash_check=True, debug=False):
		"""Yield pieces and their sha1 checksum from data file(s)."""
		piece_length = self['info']['piece length']
		if hash_check:
			pieces = StringIO.StringIO(self['info']['pieces'])

		if 'files' in self['info']: # yield pieces from a multi-file torrent
			piece = ""
			for file_info in self['info']['files']:
				if debug and vars().has_key('path'): print "OK"
				path = os.sep.join([self.base()] + file_info['path']).decode('UTF-8')
				if debug: print "%s: " % path,
				sfile = open(path, "rb")
				while True:
					piece += sfile.read(piece_length-len(piece))
					if len(piece) != piece_length:
						sfile.close()
						break
					
					if hash_check:
						yield (piece, hashlib.sha1(piece).digest() == pieces.read(20))
					else:
						yield (piece, True)
						
					piece = ""
			# Last piece
			if piece != "": # If found
				if hash_check:
					yield (piece, hashlib.sha1(piece).digest() == pieces.read(20))
				else:
					yield (piece, True)
				if debug: print "OK"
			elif hash_check and pieces.read(20): # If data finished but there still unerad piece hashes in the stream report this fact
				yield (None, False)
			
		else: # yield pieces from a single file torrent
			path =  self.base()
			if debug: print "%s: " % path,
			sfile = open(path, "rb")
			while True:
				piece = sfile.read(piece_length)
				if not piece:
					sfile.close()
					
					# ensure we've read all pieces
					if pieces.read(20):
						yield (None, False)
					else:
						if debug: print "OK"
				if hash_check:
					yield (piece, hashlib.sha1(piece).digest() == pieces.read(20))
				else:
					yield (piece, True)

	def obfuscated_pieces_generator(self, hash_check=True, debug=False):
		pieces = StringIO.StringIO(self['info']['pieces'])
		pos = 0
		
		for (piece, check) in self.pieces_generator(hash_check, debug):

			# hash-check
			if hash_check and not check:
				yield (None, False)

			# obfuscate the piece data piece's sha1
			piece = self.obfuscate(piece, pieces.read(20), pos)

			# yeld the piece
			yield (piece, check)
			
			# set new position
			pos += self['info']['piece length']

	def hash_check(self, debug=False):
		for (piece, check) in self.pieces_generator(True, debug):
			if not check:
				if debug: print "ERR"
				return False
		return True

	def name(self):
		if self['info'].has_key('name.utf-8'):
			return unicode(self['info']['name.utf-8'], 'utf8')
		else:
			if self['info'].has_key('encoding'):
				return unicode(self['info']['name'], self['info']['encoding'])
			else:
				return self['info']['name']
					
	def base(self):
		return os.sep.join([self.datadir, self['info']['name']]).decode('UTF-8')

	def encode(self):
		return btlib.bcode.bencode(self)
	
	def decode(self, torrent = None):
		if torrent: self.set(torrent)
		return self
	
	def is_dir(self):
		return 'info' in self and 'files' in self['info']

	def is_file(self):
		return 'info' in self and 'files' not in self['info']
	
	def announce(self, announce = None):
		if announce: # Wanna add announce url(s)?
			if type(announce) is types.StringType: announce = [[announce]]
			self.reannounce(announce+self.announce())
		else: # return announce list
			return self['announce-list'] if 'announce-list' in self else [[self['announce']]]

	def reannounce(self, announce):
		if type(announce) is types.ListType: # url list
			self['announce'] = announce[0][0]
			self['announce-list'] = []
			for a in announce: self['announce-list'].append(a)
			return self['announce-list']
		else: # single string
			if 'announce-list' in self: del self['announce-list']
			self['announce'] = announce
			return self['announce']

	def size(self):
		s = 0
		if self.is_dir(): # Mutli-file torrent
			for file in self['info']['files']:
				s += file['length']
		else: # Single-file torrent
			s = self['info']['length']
		return int(s)

	def size_in_mb(self):
		return int(round(self.size()/1024/1024))

	def size_in_gb(self):
		return float("%.2f" % float(float(self.size())/1024/1024/1024))

	def load(self, filename = None):
		if filename: self.filename = filename
		infile = open(self.filename, 'rb')
		self.set(infile.read())
		infile.close()
		return self

	def save(self, filename = None):
		if filename: self.filename = filename
		outfile = open(self.filename, 'wb')
		outfile.write(self.encode())
		outfile.close()
		return True
	
	def obfuscate_data(self, filename, hash_check=True, debug = False):
		st = os.stat(self.base())
		outfile = open(filename, 'wb')
#		os.utime(filename, (st.st_atime, st.st_mtime))
		for (piece, check) in self.obfuscated_pieces_generator(hash_check, debug):
			if hash_check and not check:
				return False
#			outfile.write(piece)
		outfile.close()
		os.utime(filename, (st.st_atime, st.st_mtime))
		return True
	
	def fetch(self, url, timeout = None):
		infile = urllib2.urlopen(url, timeout)
		if infile.info().gettype() != 'application/x-bittorrent':
			self.clear()
		else:
			data = infile.read()
			if infile.headers.get('content-encoding', '') == "gzip":
				data = zlib.decompress(data, 16+zlib.MAX_WBITS)
			self.set(data)
		infile.close()
		return self

	def pprint(self):
		return self.pp.pformat(self)
		
	def rtorrent_fast_resume(self, **kargs):
		if 'torrent' in kargs: self.set(kargs['torrent'])
		if 'datadir' in kargs: self.datadir=kargs['datadir']
		if os.path.exists(self.datadir):
			custom_storage = os.path.isfile(self.datadir)
		else:
			return False
		
		files = []
		size = 0
		
		if self.is_dir():
			for file in self['info']['files']:
				files.append(os.sep.join([self.base()] + file['path']).decode('UTF-8'))
				size += file['length']
		else:
			files.append(self.base())
			size = self['info']['length']
		
		self['libtorrent_resume'] = {
			'bitfield': long((size + self['info']['piece length'] - 1) / self['info']['piece length']),
			'files': []
		};
		
		for file in files:
			if custom_storage: file = self.datadir

			if os.path.exists(file):
				self['libtorrent_resume']['files'].append({'priority': long(2), 'mtime': long(os.stat(file).st_mtime)})
			else:
				return False
		
		return True