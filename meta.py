import btlib.bcode
import types
import pprint
import hashlib
import binascii
import StringIO
import urllib2
import os
import zlib
import chardet

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

	def obfuscate(self, data, key=None):
		if not key: key = self.key()
		l = len(key)
		
		buff = ""
		for i in range(0, len(data)):
			buff += chr(ord(data[i]) ^ ord(key[i % l]))
		return buff
	
	def info_hash(self):
		if 'info' in self:
#			return hashlib.sha1(btlib.bcode.bencode(self['info'])).hexdigest().lower()
			return hashlib.sha1(btlib.bcode.bencode(self['info']))
		else:
			return None
	
	def info_hash_obfuscated(self):
		return self.obfuscate(self.info_hash().digest())
		
	def pieces_generator(self, debug=False):
		"""Yield pieces from download file(s)."""
		piece_length = self['info']['piece length']
		if 'files' in self['info']: # yield pieces from a multi-file torrent
			piece = ""
			for file_info in self['info']['files']:
				if debug and vars().has_key('path'): print "OK"
				path = os.sep.join([self.datadir, self.name()] + file_info['path'])
				if debug: print "%s: " % path,
				sfile = open(path.decode('UTF-8'), "rb")
				while True:
					piece += sfile.read(piece_length-len(piece))
					if len(piece) != piece_length:
						sfile.close()
						break
					yield piece
					piece = ""
			if piece != "":
				yield piece
			if debug: print "OK"
		else: # yield pieces from a single file torrent
			path = self.name()
			print path
			sfile = open(path.decode('UTF-8'), "rb")
			while True:
				piece = sfile.read(piece_length)
				if not piece:
					sfile.close()
					return
				yield piece

	def obfuscated_pieces_generator(self, debug=False):
		# key
		key = self.key()
		
		# rotation index
		rindex = self['info']['piece length'] % len(key)

		for piece in self.pieces_generator(debug):

			# obfuscate the piece
			piece = self.obfuscate(piece, key)

			# yeld the piece
			yield piece
			
			# rotate the key
			key = key[rindex:]+key[:rindex]

	def hash_check(self, debug=False):
		pieces = StringIO.StringIO(self['info']['pieces'])
		for piece in self.pieces_generator(debug):
			# Compare piece hash with expected hash
			piece_hash = hashlib.sha1(piece).digest()
			if (piece_hash != pieces.read(20)):
				return False
		# ensure we've read all pieces 
		if pieces.read():
			return False

		return True

	def name(self):
		if self['info'].has_key('name.utf-8'):
			return unicode(self['info']['name.utf-8'], 'utf8')
		else:
			if self['info'].has_key('encoding'):
				return unicode(self['info']['name'], self['info']['encoding'])
			else:
				try:
					return unicode(self['info']['name'], chardet.detect(self['info']['name'])['encoding'])
				except:
					return None

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
	
	def fetch(self, url, timeout = None):
		infile = urllib2.urlopen(url, timeout)
		if infile.info().gettype() != 'application/x-bittorrent':
			self.clear()
		else:
			data = infile.read()
			if infile.headers.get('content-encoding', '') == "gzip":
				try:
					data = zlib.decompress(data, 16+zlib.MAX_WBITS)
				except:
					data = None
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
			raise
		
		files = []
		size = 0
		
		if self.is_dir():
			for file in self['info']['files']:
#				path = os.path.join(*[self.datadir, self['info']['name']] + file['path'])
				files.append(os.path.join(*[self['info']['name']] + file['path']))
				size += file['length']
		else:
			files.append(self['info']['name'])
			size = self['info']['length']
		
		self['libtorrent_resume'] = {
			'bitfield': long((size + self['info']['piece length'] - 1) / self['info']['piece length']),
			'files': []
		};
		
		for file in files:
			if custom_storage:
				file = self.datadir
			else:
				file = os.path.join(self.datadir, file)

			if os.path.exists(file):
				self['libtorrent_resume']['files'].append({'priority': long(2), 'mtime': long(os.stat(file).st_mtime)})
			else:
				raise