import btlib.bcode
import types
import pprint
import hashlib
import urllib2
import os
import zlib
import chardet

version = "0.1.1"

class Meta(dict):

	datadir = filename = pp = None
	
	def __init__(self, **kargs):
		torrent = url = None

		if 'torrent' in kargs: meta = kargs.pop('torrent')
		if 'datadir' in kargs:
			self.datadir = kargs.pop('datadir')
		else:
			self.datadir = "."
		if 'filename' in kargs: self.filename = kargs.pop('filename')
		if 'url' in kargs: url = kargs.pop('url')
		if 'indent' in kargs:
			self.pp = pprint.PrettyPrinter(indent = kargs.pop('indent'))
		else:
			self.pp = pprint.PrettyPrinter(indent = 4)

		super(Meta, self).__init__(kargs)

		if torrent: self.set(torrent)
		if self.filename: self.load()
		if url: self.fetch(url)
		
	def set(self, torrent):
		self.clear()
		if type(torrent) is types.StringType: # bencoded data
			self.update(btlib.bcode.bdecode(torrent))
		elif type(bittorrent) is types.DictionaryType: # bdecoded data
			self.update(torrent.copy())
		else:
			raise ValueError
	
	def info_hash(self):
		if 'info' in self:
			return hashlib.sha1(btlib.bcode.bencode(self['info']))
		else:
			return None
		
	def name(self):
		if self['info'].has_key('name.utf-8'):
			return unicode(self['info']['name.utf-8'], 'utf8')
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
		else: # single string
			if 'announce-list' in self: del self['announce-list']
			self['announce'] = announce

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
		print url
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