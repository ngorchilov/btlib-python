import urllib2
import urlparse
import btlib.bcode
import btlib.infohash

class Tracker():
	
	def __init__(self, **kargs):
		if 'url' in kargs:
			self.set_url(kargs['url'])

	def set_url(self, url):
		announce_path=scrape_path=None
		
		o = urlparse.urlparse(url)

		# udp trackers are not supported in this version
		if o.scheme != 'http':
			raise

		if o.path:
			if o.path.find('announce') != -1:
				announce_path=o.path
				scrape_path=o.path.replace("announce", "scrape")
			else:
				announce_path=o.path + int(not o.path.endswith('/')) * '/' + "announce"
				scrape_path=o.path + int(not o.path.endswith('/')) * '/' + "scrape"
		else:
			announce_path = "/announce"
			scrape_path = "/scrape"

		self.announce_url = urlparse.urlunparse((o.scheme, o.netloc, announce_path, None, None, None))
		self.scrape_url = urlparse.urlunparse((o.scheme, o.netloc, scrape_path, None, None, None))

#		print self.announce_url, self.scrape_url
		
	# scrape a tracker for a list of info_hashes, bdecode the output and return normalized directory
	def scrape(self, hash_list=[]):

		url = self.scrape_url
		
		# if hash_list is given cycle trough hashes and construct url
		if hash_list:
			url += '?'
			for info_hash in hash_list:
				url += 'info_hash=' + urllib2.quote(btlib.infohash.hex2bin(info_hash)) + '&'
#				url += 'info_hash=' + info_hash + '&'
			url = url.rstrip('&')

#		print "Scrapping ", url
		
		res=[]	
		# call the tracker and read the response in a dictionary
		try:
			ua = urllib2.urlopen(url)
			try:
				res = btlib.bcode.bdecode(ua.read())['files']
			except:
				ua.close()
				return
			ua.close()
		except:
			return
		
		# done. return the dictionary
		return(res)
		
	# announce info_hash to a tracker and collect peers, bdecode the output and return normalized directory
	def announce(self, info_hash, cmd, me):
	
		url = self.announce_url + '?info_hash=' + urllib2.quote(btlib.infohash.hex2bin(info_hash)) + "&port=65000&uploaded=0&downloaded=0&left=0&compact=1&event=started&numwant=100&peer_id=00000000000000000000" + "&event=" + cmd
		if me: url += "&me=1"
		res=[]
		# call the tracker and read the response in a dictionary
		try:
			ua = urllib2.urlopen(url)
			try:
				res = btlib.bcode.bdecode(ua.read())
			except:
				ua.close()
				return
			ua.close()
		except:
			return
		
		# done. return the dictionary
		return(res)