import random
from struct import pack
import math

class myRsa:
	
	def __init__(self):
		self.pPrimes = (3329L, 13613L, 15739L, 21893L, 25997L)
		self.qPrimes = (2203L, 24151L, 9857L, 43451L, 27653L)
		self.ePrimes = (29363L, 36343L, 43313L, 50333L, 54331L)

	#compute max bits of every encrypted char
	def __calcMaxBit__(self):
		maxN = max(self.pPrimes)*max(self.qPrimes)
		self.pckSize = int(math.ceil(math.ceil(math.log(maxN, 2))/8))

	def init(self, n=None, e=None, d=None):
		if n == None or e==None or d==None:
			return self.create()

		self.n = long(n)
		self.e = long(e)
		self.d = long(d)

		self.__calcMaxBit__()
		return self

	def create(self, p=None, q=None, e=None):
		#it's just an example, more primes here: http://primes.utm.edu/lists/small/10000.txt
		if p == None:
			t = random.randrange(len(self.pPrimes))		
			p = self.pPrimes[t] 

		if q == None:
			t = random.randrange(len(self.qPrimes))	
			q = self.qPrimes[t]

		self.n = p*q
		phi = (p-1)*(q-1)
		t = random.randrange(len(self.ePrimes))
		self.e = e or self.ePrimes[t]
		self.d = self.modinv(self.e, phi)

		self.__calcMaxBit__()
		return self

		#self.pubKey = (n, e)
		#self.privKey = (n, d)

	def egcd(self, a, b):
		if a == 0:
		    return (b, 0, 1)
		else:
		    g, y, x = self.egcd(b % a, a)
		    return (g, x - (b // a) * y, y)

	def modinv(self, a, m):
		g, x, y = self.egcd(a, m)
		if g != 1:
		    raise Exception('modular inverse does not exist')
		else:
		    return long(x % m)

		
	def encrypt(self, msg):
		m = long(ord(msg))
		if m > self.n:
			raise Exception("m > n") #just for fun: it's always

		c = pow(m, self.e, self.n) # c = (m^e) % n

		return self.int2bytes(c)

	def decrypt(self, msg):
		c = self.bytes2int(msg)

		m = pow( long(c), self.d, self.n) # m = (c^d) % n
		return chr(m & 0xFF)

	#https://bitbucket.org/sybren/python-rsa >  python-rsa / rsa / _version200.py 
	def bytes2int(self, bytes):
		"""Converts a list of bytes or a string to an integer
		>>> bytes2int('\x80@\x0f')
		8405007
		"""

		# Convert byte stream to integer
		integer = 0L
		for byte in bytes:
		    integer *= 256
		    integer += ord(byte)

		return integer

	#https://bitbucket.org/sybren/python-rsa >  python-rsa / rsa / _version200.py 
	def int2bytes(self, number):
		"""
		Converts a number to a string of bytes
		"""

		string = ""
		count = 0
		while number > 0:
			string = "%s%s" % (pack("B", (number & 0xFF)), string)
			number /= 256
			count += 1

		if self.pckSize != count:
			for i in range(self.pckSize-count):
				string = "%s%s" % (pack("B", 0), string)
		
		return string
