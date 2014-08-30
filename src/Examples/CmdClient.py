'''
Copyright (c) <2012> Tarek Galal <tare2.galal@gmail.com>

RSA Encryption added by Luciano Giuseppe <2014>

Permission is hereby granted, free of charge, to any person obtaining a copy of this 
software and associated documentation files (the "Software"), to deal in the Software 
without restriction, including without limitation the rights to use, copy, modify, 
merge, publish, distribute, sublicense, and/or sell copies of the Software, and to 
permit persons to whom the Software is furnished to do so, subject to the following 
conditions:

The above copyright notice and this permission notice shall be included in all 
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, 
INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR 
A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT 
HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF 
CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE 
OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
'''

'''
RSA Encryption messages added by Luciano Giuseppe 2014 (https://github.com/lucianogiuseppe)
'''
from Yowsup.connectionmanager import YowsupConnectionManager
import time, datetime, sys

#for a-sym communications
from _myRsa import myRsa
import re

if sys.version_info >= (3, 0):
	raw_input = input

class WhatsappCmdClient:

	def __init__(self, phoneNumber, keepAlive = False, sendReceipts = False):
		self.sendReceipts = sendReceipts
		self.phoneNumber = phoneNumber
		self.jid = "%s@s.whatsapp.net" % phoneNumber
		
		self.sentCache = {}
		
		connectionManager = YowsupConnectionManager()
		connectionManager.setAutoPong(keepAlive)
		self.signalsInterface = connectionManager.getSignalsInterface()
		self.methodsInterface = connectionManager.getMethodsInterface()
		
		self.signalsInterface.registerListener("auth_success", self.onAuthSuccess)
		self.signalsInterface.registerListener("auth_fail", self.onAuthFailed)
		self.signalsInterface.registerListener("message_received", self.onMessageReceived)
		self.signalsInterface.registerListener("receipt_messageSent", self.onMessageSent)
		self.signalsInterface.registerListener("presence_updated", self.onPresenceUpdated)
		self.signalsInterface.registerListener("disconnected", self.onDisconnected)
		
		
		self.commandMappings = {"lastseen":lambda: self.methodsInterface.call("presence_request", ( self.jid,)),
								"available": lambda: self.methodsInterface.call("presence_sendAvailable"),
								"unavailable": lambda: self.methodsInterface.call("presence_sendUnavailable"),
								"crypt": None,
								"close": None
								 }
		
		self.done = False
		#signalsInterface.registerListener("receipt_messageDelivered", lambda jid, messageId: methodsInterface.call("delivered_ack", (jid, messageId)))

		#for encrypted communication
		self.decrRcvMsgKey = myRsa().create() #generate my rsa keys
		self.encrSendMsgKey = None
		self.encrProtocolStatus = 0 # 1: request made, 2:request arrived, 3: com. is encrypted
	
	def login(self, username, password):
		self.username = username
		self.methodsInterface.call("auth_login", (username, password))

		while not self.done:
			time.sleep(0.5)

	def onAuthSuccess(self, username):
		print("Authed %s" % username)
		self.methodsInterface.call("ready")
		self.goInteractive(self.phoneNumber)

	def onAuthFailed(self, username, err):
		print("Auth Failed!")

	def onDisconnected(self, reason):
		print("Disconnected because %s" %reason)
		
	def onPresenceUpdated(self, jid, lastSeen):
		formattedDate = datetime.datetime.fromtimestamp(long(time.time()) - lastSeen).strftime('%d-%m-%Y %H:%M')
		self.onMessageReceived(0, jid, "LAST SEEN RESULT: %s"%formattedDate, long(time.time()), False, None, False)

	def onMessageSent(self, jid, messageId):
		cache = self.sentCache[messageId]
		formattedDate = datetime.datetime.fromtimestamp(cache[0]).strftime('%d-%m-%Y %H:%M')
		#software msg or received msg
		if cache[1].startswith("<<") and cache[1].endswith(">>"):
			print("%s"%(cache[1]))
		else:
			print("[%s] %s: %s"%(formattedDate, self.username, cache[1]))
		#print(self.getPrompt())

	def runCommand(self, command, jid):
		if command[0] == "/":
			if command == "/crypt":
				message = "!RSA:%d#%d"%(self.decrRcvMsgKey.n, self.decrRcvMsgKey.e)
				msgId = self.methodsInterface.call("message_send", (jid, message))
				self.encrProtocolStatus = self.encrProtocolStatus | 1 #set encr. communication request made
				if self.encrProtocolStatus == 3:
					message = "<<Communication is crypted now!>>"
				else:
					message = "<<Request sent>>"
				self.sentCache[msgId] = [int(time.time()), message]
				
				
				return 1
			else:
				command = command[1:].split(' ')
				try:
					self.commandMappings[command[0]]()
					return 1
				except KeyError:
					return 0
		
		return 0
			
	def onMessageReceived(self, messageId, jid, messageContent, timestamp, wantsReceipt, pushName, isBroadcast):
		if jid[:jid.index('@')] != self.phoneNumber:
			return
		
		if self.encrProtocolStatus == 3: #I have to decrypt a msg
			messageContent = self.decrypt(messageContent)
			formattedDate = datetime.datetime.fromtimestamp(timestamp).strftime('%d-%m-%Y %H:%M')
			print("%s [%s]:%s"%(jid, formattedDate, messageContent))

		elif re.search(r"^!RSA:\d+#\d+$", messageContent): #encrypt com. request was arrived
			tt = re.findall(r"\d+", messageContent)
			self.encrSendMsgKey = myRsa().init( long(tt[0]), long(tt[1]), 3L) #n-e-d
			self.encrProtocolStatus = self.encrProtocolStatus | 2 #set encr. com. request arrived
			if self.encrProtocolStatus == 3:
				print "<<Communication is crypted now!>>"
			else:
				print "<<Request for crypted communication arrived: use \"/crypt\" command to accept>>"

		else: # normal msg arrived
			formattedDate = datetime.datetime.fromtimestamp(timestamp).strftime('%d-%m-%Y %H:%M')
			print("%s [%s]:%s"%(jid, formattedDate, messageContent))
		
		if wantsReceipt and self.sendReceipts:
			self.methodsInterface.call("message_ack", (jid, messageId))

		#print(self.getPrompt())
	
	def goInteractive(self, jid):
		print("Starting Interactive chat with %s" % jid)
		print "My Rsa Info => n:%d, e:%d, d:%d"%(self.decrRcvMsgKey.n, self.decrRcvMsgKey.e, self.decrRcvMsgKey.d) #debug
		jid = "%s@s.whatsapp.net" % jid
		print(self.getPrompt())
		while True:
			message = raw_input()
			message = message.strip()
			if not len(message):
				continue
			if message == "/close":	
				break
			if not self.runCommand(message.strip(), jid):
				msgToCache = message #string to print when msg was sended
				if self.encrProtocolStatus == 3:
					message = self.encrypt(message) #encrypt the msg
				msgId = self.methodsInterface.call("message_send", (jid, message))
				self.sentCache[msgId] = [int(time.time()), msgToCache]
		self.done = True

	def getPrompt(self):
		return "Enter Message or command: (/%s)" % ", /".join(self.commandMappings)

	'''for crypt msg'''
	def encrypt(self, msg):
		encrMsg = []
		for char in msg:
			 encrMsg.append(self.encrSendMsgKey.encrypt(char))

		return  "".join(encrMsg).encode("base64")

	'''for decrypt msg'''
	def decrypt(self, msg):
		#print "Encripted msg: " + msg #debug
		try:
			rcvMsg = msg.strip().decode("base64")
			decrMsg = []
			pckSize = self.decrRcvMsgKey.pckSize
			for i in range(0, len(rcvMsg), pckSize):
				part = rcvMsg[i:i+pckSize]
				decrMsg.append(self.decrRcvMsgKey.decrypt(part))

			return "".join(decrMsg)
		except:
			return "<<Bad encrypted string arrived>>"
