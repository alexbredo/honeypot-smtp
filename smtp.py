#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (c) 2014 Alexander Bredo
# All rights reserved.
# 
# Redistribution and use in source and binary forms, with or 
# without modification, are permitted provided that the 
# following conditions are met:
# 
# 1. Redistributions of source code must retain the above 
# copyright notice, this list of conditions and the following 
# disclaimer.
# 
# 2. Redistributions in binary form must reproduce the above 
# copyright notice, this list of conditions and the following 
# disclaimer in the documentation and/or other materials 
# provided with the distribution.
# 
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND 
# CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, 
# INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF 
# MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE 
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR 
# CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, 
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES 
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE 
# GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR 
# BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF 
# LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT 
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT 
# OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE 
# POSSIBILITY OF SUCH DAMAGE.


'''
TODO:
 - Randomize Hash-Strings
 - Implement correct StartTLS 
 - Deliver E-Mails to POP3-account
 - Do not accept all email-adresses, but many (second request per source-addr?)
'''

import time, uuid
from datetime import datetime
from twisted.internet import protocol, reactor, ssl
from twisted.protocols.basic import LineReceiver
from twisted.conch.telnet import TelnetProtocol

from base.applog import *
from base.appconfig import Configuration
from handler.manager import HandlerManager

class SMTPConfig(Configuration):
	def setup(self, *args, **kwargs): # Defaults: 
		self.__version = '0.1.1'
		self.__appname = 'honeypot_smtp'
		self.port=25
		self.hostname='mx2.example.com'
		self.domain='example.com'
		self.sslport=465
		self.sslcertprivate='keys/smtp.private.key'
		self.sslcertpublic='keys/smtp.public.key'

		self.enabled_handlers = {
			'elasticsearch': True, 
			'screen': True,
			'file': True
		}
		self.elasticsearch = {
			'host': '127.0.0.1', 
			'port': 9200, 
			'index': 'honeypot'
		}
		self.filename = 'honeypot_output.txt'
		
config = SMTPConfig()
handler = HandlerManager(config)

class SimpleSmtpSession(LineReceiver, TelnetProtocol):
	def __init__(self):
		self.delimiter = '\n'
		self.session = str(uuid.uuid1())
		self.myownhost = None

	def connectionMade(self):
		self.__logInfo('connected', '', True)
		now = time.localtime()
		ts = time.strftime('%a, ' + str(now[2]) + ' %b %y %H:%M:%S %Z')
		self.transport.write('220 %s ESMTP server ready %s\r\n' % (config.hostname, ts))
		self.state = 'HELO'

	def connectionLost(self, reason):
		self.__logInfo('disconnected', '', True)

	def lineReceived(self, line):
		line = line.replace(b"\r", b"") # Remove unneccessary chars
		command = line.strip().lower()
		if (command in ['quit', 'exit']):
			self.transport.write('221 %s ESMTP server closing connection\r\n' % config.hostname)
			self.transport.loseConnection()
		else:
			getattr(self, 'smtp_' + self.state)(command)

	def smtp_HELO(self, command):
		if (command.startswith('ehlo') or command.startswith('helo')):
			self.__logInfo('START', command, True)
			self.transport.write('250 %s\r\n' % config.hostname)
			self.state = 'META'
		else:
			self.__logInfo('START', command, False)
			self.transport.write('502 Error: command not recognized\r\n')

	def smtp_META(self, command):
		if (command.startswith('mail from:')):
			self.__logInfo('FROM', command, True)
			emailaddr = command[10:].strip()
			if '@' not in emailaddr:
				emailaddr += '@' + config.domain
			self.transport.write('250 Sender <%s> Ok\r\n' % emailaddr)
		elif (command.startswith('rcpt to:')):
			self.__logInfo('TO', command, True)
			emailaddr = command[8:].strip()
			if '@' not in emailaddr:
				emailaddr += '@' + config.domain
			self.transport.write('250 Recipient <%s> Ok\r\n' % emailaddr)
		elif (command == 'data'):
			self.__logInfo('DATA-START', command, True)
			self.transport.write('354 Ok Send data ending with <CRLF>.<CRLF>\r\n')
			self.state = 'DATA'
		elif (command == 'auth login'):
			self.__logInfo('AUTHLOGIN', command, True)
			self.transport.write('334 VXNlcm5hbWU6\r\n') # Username
			self.state = 'AUTHLOGIN'
		elif (command == 'starttls'):
			self.__logInfo('TLS', command, True)
			self.transport.write('220 2.0.0 Ready to start TLS\r\n') 
			self.state = 'HELO'		 
		else:
			self.transport.write('502 Error: command not recognized\r\n')
			self.__logInfo('META', command, False)

	def smtp_AUTHLOGIN(self, command):
		self.__logInfo('AUTHLOGIN-USER', command, True)
		self.transport.write('334 UGFzc3dvcmQ6\r\n') # Password
		self.state = 'AUTHLOGIN2'

	def smtp_AUTHLOGIN2(self, command):
		if command:
			self.__logInfo('AUTHLOGIN-PASS', command, True)
			self.transport.write('235 ok\r\n')
			self.state = 'META'
		elif (command == 'rset'):
			self.__logInfo('META', command, True)
			self.state = 'META'
		else:
			self.__logInfo('AUTHLOGIN-FAIL', command, False)
			self.transport.write('5.7.8 Error: authentication failed: generic failure\r\n')

	def smtp_DATA(self, command):
		self.__logInfo('DATA', command, True)
		if command == '.':
			self.__logInfo('DATA-END', command, True)
			self.transport.write('250 9c642f92-e0e3-4b9e-b3d3-21054eed3247@%s Queued mail for delivery\r\n' % config.hostname)
			self.state = 'FIN'

	def smtp_FIN(self, command):
		self.__logInfo('FINISH', command, True)
		if command in ['quit', 'exit']:
			self.transport.write('221 %s ESMTP server closing connection\r\n' % config.hostname)
			self.transport.loseConnection()
		else:
			self.transport.write('502 Error: command not recognized\r\n')

	def __logInfo(self, type, command, successful):
		try: # Hack: On Connection-Close socket unavailable. remember old ip.
			self.myownhost = self.transport.getHost()
		except AttributeError:
			pass # nothing

		data = {
			'module': 'SMTP', 
			'@timestamp': int(time.time() * 1000), # in milliseconds
			'sourceIPv4Address': str(self.transport.getPeer().host), 
			'sourceTransportPort': self.transport.getPeer().port,
			'type': type,
			'command': command, 
			'success': successful, 
			'session': self.session
		}
		if self.myownhost:
			data['destinationIPv4Address'] = str(self.myownhost.host)
			data['destinationTransportPort'] = self.myownhost.port

		handler.handle(data)

class SmtpFactory(protocol.Factory):
	def buildProtocol(self, addr):
		return SimpleSmtpSession()

def main():
	try:
		reactor.listenTCP(
			config.port, 
			SmtpFactory()
		)
		reactor.listenSSL(
			config.sslport, 
			SmtpFactory(), 
			ssl.DefaultOpenSSLContextFactory(
				config.sslcertprivate,
				config.sslcertpublic
		))
		log.info('Server listening on Port %s (Plain) and on %s (SSL).' % (config.port, config.sslport))
		reactor.run()
	except Exception, e:
		log.error(str(e));
		exit(-1)
	log.info('Server shutdown.')

if __name__ == "__main__":
	main()