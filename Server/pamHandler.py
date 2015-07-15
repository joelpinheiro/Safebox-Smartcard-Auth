# pamHandler.py
#
# Python module to handle pam interaction in Safebox
# Authors: Miguel Vicente
#		   Joel Pinheiro
#

import sys
import PAM
import os
import base64
import Crypto.Hash
import sqlite3
from Crypto.Hash import SHA
from getpass import getpass

class pamHandler(object):
	def __init__(self):
		self.user = None
		self.signature = None
		self.digest = None
		self.e = None
		self.m = None
		self.pwds = None
		self.pwdt = None
		self.DB_STRING = "mySafeBoxDatabase.db"

	def start(self,user,signature,digest,m,e):
		service = 'safebox'
		self.user = user
		self.signature = signature
		self.digest = digest
		self.e = e
		self.m = m		
		auth = PAM.pam()
		auth.start('safebox')
		auth.set_item(PAM.PAM_USER,user)
		auth.set_item(PAM.PAM_CONV, self.pam_conv)
		def authenticate(auth):
			try:
				auth.authenticate()
			except PAM.error, resp:
				return 'Go away! (%s)' % resp
			except:
				return 'Internal error'
			else:
				#auth.end()
				return 'Good to go!'
		
		return authenticate(auth) 
	def startpw(self,user,pwdt,pwds):
		service = 'safebox'
		self.user = user
		self.pwds = pwds
		self.pwdt = pwdt

		auth = PAM.pam()
		auth.start('safebox_pw')
		auth.set_item(PAM.PAM_USER,user)
		auth.set_item(PAM.PAM_CONV,self.pam_conv)
		def authenticate(auth):
			try:
				auth.authenticate()
			except PAM.error, resp:
				return 'Go away! (%s)' % resp
			except:
				return 'Internal error'
			else:
				#auth.end()
				return 'Good to go!'
		return authenticate(auth)

	

	def pam_conv(self,auth,query_list,userdata):
		resp = []

		for i in range(len(query_list)):
			query, type = query_list[i]
			print query
			if type == PAM.PAM_PROMPT_ECHO_ON:
				val = raw_input(query)
				resp.append((val,0))
			elif type == PAM.PAM_PROMPT_ECHO_OFF:
				if query == 'modulus':
					val = self.m
					resp.append((val,0))
				elif query == 'exponent':
					val = self.e
					print val
					resp.append((val,0))
				elif query == 'signature':
					val = self.signature #base64.b64encode(digest)+'-'+signed
					resp.append((val,0))
				elif query == 'challenge':
					sha = SHA.new();
					sha.update(base64.b64decode(self.digest))
					val = base64.b64encode(sha.digest())
					resp.append((val,0))
				elif query == 'attempt':
					val = self.pwdt
					resp.append((val,0))
				elif query == 'storedpassword':
					val = self.pwds
					print val
					resp.append((val,0))
				elif query == 'attempt':
					val = self.pwdt
					resp.append((val,0))
				elif query == 'storedpassword':
					val = self.pwds
					print val
					resp.append((val,0))
			elif type == PAM.PAM_PROMPT_ERROR_MSG or type == PAM.PAM_PROMPT_TEXT_INFO:
				print query
				resp.append(('', 0))
			else:
				return None

		return resp
"""
	def pam_conv_pw(self,auth,query_list,userdata):
		resp = []

		for i in range(len(query_list)):
			query, type = query_list[i]
			print query
			if type == PAM.PAM_PROMPT_ECHO_ON:
				val = raw_input(query)
				resp.append((val,0))
			elif type == PAM.PAM_PROMPT_ECHO_OFF:
				
#				elif query == 'flag':
#					if self.digest and self.signature:
#						val = 1
#					else:
#						val = 0
#					resp.append((val,0))
			elif type == PAM.PAM_PROMPT_ERROR_MSG or type == PAM.PAM_PROMPT_TEXT_INFO:
				print query
				resp.append(('', 0))
			else:
				return None

		return resp
"""
'''
	def pam_conv_pw(self,auth,query_list,userdata):
		resp = []

		for i in range(len(query_list)):
			query, type = query_list[i]
			if type == PAM.PAM_PROMPT_ECHO_ON:
				val = raw_input(query)
				resp.append((val,0))
			elif type == PAM.PAM_PROMPT_ECHO_OFF:
				if query == 'attemptpassword':
					val = self.pwdt
				elif query == 'storedpassword':
					val = self.pwds
				resp.append((val,0))
			elif type == PAM.PAM_PROMPT_ERROR_MSG or type == PAM.PAM_PROMPT_TEXT_INFO:
				print query
				resp.append(('', 0))
			else:
				return None

		return resp
'''
