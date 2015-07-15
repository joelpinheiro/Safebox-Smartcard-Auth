import cherrypy
import os
import sqlite3
import json
import sys
import PAM
import base64
import Crypto.Hash
import pamHandler
import bcrypt

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA
from pamHandler import pamHandler

def check_credentials(username,pwd):
	if not checkPwd(username,pwd):
		return 'Password mismatch'

	return None

def locked(user):
	pass
	#if bd.locked
	#	return True
	#else
	#	return False
def checkPwd(user,pwd):
	print 'checkpwd'
	with sqlite3.connect(SafeBoxAuth.DB_STRING) as c:
		for row in c.execute("SELECT pbox_id,password FROM pbox WHERE username = ?;",[str(user)]):
			stored = row[1]
			if pwd == stored:
				cherrypy.response.headers['pboxid'] = row[0]
				print 'Encontrou pass'
				return True
	print 'Retornou falso'
	return False

def check_auth(*args, **kwargs):
	print 'check_auth'
	conditions = cherrypy.request.config.get('auth.require', None)
	if conditions is not None:
		for condition in conditions:
			if not condition():
				print 'nao autenticado'
				raise cherrypy.HTTPError(401,'Unauthorized access')


cherrypy.tools.auth = cherrypy.Tool('before_handler', check_auth)

def require():
	def decorate(f):
		if not hasattr(f, '_cp_config'):
			f._cp_config = dict()
		if 'auth.require' not in f._cp_config:
			f._cp_config['auth.require'] = []
		f._cp_config['auth.require'].extend(conditions)
		return f
	return decorate

def logged_in():
	def decipherRequest(request):
		key = open('server.pem','r')
		rsa = RSA.importKey(key)
		privdecipher = PKCS1_OAEP.new(rsa)
		key.close()
		deciphered = privdecipher.decrypt(request.decode('hex'))
		return json.loads(deciphered) 

	def check():
		data = {}
		if cherrypy.request.headers['hasfile'] == 'true':
			for (h,v) in cherrypy.request.header_list:
				if 'PARAMS' in h:
					items = decipherRequest(v)
					data = dict(data.items() + items.items())
				else:
					data[h] = v
		else:
			request = cherrypy.request.body.read()
			data = decipherRequest(request)
			print cherrypy.request.header_list
			if ('SHARE','true') in cherrypy.request.header_list:
				for (h,v) in cherrypy.request.header_list:
					if 'PARAMS' in h:
						items = decipherRequest(v)
						data = dict(data.items() + items.items())
					else:
						data[h] = v
		print data
		SafeBoxAuth.requestData = data
		if data.has_key('username') and data.has_key('sessionid'):
			print data['sessionid'].decode('hex')
			if(SafeBoxAuth.sessions[data['sessionid'].decode('hex')] == data['username']):
				return True
		else:
			return False
	return check
		


class SafeBoxAuth(object):
	DB_STRING = "mySafeBoxDatabase.db"

	sessions = {}
	challenges = {}
	requestData = {}
	def on_login(self,username):
		print 'on_login'
		session_id = str(os.urandom(10))
		print session_id
		SafeBoxAuth.sessions[session_id] = username
		cherrypy.response.headers['sessionid'] = session_id.encode('hex')
		
		with sqlite3.connect(SafeBoxAuth.DB_STRING) as c:
			rows = 0
			for row in c.execute("SELECT public_key_id,pbox_id FROM pbox WHERE username = ?;",[str(username)]):
				public_key_id = row[0]
				pbox_id = row[1]
				rows += 2
				for row in c.execute("SELECT public_key FROM key WHERE key_id = ?;",[str(public_key_id)]):
					public_key = row[0]
					rows += 1

		if rows == 3:
			cherrypy.response.headers['publickey'] = public_key
			cherrypy.response.headers['pboxid'] = pbox_id



	def on_logout(self):
		pass

	@cherrypy.expose
	def loginPw(self):
		request = cherrypy.request.body.read()
		key = open('server.pem','r')
		rsa = RSA.importKey(key)
		privdecipher = PKCS1_OAEP.new(rsa)
		key.close()
		deciphered = privdecipher.decrypt(request.decode('hex'))
		data = json.loads(deciphered) 

		username = cherrypy.request.headers['user'].decode('hex')
		pwds = gethashbd(username)
		pwdt = data['hashed']#bcrypt.hashpw(data['pwd'].encode('ascii'),pwds.decode('hex'))

		pam = pamHandler()
		res = pam.startpw(username,base64.b64encode(pwdt),base64.b64encode(pwds.decode('hex')))
		#error = check_credentials(username,pwd)
		if res != 'Good to go!':
			cherrypy.response.headers['error'] = res
		else:
			cherrypy.response.headers['error'] = 'OK'
			self.on_login(username)

	################################################################################################
	@cherrypy.expose
	def loginCC(self):
		hdrs = cherrypy.request.headers
		userid = hdrs['userid']

		sequence = os.urandom(20)
		print "SERVER: GENERATED SEQUENCE %s" % sequence
		challenge = base64.b64encode(sequence)
		print "SERVER: B64 ENCODED SEQUENCE %s" % challenge

		cherrypy.response.headers['error']='OK'
		cherrypy.response.headers['challenge']=challenge
		#cherrypy.response.headers['userid']=userid
		cherrypy.response.headers['username']=getUserById(userid)
		SafeBoxAuth.challenges[userid] = challenge

	@cherrypy.expose
	def verifyChallenge(self):
		#Integrar com PAM
		hdrs = cherrypy.request.headers
		userid = hdrs['userid']
		user = getUserById(userid)
		signed = hdrs['signature']
		(m,e) = getExpAndMod(user)
		#digest = hdrs['challengedigest']
		pam = pamHandler()
		res = pam.start(user,signed,SafeBoxAuth.challenges[userid],m,e)
		if res != 'Good to go!':
			cherrypy.response.headers['error'] = res
		else:
			cherrypy.response.headers['error'] = 'OK'
			self.on_login(user)
		#if SafeBoxAuth.challenges[user] == signed: #TODO PAM 
		#	cherrypy.response.headers['error'] = 'OK'
		#	with sqlite3.connect(SafeBoxAuth.DB_STRING) as c:
		#		row = cc.execute("SELECT pboxid,username FROM pbox WHERE username = ?;",[str(user)])
		#		cherrypy.response.headers['pboxid'] = row[0]
		#		self.on_login(row[1])
		#else:
		#	cherrypy.response.headers['error'] = 'Authentication Failed'
	#################################################################################################


	#@cherrypy.expose
	@cherrypy.expose
	def logout(self):
		hdrs = cherrypy.request.headers['sessionid']
		SafeBoxAuth.sessions[hdrs['sessionid'].decode('hex')] = None

	@cherrypy.expose
	def gethash(self):
		#username = cherrypy.request.headers['username']
		request = cherrypy.request.body.read()
		key = open('server.pem','r')
		rsa = RSA.importKey(key)
		privdecipher = PKCS1_OAEP.new(rsa)
		key.close()
		deciphered = privdecipher.decrypt(request.decode('hex'))
		data = json.loads(deciphered) 

		if data.has_key('username'):
			username = data['username']
			hashed = None
			with sqlite3.connect(SafeBoxAuth.DB_STRING) as c:
				rows = 0
				for row in c.execute("SELECT password FROM pbox WHERE username = ?;",[str(username)]):
					hashed = row[0]
				if hashed:
					cherrypy.response.headers['error'] = 'OK'
					cherrypy.response.headers['data'] = hashed
					print hashed
				else:
					cherrypy.response.headers['error'] = 'Couldn\'t find user'

def gethashbd(username):
	#username = cherrypy.request.headers['username']
	
	hashed = None
	with sqlite3.connect(SafeBoxAuth.DB_STRING) as c:
		rows = 0
		for row in c.execute("SELECT password FROM pbox WHERE username = ?;",[str(username)]):
			hashed = row[0]
			return hashed


def getExpAndMod(username):
	with sqlite3.connect(SafeBoxAuth.DB_STRING) as c:
		for row in c.execute("SELECT modulus,exponent FROM pbox WHERE username = ?;",[str(username)]):
			m = row[0]
			e = row[1]
			return (m,e)

def getUserById(userid):
	with sqlite3.connect(SafeBoxAuth.DB_STRING) as c:
		rows = 0
		for row in c.execute("SELECT username FROM pbox WHERE bi = ?;",[str(userid)]):
			userid = row[0]
			return userid





