import cherrypy
import sqlite3
import string
import shutil
import os
import mimetypes
import tempfile
import Crypto
import json
from SafeBoxAuth import SafeBoxAuth,logged_in,require

from cherrypy.lib import static
from cherrypy.lib import sessions
from os import listdir
from os.path import isfile, join
from Crypto import Random
from Crypto.PublicKey import RSA
import Crypto.Cipher
from Crypto.Cipher import PKCS1_OAEP


local_dir = os.path.dirname(os.path.abspath(__file__)) + os.path.sep


class SafeBoxRestricted:
	_cp_config = {
		'auth.require': [logged_in()]
	}

	@cherrypy.config(**{'response.timeout': 3600})
	@cherrypy.expose
	def upload(self):
		print 'entrou'
		filename = SafeBox.auth.requestData['filename']
		user = SafeBox.auth.requestData['username']
		ovrw = SafeBox.auth.requestData['overwrite']
		signature = SafeBox.auth.requestData['SIGNATURE']
		access = SafeBox.auth.requestData['ACCESS']
		path = user+'/'+filename
		pbox_id = getPboxID(user)
		destination = None
		if ovrw == 'y':
			destination = os.path.join(path)
		elif not os.path.isfile(path):
			destination = os.path.join(path)
		print destination
		with open(destination, 'wb') as f:
			shutil.copyfileobj(cherrypy.request.body, f)

		#insert file to data base
		with sqlite3.connect(SafeBox.DB_STRING) as c:
		    cursor = c.execute("INSERT INTO file (pathfile,owner_pbox_id,signature) VALUES (?, ?, ?)",[destination,pbox_id,signature])
		    file_id = cursor.lastrowid
		    c.execute("INSERT INTO sharing (pbox_id,file_id,access) VALUES (?,?,?)",[pbox_id,file_id,access])
	
	@cherrypy.expose
	def existingfile(self):
		filename = SafeBox.auth.requestData['filename']
		user = SafeBox.auth.requestData['username']
		pubkey = getPublicKey(user)
		res = {'exists':'0'}
		path = user+'/'+filename
		with sqlite3.connect(SafeBox.DB_STRING) as c:
		    rows = 0
		    for row in c.execute("SELECT file_id FROM file JOIN pbox on owner_pbox_id = pbox_id WHERE username = ? and pathfile = ?",[user,path]):
		    	rows += 1
		    	res['exists'] = '1'

		data = cipherResponse(res,pubkey)
		return data


	@cherrypy.expose
	@cherrypy.config(**{'response.timeout': 3600})
	def download(self):
		hdrs = SafeBox.auth.requestData
		fileid = None
		username = None
		path = None
		res = {}
		if hdrs.has_key('fileid'):
			fileid = hdrs['fileid']
			if hdrs.has_key('username'):
				username = hdrs['username']
				pbox_id = getPboxID(username)

		print "File ID: %s" % fileid

		if fileid == None or username == None:
			raise cherrypy.HTTPError(400,'Bad File request')

		with sqlite3.connect(SafeBox.DB_STRING) as c:
			rows = 0
			for row in c.execute("SELECT access,signature,pathfile FROM file,sharing where sharing.pbox_id = ? and sharing.file_id = ?",[pbox_id,fileid]):
				rows += 1
			if rows != 0:
				(access,signature) = (row[0],row[1])
				path = row[2]
				cherrypy.response.headers['access'] = access
				res['signature'] = signature
				res['filename'] = os.path.basename(path)
				print "File name: %s" % os.path.basename(path)

		f = open(path,'r')
		size = os.path.getsize(path)
		mime = mimetypes.guess_type(os.path.basename(path))[0]

		data = cipherResponse(res,getPublicKey(username))
		cherrypy.response.headers['data'] = data
		cherrypy.response.headers['Content-Type'] = mime
		cherrypy.response.headers["Content-Disposition"] = 'attachment; filename="%s"' % os.path.basename(path)
		cherrypy.response.headers["Content-Length"] = size
		buffersize = 1024*5
		def stream():
			data = f.read(buffersize)
			while(len(data)>0):
				yield data
				data = f.read(buffersize)
			f.close()
		return stream()

	@cherrypy.expose
	def getAccessAndPublicKey(self):
	   	hdrs =  SafeBox.auth.requestData
	   	usernameOwner = hdrs['username']
		usernameForShare = hdrs['usernameToShare']
		file_id = hdrs['fileid']
		
		owner_pbox_id = getPboxID(usernameOwner)
		share_pbox_id = getPboxID(usernameForShare)

		with sqlite3.connect(SafeBox.DB_STRING) as c:
			rows = 0
	        for row in c.execute("SELECT access FROM sharing WHERE pbox_id = ? and file_id = ?",[owner_pbox_id,file_id]):
	            access = row[0]
	            rows += 1
	            print access

	        if rows == 0: 
	            print 'Erro na funcao "getAccessAndPublicKey": Nao e possivel encontrar access.'
	        else:
	        	print 'found access'
	        	cherrypy.response.headers['access'] = access

		with sqlite3.connect(SafeBox.DB_STRING) as c:
			rows = 0
	        for row in c.execute("SELECT public_key FROM key JOIN pbox ON key_id = public_key_id WHERE pbox_id = ?",[share_pbox_id]):
	            public_key = row[0]
	            rows += 1
	        if rows == 0: 
	            print 'Erro na funcao "getAccessAndPublicKey": Nao e possivel encontrar public_key_id.'
	        else:
	        	cherrypy.response.headers['newpublickey'] = public_key

	@cherrypy.expose
	def listFiles(self):	
		username = SafeBox.auth.requestData['username']
		listF = []

		# Get pbox_id
		with sqlite3.connect(SafeBox.DB_STRING) as c:
			rows = 0
	        for row in c.execute("SELECT pbox.pbox_id,key.public_key FROM pbox JOIN key ON pbox.public_key_id = key.key_id WHERE pbox.username = ?",[username]):
	            pbox_id = row[0]
	            userkey = row[1].decode('hex')
	            rows += 1
	        if rows == 0: 
	        	print 'There isn\'t any Pbox in Safebox'
	        else:# Get files which this pbox has
	        	with sqlite3.connect(SafeBox.DB_STRING) as c:
			    	for row in c.execute("SELECT file.file_id,file.pathfile FROM sharing JOIN file ON sharing.file_id = file.file_id WHERE pbox_id = ?",[pbox_id]):
			    		listF += str(row[0]) + ' ' + os.path.basename(row[1])+'\n'

		data = cipherResponse(listF,userkey)
		return data

	@cherrypy.expose
	def listFilesShared(self):
		hdrs = SafeBox.auth.requestData
		username = hdrs['username']
		listF = []
		pbox_id = getPboxID(username)
		with sqlite3.connect(SafeBox.DB_STRING) as c:
			rows = 0
			for row in c.execute("SELECT file.file_id,pathfile,username FROM file JOIN sharing ON file.file_id = sharing.file_id JOIN pbox ON pbox.pbox_id = sharing.pbox_id WHERE pbox.pbox_id != ? and sharing.giveaccess_pbox_id = ?",[pbox_id,pbox_id]):
				listF += str(row[0])+' '+os.path.basename(row[1])+' '+ row[2] +'\n'
				rows += 1
		data = cipherResponse(listF,getPublicKey(username))
		return data

	@cherrypy.expose
	def listFilesOwned(self):
		hdrs = SafeBox.auth.requestData
		username = hdrs['username']
		pbox_id = getPboxID(username)
		listF = []
		with sqlite3.connect(SafeBox.DB_STRING) as c:
			for row in c.execute("SELECT file.file_id,pathfile FROM file JOIN pbox ON file.owner_pbox_id = pbox.pbox_id WHERE pbox_id = ?",[pbox_id]):
				listF += str(row[0])+' '+os.path.basename(row[1])+'\n'
		data = cipherResponse(listF,getPublicKey('username'))
		return data


	@cherrypy.expose
	def share(self):
		print 'share'
		hdrs = SafeBox.auth.requestData
		username = hdrs['username']
		fileid = hdrs['fileid']
		usernameToShare = hdrs['usernameToShare']
		access = cherrypy.request.headers['access']
		share_pbox_id = getPboxID(usernameToShare)
		pbox_id = getPboxID(username)
		res = {'result':'0'}
		with sqlite3.connect(SafeBox.DB_STRING) as c:
			cursor = c.execute("INSERT INTO sharing (pbox_id, giveaccess_pbox_id, file_id, access) VALUES (?, ?, ?, ?)",[share_pbox_id, pbox_id, fileid, access])
			if cursor.rowcount != 0:
				res['result'] = '1'

		data = cipherResponse(res,getPublicKey(username))
		return data


	@cherrypy.expose
	def deleteFile(self):
		hdrs = SafeBox.auth.requestData
		print hdrs
		file_id = hdrs['fileid']
		filename = hdrs['filename'].decode('hex')
		username = hdrs['username']
		print 'entrou'
		with sqlite3.connect(SafeBox.DB_STRING) as c:
			rows1 = 0
			for row in c.execute("DELETE FROM sharing WHERE file_id=?", [file_id]):
				rows1 += 1

		with sqlite3.connect(SafeBox.DB_STRING) as c:
			rows2 = 0
			for row in c.execute("DELETE FROM file WHERE file_id=?", [file_id]):
				rows2 += 1

		filepath = username+'/'+filename
		if(os.path.isfile(filepath)):
			os.remove(filepath)

		if rows1 != 0 and rows2 != 0:
			cherrypy.response.headers['result'] = '1'
		else:
			cherrypy.response.headers['result'] = '0'

	@cherrypy.expose
	def unshare(self):
		hdrs = SafeBox.auth.requestData
		print hdrs
		fileid = hdrs['fileid']
		username = hdrs['username']
		unshareusername = hdrs['unshareusername'].decode('hex').split('\n')[0]

		print unshareusername
		unshare_pbox_id = getPboxID(unshareusername)

		unsharerecursive(unshare_pbox_id, fileid)

	@cherrypy.expose
	def listFileSharers(self):
		hdrs = SafeBox.auth.requestData
		print hdrs
		fileid = hdrs['fileid']
		username = hdrs['username']
		pboxid = getPboxID(username)

		listF = []
		with sqlite3.connect(SafeBox.DB_STRING) as c:
			for row in c.execute("SELECT pbox.pbox_id,pbox.username FROM pbox JOIN sharing on sharing.pbox_id = pbox.pbox_id JOIN file on sharing.file_id = file.file_id WHERE file.file_id = ? and sharing.giveaccess_pbox_id = ?",[fileid,pboxid]):
				listF += str(row[0])+' '+row[1]+'\n'
		data = cipherResponse(listF)
		return data


def cipherResponse(response,userkey):
	rsa = RSA.importKey(userkey)
	pubcipher = PKCS1_OAEP.new(rsa)
	data = pubcipher.encrypt(json.dumps(response))
	print len(data)
	return data.encode('hex')
	



def unsharerecursive(unshare_pbox_id, fileid):
	with sqlite3.connect(SafeBox.DB_STRING) as c:
		rows = 0
		for row in c.execute("SELECT pbox_id FROM sharing WHERE giveaccess_pbox_id = ? AND file_id = ?" ,[unshare_pbox_id, fileid]):
			pboxid = row[0]
			rows += 1
	if rows != 0:
		unsharerecursive(pboxid, fileid)
		
	with sqlite3.connect(SafeBox.DB_STRING) as c:
		c.execute("DELETE FROM sharing WHERE pbox_id = ? AND file_id = ?", [unshare_pbox_id, fileid])
 

class SafeBox:	
	_cp_config = {
		'tools.sessions.on': True,
        'tools.auth.on': True,
        'global':{
	        'server.socket_host' : '127.0.0.1',
	        'server.socket_port' : 8080,
	        'server.thread_pool' : 8,
	        # remove any limit on the request body size; cherrypy's default is 100MB
	        'server.max_request_body_size' : 0,
	        # increase server socket timeout to 60s; cherrypy's defult is 10s
	        'server.socket_timeout' : 60
	     }

	}
	DB_STRING = "mySafeBoxDatabase.db"
	auth = SafeBoxAuth()
	restricted = SafeBoxRestricted()
	#serverPublicKey =  RSA.importKey(open('serverpub.pem','r').read())

	@cherrypy.expose
	#@cherrypy.tools.json_in()
	def testJSON(self):
		data = decipherRequest(cherrypy.request.body.read())
		print data

	@cherrypy.expose
	def listPboxes(self):
	    lista = '\n'
	    with sqlite3.connect(SafeBox.DB_STRING) as c:
	        rows = 0
	        for row in c.execute("SELECT username FROM pbox"):
	        	lista += row[0]+'\n'
	        	rows += 1
	        if rows == 0: 
	            print 'There isn\'t any PBoxes in Safebox'

	    return lista

	@cherrypy.expose
	def existinguser(self):
		username = cherrypy.request.headers['username']

		with sqlite3.connect(SafeBox.DB_STRING) as c:
		    rows = 0
		    for row in c.execute("SELECT username FROM pbox WHERE username = ?",[username]):
		    	rows += 1
		    
		    if rows != 0: 
		    	cherrypy.response.headers['existinguser'] = '1'
		    else:
		    	cherrypy.response.headers['existinguser'] = '0'

	@cherrypy.expose
	def existingcc(self):
		userid = cherrypy.request.headers['userid']

		with sqlite3.connect(SafeBox.DB_STRING) as c:
		    rows = 0
		    for row in c.execute("SELECT bi FROM pbox WHERE bi = ?",[userid]):
		    	rows += 1
		    
		    if rows != 0: 
		    	cherrypy.response.headers['existingcc'] = '1'
		    else:
		    	cherrypy.response.headers['existingcc'] = '0'


	@cherrypy.expose
	def createPbox(self):
	    #fetch pub key
	    hdrs = cherrypy.request.headers
	    username = hdrs['username']
	    pwd = hdrs['pwd']
	    public_key = hdrs['pubkey']
	    bi = hdrs['bi']
	    mx = hdrs['mx']
	    ex = hdrs['ex']

	    public_key_id = storeKey(public_key)

        #create user directory
	    if not os.path.exists(username):
	    	os.makedirs(local_dir+username)

	    with sqlite3.connect(SafeBox.DB_STRING) as c:
	    	cursor = c.execute("INSERT INTO pbox (username, password, public_key_id, modulus, exponent, bi) VALUES (?, ?, ?, ?, ?, ?)", 
            	[username, pwd, public_key_id, mx, ex, bi])

	    if cursor.rowcount != 0:
	        cherrypy.response.headers['result'] = '1'
	    else:
	        cherrypy.response.headers['result'] = '0'

def storeKey(key):
	with sqlite3.connect(SafeBox.DB_STRING) as c:
		cursor = c.execute("INSERT INTO key (public_key) VALUES (?)", 
			[key])
	return cursor.lastrowid

def getPboxID(username):
    with sqlite3.connect(SafeBox.DB_STRING) as c:
        rows = 0
        for row in c.execute("SELECT pbox_id FROM pbox WHERE username = ?",[username]):
            userID = row[0]
            rows += 1
            print rows

        if rows == 0: 
            print 'Erro na funcao "getPboxID": Nao e possivel encontrar pbox_id'
    return userID

def getPublicKey(username):
	with sqlite3.connect(SafeBox.DB_STRING) as c:
		for row in c.execute("SELECT public_key FROM key JOIN pbox ON key_id = public_key_id WHERE pbox.username = ?",[username]):
			return row[0].decode('hex')

#def decipherRequest(request):
#	key = open('server.pem','r') #mudar para cha
#	rsa = RSA.importKey(key)
#	privdecipher = PKCS1_OAEP.new(rsa)
#	key.close()
#	deciphered = privdecipher.decrypt(request)
#	data = json.loads(deciphered)
#	return data


if __name__ == '__main__':
	#cherrypy.server.ssl_module = 'builtin'
	#cherrypy.server.ssl_certificate = 'cert.pem'
	#cherrypy.server.ssl_private_key = 'private.pem'
	cherrypy.quickstart(SafeBox())

