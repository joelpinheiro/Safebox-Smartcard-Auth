import Crypto.Cipher
from Crypto.Cipher import PKCS1_OAEP,AES
from Crypto import Random
from Crypto.PublicKey import RSA
from Crypto.Hash import HMAC,SHA

import sys
from sys import argv
from requests import Request
import requests
import io
import os
import bcrypt
import json
import base64
from ccModule import ccHandler

prompt1 = '>'
serverKey = RSA.importKey(open('serverpub.pem','r').read())
class User(object):
	def __init__(self,username,session_id,public_key):
		self.username = username
		self.session_id = session_id
		self.public_key = public_key

def main():
	options = {
		#1: loginPw,
		1: loginCC,
		2: createPbox,
		3: listPboxes,
		#5: testJson,
	}
	while(1):
		print

		print 'Safebox (Public Area):'
		#print '1 - Login with password'
		print '1 - Login'
		print '2 - Create PBox'
		print '3 - List the existing PBox\'s'
		prompt = '> '
		option = raw_input(prompt)
		if option.isdigit():
			option = int(option)
			if option > 0 and option < 5:
				if(option == 1):
					user = options[option]()
					if user:
						return safeboxmenu(user)
				else:
					msg = options[option]()
					print msg
			else:
				print "Wrong option!\n"
		else:
			print "Wrong option!\n"

def safeboxmenu(user):
	restricted_options = {
		1: uploadFile,
		2: downloadFile,
		3: listFilesByPbox,
		4: listFilesShared,
		5: shareFile,
		6: delete,
		7: unshare,
		8: logout,
	}
	while(1):

		print '1 - Add a protected file to my PBox'
		print '2 - Get the file contents of a protected file in my PBox'
		print '3 - List my PBox files' 
		print '4 - List files shared'
		print '5 - Share a file in my PBox with other PBoxes'
		print '6 - Delete a file from my PBox - not done'
		print '7 - Unshare a file with other PBox'
		print '8 - Logout'

		prompt = '> '
		option = raw_input(prompt)
		if option.isdigit():
			option = int(option)
			if option > 0 and option < 9:
				msg = restricted_options[option](user)
				print msg
			else:
				print "Wrong option!\n"
		else:
			print "Wrong option!\n"

def loginPw():
	print "Whats your username?"
	username = raw_input(prompt1)
	print "What's your password?"
	os.system("stty -echo")
	password = raw_input(prompt1)
	os.system("stty echo")

	s = requests.Session()
	data = {'username':username}
	data = cipherRequest(data)
	res = s.post('http://localhost:8080/auth/gethash',data=data)
	if res.headers['error'] != 'OK':
		print res.headers['error']
		return

	
	hashed = bcrypt.hashpw(password,res.headers['data'].decode('hex'))

	data = {'hashed': hashed}
	data = cipherRequest(data)
	resp = s.post('http://localhost:8080/auth/loginPw', data=data,headers={'user':username.encode('hex')})
	if resp.headers['error'] != 'OK':
		print resp.headers['error']
		return

	session_id = resp.headers['sessionid']
	public_key = resp.headers['publickey']
	pbox_id = resp.headers['pboxid']

	if not session_id: 
	    print 'Authenthication failed!'
	else:
		user = User(username,session_id,public_key)
		print '\nHi ' + username + '! (ID: ' + pbox_id + ')'
		return user


def loginCC():
	print "Trying to login using your citizen card\n"
	cc = ccHandler()
	err = cc.openSession()
	if not err:
		print 'Unavailable to login by Smartcard, please use your credentials \n'
		return loginPw()
	
	print 'Validating your citizen card'
	if not cc.certificate_chain_verify():
		print 'Your Smartcard certificate could not be verified, please user your credentials \n'
		return loginPw()
	print 'Citizen card validated\n'

	s = requests.Session()
	#prompt = '> '
	#print "What's your username?"
	print 'Getting your cardholder ID\n'
	userid = cc.bi()#raw_input(prompt1)
	resp = s.post('http://localhost:8080/auth/loginCC',headers={'userid':userid})
	if resp.headers['error'] != 'OK':
		return resp.headers['error']
	username = resp.headers['username']
	#print "CLIENT: B64 RECEIVED SEQUENCE %s" % resp.headers['challenge']
	#print "CLIENT: DECODED SEQUENCE %s" % base64.b64decode(resp.headers['challenge'])

	return sendChallenge(username,base64.b64decode(resp.headers['challenge']),cc)


def sendChallenge(username,challenge,cc):
	s = requests.Session()

	signed = cc.sign(challenge)
	
	#print "CLIENT: B64 SIGNATURE %s" % signed
	s = requests.Session()
	userid = cc.bi()

	s.headers= {'signature':signed,'userid':userid}#'challenge':challenge}
	resp = s.post('http://localhost:8080/auth/verifyChallenge')

	session_id = resp.headers['sessionid']
	public_key = resp.headers['publickey']
	pbox_id = resp.headers['pboxid']

	if not session_id: 
	    print 'Authenthication failed!'
	else:
		user = User(username,session_id,public_key)
		print '\nHi ' + username + '! (ID: ' + pbox_id + ')'
		return user
#################################################################

def createPbox():
	prompt = '> '
	s = requests.Session()

	print "To create a Safebox account, make sure you have your citizen card connected to your computer.\nThis can be used later as an authentication method for your Safebox account\n"
	raw_input('Press any key to continue\n')

	a=ccHandler()
	err = a.openSession()
	if not err:
		return 'Smartcard unavailable\n'
		
	"""
	Get from CC
	Modulus, exponent and BI
	"""
	a.sign('1234567890')
	a.verify()
	
	bi = a.bi()
	s.headers = {'userid': bi}
	res = s.post('http://localhost:8080/existingcc')
	if res.headers['existingcc'] == 	'1':
		return 'An account associated with this Citizen Card already exists, you cannot create another one'

	print 'Validating your citizen card'
	if not a.certificate_chain_verify():
		print 'Your Smartcard certificate could not be verified, please user your credentials \n'

	print 'Citizen card validated\n'

	mx = a.mx
	ex = a.ex

	#print "\n\nbi:" + bi
	#print "\n\nmx:" + mx
	#print "\n\nex:" + ex

	print "Username?"
	username = raw_input(prompt)
	s.headers = {'username': username}
	res = s.post('http://localhost:8080/existinguser')
	if res.headers['existinguser'] == 	'1':
		return 'Username has been taken, please choose another one'

	print "Password?"
	while 1:
		os.system("stty -echo")
		password = raw_input(prompt)
		os.system("stty echo")
		if(len(password) < 6):
			print 'Password too short'
		else:
			break
	#TODO validar forca da password

	# Public and Private key - RSA
	rsa = RSA.generate(2048)
	priv = open('private.pem','w')
	priv.write(rsa.exportKey('PEM'))

	pubkey = rsa.publickey().exportKey('PEM').encode('hex')
	
	hashedpw = bcrypt.hashpw(password,bcrypt.gensalt())

	s.headers = {'username': username, 'pwd':hashedpw.encode('hex'), 'pubkey':pubkey, 'bi': bi, 'mx': mx, 'ex' : ex}
	res = s.post('http://localhost:8080/createPbox')
	result = res.headers['result']

	if result == '0': 
	    return 'Registration failed!'
	else:
	    print '\nHi ' + username + '! Welcome to SafeBox! You have created a PBox successfully! ' # (ID: ' + pbox_id + ')'


def logout(user):
	requests.post('http://localhost:8080/auth/logout',headers={'sessionid':user.session_id})
	print 'Logged out'
	main()


def listPboxes():
	lista = requests.get('http://localhost:8080/listPboxes')
	return lista.content


def cipherRequest(params):
	pubcipher = PKCS1_OAEP.new(serverKey)
	data = pubcipher.encrypt(json.dumps(params))
	return data.encode('hex')
	#requests.post('http://localhost:8080/testJSON',data=bytes(data))

def decipherResponse(params):
	rsa = RSA.importKey(open('private.pem','r').read())
	privdecipher = PKCS1_OAEP.new(rsa)
	data = privdecipher.decrypt(params)
	return json.loads(data)

def listFilesByPbox(user):
	#headers = {'username':user.username,'sessionid':user.session_id}
	params = {'username':user.username,'sessionid':user.session_id}
	data = cipherRequest(params)
	resp = requests.post('http://localhost:8080/restricted/listFiles', data=data, headers={'hasfile':'false'})
	files = decipherResponse(resp.content.decode('hex'))
	return ''.join(files)

def uploadFile(user):
	filename = str(raw_input('Nome do ficheiro:\n'))
	#file exists in client?
	if not os.path.isfile(filename):
		return 'File does not exists'

	#file exists in pbox?
	s = requests.Session()
	s.headers = {'hasfile':'false'}
	params = {'username':user.username, 'sessionid': user.session_id,'filename':filename}
	data = cipherRequest(params)
	res = s.post('http://localhost:8080/restricted/existingfile', data=data)
	print res.content
	data = decipherResponse(res.content.decode('hex'))

	overwrite = 'n'
	if data['exists'] == '1':
		while 1:
			print 'You already have a file with that name, do you wish to overwrite? (y/n)\n'
			overwrite = str(raw_input(prompt1))
			if overwrite == 'y':
				break
			elif overwrite != 'n':
				print 'Invalid operation\n'

	(toSend,access,signature) = encrypt(filename,user.public_key.decode('hex'))
	f = FileLenIO(toSend.name, 'rb')
	
	params = {'username':user.username,'sessionid':user.session_id, 'filename': filename}
	params2 = {'overwrite':overwrite}
	print params
	print params2
	data = cipherRequest(params)
	data2 = cipherRequest(params2)
	s.headers={'hasfile':'true','params':data,'params2':data2, 'access':access.encode('hex'),'signature': signature.encode('hex')}
	res = s.post('http://localhost:8080/restricted/upload',f)

	os.remove(toSend.name)

	if res.status_code == 200:
		return 'File Sent'

def downloadFile(user):
	print 'Select file to download'
	print 'ID | Path'

	files = listFilesByPbox(user)
	print files
	fileid = str(raw_input('ID: '))
	found = False
	for f in files.split('\n'):
		if fileid == f.split(' ')[0]:
			found = True
	if not found:
		print 'Please choose a file from the list'

	s = requests.Session()
	params = {'username':user.username, 'sessionid': user.session_id,'fileid':fileid}
	#print "File ID: %s" % fileid
	s.headers = {'hasfile':'false'}
	data = cipherRequest(params)
	res = s.post('http://localhost:8080/restricted/download',data=data)
	
	data = decipherResponse(res.headers['data'].decode('hex'))
	filename = data['filename']
	#print "File name: %s" % filename	
	if res.status_code == 200:
		with open(filename, 'wb') as f:
			for chunk in res.iter_content():
				f.write(chunk)
		access = res.headers['access'].decode('hex')
		signature = data['signature'].decode('hex')
		decrypt(filename,user.public_key.decode('hex'),access,signature)

	#TODO verificar que se e necessario enviar a public key para verificar integridade


def shareFile(user):
	print 'Select file to share'
	print 'ID | Path'

	files = listFilesByPbox(user)
	print files
	fileid = str(raw_input('ID: '))
	found = False
	for f in files:
		if fileid == f.split(' ')[0]:
			found = True
	if not found:
		print 'Please choose a file from the list'

	toshare = str(raw_input('Type username to share file with: '))
	users = listpboxes()
	valid = False
	for u in users.split('\n'):
		if toshare == u:
			valid = True
	if not valid:
		return 'Username does not exist'

	s = requests.Session()
	params = {'username' : user.username,  'fileid': fileid, 'usernameToShare':toshare}
	params2 = {'sessionid':user.session_id,}
	data = cipherRequest(params)
	data2 = cipherRequest(params2)
	s.headers = {'hasfile':'false','share':'true','params':data2,}
	res = s.post('http://localhost:8080/restricted/getAccessAndPublicKey',data=data)
	key,iv = decryptAccess(res.headers['access'].decode('hex'))
	newaccess = encryptAccess(res.headers['newpublickey'].decode('hex'),key,iv)

	params = {'username' : user.username, 'sessionid':user.session_id}
	params2 = { 'fileid': fileid, 'usernameToShare':toshare}
	data = cipherRequest(params)
	data2 = cipherRequest(params2)
	s.headers = {'hasfile':'false', 'access':newaccess.encode('hex'),'share':'true','params':data2}
	res = s.post('http://localhost:8080/restricted/share',data=data)
	#TODO verificar se foi feito com sucesso

def unshare(user):
	print 'Select file to unshare'
	print 'ID | NAME'

	files = listFilesShared(user)
	print files
	fileid = str(raw_input('ID: '))
	found = False
	for f in files:
		if fileid == f.split(' ')[0]:
			found = True
	if not found:
		print 'Please choose a file from the list'

	sharers = listFileSharers(user,fileid)

	print 'Select user'
	print 'ID | NAME'
	print sharers.content
	pboxid = str(raw_input('ID: '))
	found = False
	for u in sharers:
		if pboxid == u.split(' ')[0]:
			tounshare = str(u.split(' ')[1])
			found = True
	if not found:
		print 'Please choose a user from the list'

	s = requests.Session()
	params = {'username' : user.username, 'sessionid': user.session_id}
	params2 = {'fileid': fileid, 'unshareusername':tounshare.encode('hex')}
	data = cipherRequest(params)
	data2 = cipherRequest(params2)
	s.headers ={ 'hasfile':'false','share':'true','params':data2}
	res = s.post('http://localhost:8080/restricted/unshare',data=data)

def listFilesShared(user):
	params = {'username':user.username,'sessionid':user.session_id}
	headers = {'hasfile':'false'}
	data = cipherRequest(params)
	resp = requests.post('http://localhost:8080/restricted/listFilesShared',data=data,headers=headers)
	files = decipherResponse(resp.content.decode('hex'))
	return ''.join(files)

def listFileSharers(user,fileid):
	headers = {'hasfile':'false'}
	params = {'username':user.username,'sessionid':user.session_id, 'fileid':fileid}
	data = cipherRequest(params)
	resp = requests.post('http://localhost:8080/restricted/listFileSharers',data=data,headers=headers)
	sharers = decipherResponse(resp.content.decode('hex'))
	return ''.join(sharers)

def listpboxes():
	lista = requests.get('http://localhost:8080/listPboxes')
	return lista.content

def delete(user):
	print 'Select file to delete'
	print 'ID | NAME'

	files = listFilesOwned(user)
	print files.content
	fileid = str(raw_input('ID: '))
	fileList = files.content.split('\n')
	print fileList
	found = False
	for f in fileList:
		if fileid == f.split(' ')[0]:
			filename = f.split(' ')[1]
			found = True
	if not found:
		print 'Please choose a file from the list'
		return delete(user)

	headers={'hasfile':'false'}
	params = {'username':user.username, 'sessionid':user.session_id, 'fileid':fileid, 'filename':filename.encode('hex')}
	data = cipherRequest(params)
	print requests.post('http://localhost:8080/restricted/deleteFile',data=data,headers = headers)

def listFilesOwned(user):
	headers = {'hasfile':'false'}
	params = {'username':user.username,'sessionid':user.session_id}
	data = cipherRequest(params)
	resp = requests.post('http://localhost:8080/restricted/listFilesOwned',data=data,headers=headers)
	files = decipherResponse(resp.content.decode('hex'))
	return files

def confirm():
	print 'Are you sure you want to proceed? (y/n)'
	option = str(raw_input(prompt1))
	if option == 'y':
		return True
	else:
		return False


def encrypt(filename,public_key):
	#Gera chave da assinatura
	hmac = HMAC.new(public_key)

	###################
	key = Random.new().read(AES.block_size) #chave aleatoria
	iv =  Random.new().read(AES.block_size) #vector inicializacao aleatorio
	##################
	
	#cifra os dados da chave AES com RSA
	access = encryptAccess(public_key,key,iv)

	#ler o ficheiro original criar o temporario para conteudo
	cipheredFile = open('temp','w')
	originalFile = open(filename,'r')

	#le o ficheiro original as chunks e escreve a chunk cifrada no temporario
	cipher = AES.new(key,AES.MODE_CBC,iv)
	finished = False
	while not finished:
		data = originalFile.read(AES.block_size*1024)
		#logica de padding - Caso se leia um bloco de tamanho vazio ou nao divisivel por 16 (aes.block_size)
		if(len(data) == 0 or (len(data) % cipher.block_size !=0)):
			pad = (cipher.block_size - len(data) % cipher.block_size)
			data += pad * chr(pad)
			finished = True
		hmac.update(data) #assinatura
		cipheredFile.write(cipher.encrypt(data))
	
	#escreve o resultado do hashing do ficheiro
	originalFile.close()
	cipheredFile.close()
	
	return (cipheredFile, access, hmac.hexdigest())

def encryptAccess(public_key,key,iv):
	#cifrar em rsa 2048 a chave aes do ficheiro e o seu vector de inicializacao

	pubKey = RSA.importKey(public_key)
	pubcipher = PKCS1_OAEP.new(pubKey)
	
	return (pubcipher.encrypt(key+iv))

def decrypt(filename,public_key,access,signature):
	#Ficheiro cifrado, ficheiro de acesso e ficheiro com a chave privada
	ciphered = open(filename,'rb')

	#access = open(os.path.splitext(filename)[0],'r')
	key = open('private.pem','r')
	
	#le chave privada
	hmac = HMAC.new(public_key)
	rsa = RSA.importKey(key)
	
	privdecipher = PKCS1_OAEP.new(rsa)
	key.close()
	
	#decifra ficheiro de acesso e guarda os valores
	keys = privdecipher.decrypt(access)
	key = bytes(keys[0:16])
	iv = bytes(keys[16:32])
	#access.close()

	original = open('temp','w')
	decipher = AES.new(key,AES.MODE_CBC,iv)

	#decifra o ficheiro em chunks
	next_chunk = ''
	while True:
		if next_chunk == '':
			data = ciphered.read(decipher.block_size*1024)
		else:
			data = next_chunk
		next_chunk = ciphered.read(decipher.block_size*1024)

		#eliminar o padding
		if len(next_chunk) == 0 :
			data = decipher.decrypt(data)
			#print data
			hmac.update(data)
			padsize = ord(data[-1])
			if(padsize<16):
				original.write(data[0:(AES.block_size-padsize)])
			break
		originalData = decipher.decrypt(data)
		#print originalData
		original.write(originalData)
		hmac.update(originalData)

	#verifica assinaturas
	if(signature == hmac.hexdigest()):
		print 'Ficheiro validado'
	
	ciphered.close()
	original.close()
	os.remove(filename)
	os.rename('temp',filename)

def decryptAccess(access):
	key = open('private.pem','r')
	rsa = RSA.importKey(key)
	privdecipher = PKCS1_OAEP.new(rsa)
	key.close()

	#decifra ficheiro de acesso e guarda os valores
	keys = privdecipher.decrypt(access)
	key = bytes(keys[0:16])
	iv = bytes(keys[16:32])

	return key,iv

class FileLenIO(io.FileIO):
	def __init__(self, name, mode = 'r', closefd = True):
		io.FileIO.__init__(self, name, mode, closefd)

		self.__size = statinfo = os.stat(name).st_size

	def __len__(self):
		return self.__size

if __name__ == '__main__':
    main()
