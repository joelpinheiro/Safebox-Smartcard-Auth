import sys
import PAM
import os
import base64
import Crypto.Hash
from Crypto.Hash import SHA
from getpass import getpass
import ccModule
from ccModule import ccHandler


def pam_conv(auth,query_list,userdata):
	resp = []

	for i in range(len(query_list)):
		query, type = query_list[i]
		if type == PAM.PAM_PROMPT_ECHO_ON:
			val = raw_input(query)
			resp.append((val,0))
		elif type == PAM.PAM_PROMPT_ECHO_OFF:
			challenge = os.urandom(20)
			sha1 = SHA.new(challenge)
			sha1.update(challenge)
			digest = sha1.digest()
			print "PYTHON digest: %s" % digest
			print "PYTHON Encoded digest: %s" % base64.b64encode(digest)
			cc = ccHandler()
			cc.openSession()
			signed = cc.sign(challenge)
			val = base64.b64encode(digest)+'-'+signed

			resp.append((val,0))
		elif type == PAM.PAM_PROMPT_ERROR_MSG or type == PAM.PAM_PROMPT_TEXT_INFO:
			print query
			resp.append(('', 0))
		else:
			return None

	return resp

service = 'safebox'

if len(sys.argv) == 2:
	user = sys.argv[1]
else:
	user = None

auth = PAM.pam()
auth.start(service)
if user != None:
	auth.set_item(PAM.PAM_USER, user)
auth.set_item(PAM.PAM_CONV, pam_conv)
try:
	auth.authenticate()
	#auth.acct_mgmt()
except PAM.error, resp:
	print 'Go away! (%s)' % resp
except:
	print 'Internal error'
else:
	print 'Good to go!'
