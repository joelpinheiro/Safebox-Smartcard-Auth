import sys
import PAM
import os
import base64
import Crypto.Hash
import sqlite3
import bcrypt
from Crypto.Hash import SHA


def pam_conv(auth, query_list, userData):
	resp = []
	
	for i in range(len(query_list)):
		query, type = query_list[i]
		if type == PAM.PAM_PROMPT_ECHO_ON:
			val = raw_input(query)
			resp.append((val, 0))
		elif type == PAM.PAM_PROMPT_ECHO_OFF:
			print query
			if query == 'attempt':
				pwds = '24326124313224667050514734534c73762f422f2f6f7543425337437532552e73557851455447585335305a5277656763727149596f35424a6b6932'.decode('hex')
				pwdt = base64.b64encode(bcrypt.hashpw('123456',pwds))
				print pwdt
				resp.append((pwdt, 0))
			if query == 'storedpassword':
				pwds = base64.b64encode('24326124313224667050514734534c73762f422f2f6f7543425337437532552e73557851455447585335305a5277656763727149596f35424a6b6932'.decode('hex'))
				resp.append((pwds, 0))
		elif type == PAM.PAM_PROMPT_ERROR_MSG or type == PAM.PAM_PROMPT_TEXT_INFO:
			print query
			resp.append(('', 0))
		else:
			return None

	return resp


service = 'testpw'

#if len(sys.argv) == 2:	user = sys.argv[1]
#else:
user = 'mvicente'
auth = PAM.pam()
auth.start(service)
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

