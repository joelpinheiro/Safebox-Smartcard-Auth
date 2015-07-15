from ccModule import ccHandler
a=ccHandler()
a.openSession()
#a.sign()
#a.verify()
a.certificate_chain_verify()
"""
Verify CRL
"""
#a.revoked_certifications(r'X509v3 CRL Distribution Points:\s+Full Name:\s+URI:([^\s]+)')
"""
Verify Delta CRL
"""
#a.revoked_certifications(r'X509v3 Freshest CRL:\s+Full Name:\s+URI:([^\s]+)')
#print str(result)
#print a.bi()
#print str(a.mx)
#print str(a.ex)