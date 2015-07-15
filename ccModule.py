#   Portuguese Citizen Card Module for SafeBox  
#   author: Miguel Vicente
#
#   reference:
#   www.bit4id.org/trac/pykcs11

import PyKCS11
import getopt
import sys
import platform
import pytz
from datetime import datetime
from pytz import timezone
from M2Crypto import X509
import OpenSSL
import re
import requests

class ccHandler(object):
    def __init__(self):
        self.pkcs11 = PyKCS11.PyKCS11Lib()
        self.pkcs11.load("libpteidpkcs11.so")
        self.slots = self.pkcs11.getSlotList()
        self.session = None
        self.attrDict = None
        self.key = None
        self.signature = None
        self.e = None
        self.m = None
        self.ex = None
        self.mx = None

    def getSlotInfo(self,slot):
        print "Slot n.:",slot
        print self.pkcs11.getSlotInfo(slot)

    def getTokenInfo(self,slot):
        print self.pkcs11.getTokenInfo(slot)

    def getMechanismInfo(self,slot):
        print "Mechanism list:"
        m = self.pkcs11.getMechanismList(slot)
        for x in m:
            i = self.pkcs11.getMechanismInfo(slot,x)
            if not i.flags & PyKCS11.CFK_DIGEST:
                if i.ulMinKeySize != PyKCS11.CK_UNAVAILABLE_INFORMATION:
                    print "ulMinKeySize:"+i.ulMinKeySize
                if i.ulMaxKeySize != PyKCS11.CK_UNAVAILABLE_INFORMATION:
                    print "ulMaxKeySize"+i.ulMaxKeySize

    def getInfo(self):
        print self.pkcs11.getInfo()

    def getSessionInfo(self,slot,pin=""):
        session = self.pkcs11.openSession(slot)

        if pin != "":
            if pin == None:
                print "(using pinpad)"
            else:
                print "(using pin: %s)" % pin
            session.login(pin)
        else:
            print

        if pin:
            session.logout()

    def openSession(self):
        for s in self.slots:
            try:
                self.session = self.pkcs11.openSession(s)
                print "Opened session 0x%08X" % self.session.session.value()
                pin = input("Your smartcard pin is required: ")
                try:
                    self.session.login(pin=str(pin))
                    self.loadDict() #ler objecto rsa
                    break
                except:
                    print "login failed, exception:", str(sys.exc_info()[1])

            except PyKCS11.PyKCS11Error, e:
                print "Error:", e
    
    def loadDict(self):
        objects = self.session.findObjects()
        all_attributes = PyKCS11.CKA.keys()
        # remove the CKR_ATTRIBUTE_SENSITIVE attributes since we can't get
        # their values and will get an exception instead
        all_attributes.remove(PyKCS11.CKA_PRIVATE_EXPONENT)
        all_attributes.remove(PyKCS11.CKA_PRIME_1)
        all_attributes.remove(PyKCS11.CKA_PRIME_2)
        all_attributes.remove(PyKCS11.CKA_EXPONENT_1)
        all_attributes.remove(PyKCS11.CKA_EXPONENT_2)
        all_attributes.remove(PyKCS11.CKA_COEFFICIENT)
        # only use the integer values and not the strings like 'CKM_RSA_PKCS'
        all_attributes = [e for e in all_attributes if isinstance(e, int)]
        for o in objects:
            attributes = self.session.getAttributeValue(o, all_attributes)
            attrDict = dict(zip(all_attributes, attributes))
            if attrDict[PyKCS11.CKA_CLASS] == PyKCS11.CKO_PRIVATE_KEY \
                and attrDict[PyKCS11.CKA_KEY_TYPE] == PyKCS11.CKK_RSA:
                    self.key = o;
                    self.attrDict = attrDict;
                    break

    def sign(self):
        #assinar challenge do servidor com a chave privada
        try:
            toSign = "12345678901234567890" #TODO Challenge do servidor
            self.signature = self.session.sign(self.key,toSign)
            print "Signature:"
            print self.signature
            print dump(''.join(map(chr, self.signature)), 16)
        except:
            print "Sign failed, exception:", str(sys.exc_info()[1])

    def verify(self):
        self.m = self.attrDict[PyKCS11.CKA_MODULUS]
        self.e = self.attrDict[PyKCS11.CKA_PUBLIC_EXPONENT]
        s = ''.join(chr(c) for c in self.signature).encode('hex')
        self.mx = eval('0x%s' % ''.join(chr(c) for c in self.m).encode('hex'))
        self.ex = eval('0x%s' % ''.join(chr(self.e) for self.e in self.e).encode('hex'))
        
        print "self.mx" + str(self.mx)
        print "self.ex" + str(self.ex)

        sx = eval('0x%s' % s)
        decrypted = pow(sx,self.ex,self.mx)
        d = hexx(decrypted).decode('hex')
        print "Decrypted:"
        print dump(d, 16)

    def certificates(self):
        """
        Get certificates
        """
        objects = self.session.findObjects()

        try:
            certificates = []
            for obj in objects:
                d = obj.to_dict()
                if d['CKA_CLASS'] == 'CKO_CERTIFICATE':
                    der = self._os2str(d['CKA_VALUE'])
                    cert = X509.load_cert_string(der, X509.FORMAT_DER)
                    certificates.append(cert)
            return certificates
        except:
            return 'Error: Getting User Certificate'

    def _os2str(self, os):
        """
        Convert octet string to python string
        """
        return ''.join(chr(c) for c in os)

    def bi(self):
        BIprefix = "serialNumber=BI"
        
        certificates = self.certificates()
        cert0 = certificates[0].as_text()

        """
        Subtring to find BI in certificate
        """
        p = cert0.find(BIprefix);
        s = p + len(BIprefix)
        bi = cert0[s:s+8]

        return bi

        #print "BI:" + bi

    def certificate_chain_verify(self):
        """Verify if certificate chain is valid"""
        certificates = self.certificates()
        verified_chain = False

        """
        Tasks:
        -Validate date
        -Verify pubkey signatures
        -Validate crl
        """
        for i in range (0,4):
            certificate = certificates[i]
            public_key = certificates[i+1].get_pubkey()
            task1 = self.validateCertificateDate(self.get_certificate_validity(certificate))
            task2 = self.verify_certificate(certificate, public_key)
            task3 = self.validate_crls(certificate)
            if task1 and task2 and task3:
                verified_chain = True
        print verified_chain
        return verified_chain

    def validateCertificateDate(self,dates):
        present = datetime.now(pytz.utc)
        if present > dates[0] and present < dates[1]:
            return True
        else:
            return False

    def validate_crls(self,certificate):
        """
        Validate CRL and CRL delta
        """
        revcrl = self.revoked_certifications(self.get_crluri(), certificate)
        revcrldelta = self.revoked_certifications(self.get_crldeltauri(),certificate)
        if revcrl or revcrldelta:
            return False
        else:
            return True



    def revoked_certifications(self, crlString,certificate):
        objects = self.session.findObjects()
        revoked = False

        uri = ''

        path = re.search(crlString, certificate.as_text())
        if path:
            uri = path.groups()[0]
            print uri



        """
        Find CRL's URI
        """
        #p = path.group().find(URIprefix);
        #s = p + len(URIprefix)
        #uri = path.group()[s:]

        #print "uri:" + uri

        # Gets content from CRL URI
        if path!=None:
            crl = requests.request('GET',uri)
            crl_object = OpenSSL.crypto.load_crl(OpenSSL.crypto.FILETYPE_ASN1, crl.content)
            revoked_objects = crl_object.get_revoked()
            if revoked_objects != None:
                for rvk in revoked_objects:
                    print rvk.get_serial()
                    certSerial = certificate.get_serial_number()
                    if certSerial == rvk.get_serial():
                        revoked = True
            #print self.get_certificate_serial(certificate)
            #print (certSerial,rvk.get_serial())
            #if rvk.get_serial() == certSerial:
             #   revoked = True
            """
            TODO:
            Apanhar a serial do proprietario do CC e 
            verificar se nenhum destes revoked objects tem
            essa serial. Se tiver revoked = true.
            """

        return revoked
        #except:
         #   return 'Error: Getting User Certificate'

        #return revoked

    

    def verify_certificate(self, certificate, public_key):
        result = certificate.verify(public_key)
        if result:
            return True
        else:
            return False

    def get_certificate_validity(self,certificate):
        return (self.get_certificate_date_notBefore(certificate),self.get_certificate_date_notAfter(certificate))

    def get_certificate_pKey(self, certificate):
        return certificate.get_pubkey()

    def get_certificate_pKey_text(self, certificate_object):
        return certificate_object.get_pubkey().get_rsa().as_pem()

    def get_certificate_date_notBefore(self, certificate_object):
        return certificate_object.get_not_before().get_datetime()

    def get_certificate_date_notAfter(self, certificate_object):
        return certificate_object.get_not_after().get_datetime()

    def get_certificate_subject_commonName(self, certificate_object):
        return certificate_object.get_subject().commonName

    def get_certificate_issuer_commonName(self, certificate_object):
        return certificate_object.get_issuer().commonName

    def get_crluri(self):
        return r'X509v3 CRL Distribution Points:\s+Full Name:\s+URI:([^\s]+)'
    def get_crldeltauri(self):
        return r'X509v3 Freshest CRL:\s+Full Name:\s+URI:([^\s]+)'





def dump(src, length=8):
    FILTER = ''.join([(len(repr(chr(x))) == 3) and chr(x) or '.' for x in range(256)])
    N = 0
    result = ''
    while src:
        s, src = src[:length], src[length:]
        hexa = ' '.join(["%02X" % ord(x) for x in s])
        s = s.translate(FILTER)
        result += "%04X   %-*s   %s\n" % (N, length * 3, hexa, s)
        N += length
    return result

def hexx(intval):
    x = hex(intval)[2:]
    if (x[-1:].upper() == 'L'):
        x = x[:-1]
    if len(x) % 2 != 0:
        return "0%s" % x
    return x
