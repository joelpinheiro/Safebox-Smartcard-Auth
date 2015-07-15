#   Portuguese Citizen Card Module for SafeBox  
#   authors: Miguel Vicente
#            Joel Pinheiro
#   reference:
#   www.bit4id.org/trac/pykcs11

import PyKCS11
import getopt
import sys
import platform
import base64
from datetime import datetime
from PyKCS11 import MechanismRSAPKCS1
#from M2Crypto import X509

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

    def sign(self,toSign):
        #assinar challenge do servidor com a chave privada
        try:
            mech = MechanismRSAPKCS1
            self.signature = self.session.sign(self.key,toSign,mecha=mech)
            #print dump(''.join(map(chr, self.signature)), 16)

            sign = ''
            for s in self.signature:
                bytechar = bytes(chr(s))
                sign += bytechar

            print "PYTHON Signature: %s" % sign
            print "PYTHON Signature length: %d" % len(sign)
            print "PYTHON Encoded Signature: %s" % base64.b64encode(sign)
            return base64.b64encode(sign)
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
