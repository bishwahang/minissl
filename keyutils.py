#!/bin/python
from Crypto.Util.asn1 import DerSequence
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Hash import HMAC
from Crypto.Random import _UserFriendlyRNG as Random
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from M2Crypto import X509 as m2x509
from OpenSSL import crypto as ocrypto
from binascii import a2b_base64,b2a_base64,hexlify


"""
This will read an RSA public key from a DER binary blob. 

The idea for the DER parsing is from:
http://stackoverflow.com/questions/12911373/how-do-i-use-a-x509-certificate-with-pycrypto

Idea: 
 * Read DER using Crypto.Util.asn1.DerSequence, with decode()
 * The first item in the sequence is the certificate...
 * ... and the 6th item is the Subject Public Key Info, the only thing
 that pycrypto will swallow without complaining

Arguments:
blob -- binary string representing a DER file (read from file)

Returns:
RSA public key for use with pyCrypto (Crypto.PublicKey.RSA)
"""
def read_pubkey_from_der(blob):
    cert = DerSequence()
    cert.decode(blob)
    tbsCertificate = DerSequence()
    tbsCertificate.decode(cert[0])
    subjectPublicKeyInfo = tbsCertificate[6]
    return RSA.importKey(subjectPublicKeyInfo)
    

"""
This will read an RSA public key from a PEM string.
Idea:
 * Convert PEM to DER using binascii
 * Call read_pubkey_from_der

Arguments:
pemstring -- String representing a certificate in PEM format

Returns:
RSA public key for use with pyCrypto (Crypto.PublicKey.RSA)
"""
def read_pubkey_from_pem(pemstring):
    lines = pemstring.replace(" ",'').split()
    der = a2b_base64(''.join(lines[1:-1]))
    return read_pubkey_from_der(der)


"""
This will read an RSA private key from a DER binary blob.
Idea: 
 * Read DER using Crypto.Util.asn1.DerSequence, with decode()
 * The first item in the sequence is the certificate...
 * ... and the x th item is the Private Key Info

Arguments:
blob -- binary string representing a private key in DER format (read from file)

Returns:
RSA private key for use with pyCrypto (Crypto.PublicKey.RSA)
"""
def read_privkey_from_der(blob):
    return RSA.importKey(blob)


"""
This will read an RSA private key from a PEM string.
Idea:
 * Convert PEM to DER using binascii
 * Call read_privkey_from_der

Arguments:
pemstring -- String representing a private key in PEM format

Returns:
RSA private key for use with pyCrypto (Crypto.PublicKey.RSA)
"""
def read_privkey_from_pem(pemstring):
    lines = pemstring.replace(" ",'').split()
    der = a2b_base64(''.join(lines[1:-1]))
    return read_privkey_from_der(der)



"""
This will encrypt a message with an RSA public key.

Arguments:
msg -- message, String
pk -- public key, Crypto.PublicKey.RSA

Returns:
ciphertext -- binary string
"""
def encrypt_with_rsa_hybrid(msg, pk):
    aes_key = generate_key(16)
    iv = generate_random(16)
    cipher_aes = AES.new(aes_key, AES.MODE_CFB, iv)
    aes_enc_msg = cipher_aes.encrypt(msg)
    cipher_rsa = PKCS1_OAEP.new(pk)
    return (aes_enc_msg, iv, cipher_rsa.encrypt(aes_key))


"""
Generate a random number.

Returns:
random number -- byte array
"""
def generate_random(bytes):
    return Random.get_random_bytes(bytes)


"""
Generate random key for AES.
Returns:
key -- byte array
"""
def generate_key(bytes=16):
    return generate_random(bytes)



"""
Generate random nonce.
Returns:
nonce -- byte array
"""
def generate_nonce(bytes=28):
    return generate_random(bytes)



"""
Read subject of a X.509 certificate.

Arguments:
pem -- String representing a certificate in PEM format

Returns:
String of subject components
"""
def read_subject(pem):
    return ocrypto.load_certificate(ocrypto.FILETYPE_PEM, pem).get_subject()




"""
Read issuer of a X.509 certificate.

Arguments:
pem -- String representing a certificate in PEM format

Returns:
Tuple of issuer components
"""
def read_issuer(pem):
    return ocrypto.load_certificate(ocrypto.FILETYPE_PEM, pem).get_issuer()




"""
Read notafter of a X.509 certificate.

Arguments:
pem -- String representing a certificate in PEM format

Returns:
String representing notafter
"""
def read_notafter(pem):
    return ocrypto.load_certificate(ocrypto.FILETYPE_PEM, pem).get_notAfter()


"""
Verifies the signature of a certificate.
WARNING: Does not validate anything except the signature.

Arguments:
issuer_cert -- issuer certificate, in PEM, String.
cert -- certificate whose signature is to be verified. In PEM, String.
"""
def verify_certificate(issuer_cert, cert):
    issuer_pubkey = m2x509.load_cert_string(issuer_cert, m2x509.FORMAT_PEM).get_pubkey()
    return m2x509.load_cert_string(cert, m2x509.FORMAT_PEM).verify(issuer_pubkey)



"""
Create a HMAC from a key and data.

Arguments:
secret -- HMAC key, binary array
data -- data to be hashed, binary array

Returns:
HMAC value as hex string
"""
def create_hmac(secret, data):
    h = HMAC.new(secret, 'sha')
    h.update(data)
    return h.hexdigest()
