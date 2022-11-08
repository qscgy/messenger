import os
import pickle
import string
from cryptography.hazmat.primitives.asymmetric import dh, ec
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.serialization import PublicFormat, Encoding, PrivateFormat
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class MessengerServer:
    def __init__(self, server_signing_key, server_decryption_key):
        self.server_signing_key = server_signing_key
        self.server_decryption_key = server_decryption_key

    def decryptReport(self, ct):
        raise Exception("not implemented!")
        return

    def signCert(self, cert):
        bytestring = cert.to_bytes()
        signature = self.server_signing_key.sign(bytestring, ec.ECDSA(hashes.SHA256()))
        return signature

class Certificate:
    def __init__(self, name: str, public_key: ec.EllipticCurvePublicKey):
        self.name = name
        self.pkey = public_key
    
    def to_bytes(self):
        # Convert the certificate to bytes
        return b''.join([bytes(self.name, encoding='ascii'), self.pkey.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)])

class ConnState:
    def __init__(self):
        self.DHs = None     # sending DH key pair (our public and private)
        self.DHr = None     # receiving DH public key (other party's public key)
        self.RK = None      # root key
        self.CKs = None     # sending chain key
        self.CKr = None     # receiving chain key
        self.SK = None      # initial shared secret for root key
        self.Ns = 0
        self.Nr = 0
        self.pn = 0
        self.mkskipped = {}

class Header:
    def __init__(self, name, pkey: ec.EllipticCurvePublicKey, pn, n):
        self.name = name
        self.pkey = pkey
        self.pn = pn
        self.n = n
    
    def to_bytes(self):
        return b''.join([
            bytes(self.name, 'ascii'),
            self.pkey.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo),
            bytes(self.pn),
            bytes(self.n)
        ])

MAX_SKIP = 40

class MessengerClient:

    def __init__(self, name: str, server_signing_pk: ec.EllipticCurvePublicKey, server_encryption_pk: ec.EllipticCurvePublicKey):
        self.name = name
        self.server_signing_pk = server_signing_pk
        self.server_encryption_pk = server_encryption_pk
        self.conns = {}
        self.certs = {}

    def generate_keypair(self):
        skey = ec.generate_private_key(curve=ec.SECP256R1())
        pkey = skey.public_key()
        return skey, pkey

    def generateCertificate(self):
        skey, pkey = self.generate_keypair()
        self.DHs = (skey, pkey)
        return Certificate(self.name, pkey)

    def receiveCertificate(self, certificate: Certificate, signature: bytes):
        bytestring = certificate.to_bytes()
        self.server_signing_pk.verify(signature, bytestring, ec.ECDSA(hashes.SHA256()))
        self.certs[certificate.name] = certificate

    def kdf_rk(self, rk_in: bytes, DHs, DHr):
        dh_out = DHs[0].exchange(ec.ECDH(), DHr)
        salt = rk_in

        hkdf = HKDF(algorithm=hashes.SHA256(), length=64, salt=salt, info=None)
        kdf_out = hkdf.derive(dh_out)
        rk = kdf_out[:32]
        ck = kdf_out[32:]
        return rk, ck
    
    def kdf_ck(self, ck: bytes):
        kdf = hmac.HMAC(ck, hashes.SHA256())
        kdf.update(b'\x01')
        mk = kdf.finalize()

        kdf = hmac.HMAC(ck, hashes.SHA256())
        kdf.update(b'\x02')
        ck = kdf.finalize()

        return ck, mk

    def encrypt(self, mk: bytes, plaintext: bytes, ad: bytes):
        # print(mk)
        aesgcm = AESGCM(mk)
        nonce = os.urandom(16)
        ct = aesgcm.encrypt(nonce, plaintext, ad)
        return ct, nonce

    def ratchet_encrypt(self, state: ConnState, plaintext: bytes):
        print(self.name, 'CKs = ', state.CKs)
        state.CKs, mk = self.kdf_ck(state.CKs)
        header = Header(self.name, state.DHs[1], state.pn, state.Ns)
        ct, nonce = self.encrypt(mk, plaintext, header.to_bytes())
        state.Ns += 1
        return ct, nonce, header

    def decrypt(self, mk: bytes, ct: bytes, ad: bytes, nonce: bytes):
        # print(mk)
        aesgcm = AESGCM(mk)
        message = aesgcm.decrypt(nonce, ct, ad)
        return message.decode('ascii')
    
    def dh_ratchet(self, state: ConnState, header: Header):
        state.DHr = header.pkey
        state.pn = state.Ns
        state.Ns = 0
        state.Nr = 0
        state.RK, state.CKr = self.kdf_rk(state.RK, state.DHs, state.DHr)
        # print(self.name, 'ratcheting CKr in dh_ratchet', state.CKr)
        state.DHs = self.generate_keypair()
        state.RK, state.CKs = self.kdf_rk(state.RK, state.DHs, state.DHr)

    def try_skipped(self, state: ConnState, full_header: tuple[Header, bytes], ciphertext: bytes):
        header, nonce = full_header
        if (header.pkey, header.n) in state.mkskipped:
            mk = state.mkskipped[(header.pkey, header.n)]
            del state.mkskipped[(header.pkey, header.n)]
            return self.decrypt(mk, ciphertext, header.to_bytes(), nonce)
        else:
            return None
    
    def skip_keys(self, state: ConnState, until: int):
        if state.Nr + MAX_SKIP < until:
            raise ValueError('Nr should be larger')
        if state.CKr != None:
            while state.Nr < until:
                print(self.name, 'CKr in skip_keys = ', state.CKr)
                state.CKr, mk = self.kdf_ck(state.CKr)
                state.mkskipped[(state.DHr, state.Nr)] = mk
                state.Nr += 1

    def ratchet_decrypt(self, state: ConnState, full_header: tuple[Header, bytes], cipertext: bytes):
        header, nonce = full_header
        plaintext = self.try_skipped(state, full_header, cipertext)
        if plaintext != None:
            return plaintext
        if header.pkey != state.DHr:
            self.skip_keys(state, header.n)
            self.dh_ratchet(state, header)
        self.skip_keys(state, header.n)
        state.Nr += 1
        print(self.name, 'CKr = ', state.CKr)
        state.CKr, mk = self.kdf_ck(state.CKr)
        return self.decrypt(mk, cipertext, header.to_bytes(), nonce)

    def sendMessage(self, name: str, message: str):
        if name not in self.conns:      # if we have not sent or received a message with name, init as Alice
            # Assume we have certificate
            certificate = self.certs[name]
            state = ConnState()

            # handshake to derive shared secret for initial root key
            dh_out = self.DHs[0].exchange(ec.ECDH(), certificate.pkey)
            hkdf_init = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=None)
            state.SK = hkdf_init.derive(dh_out)

            state.DHs = self.generate_keypair()     # generate new keypair
            state.DHr = certificate.pkey

            state.RK, state.CKs = self.kdf_rk(state.SK, state.DHs, state.DHr)
            self.conns[name] = state
        else:
            state = self.conns[name]
        ct, nonce, header = self.ratchet_encrypt(state, bytes(message, encoding='ascii'))
        return (header, nonce), ct
            
    def receiveMessage(self, name: str, header: tuple[Header, bytes], ciphertext: bytes):
        if name not in self.conns:      # if we have not sent or received a message with name, init as Bob
            certificate = self.certs[name]
            state = ConnState()
            state.DHs = self.DHs
            # print(header[0].to_bytes())

            # handshake
            dh_out = self.DHs[0].exchange(ec.ECDH(), certificate.pkey)
            hkdf_init = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=None)
            state.SK = hkdf_init.derive(dh_out)
            state.RK = state.SK
        else:        
            state = self.conns[name]
        plaintext = self.ratchet_decrypt(state, header, ciphertext)
        return plaintext

    def report(self, name, message):
        raise Exception("not implemented!")
        return
