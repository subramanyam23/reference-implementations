import base64
import datetime
import os
import re
import json
import fire as fire
import nacl.encoding
import nacl.hash
from nacl.bindings import crypto_sign_ed25519_sk_to_seed
from nacl.signing import SigningKey, VerifyKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey,X25519PublicKey
from cryptography.hazmat.primitives import serialization
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad,unpad

class DHKeyPair:
    def __init__(self, private_key, public_key):
        self.private_key = private_key
        self.public_key = public_key

def generate_key_pair():

    inst_private_key = X25519PrivateKey.generate()
    inst_public_key = inst_private_key.public_key()
    
    bytes_private_key = inst_private_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    bytes_public_key = inst_public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    private_key = base64.b64encode(bytes_private_key).decode('utf-8')
    public_key = base64.b64encode(bytes_public_key).decode('utf-8')
    
    return DHKeyPair(private_key, public_key)

def generate_shared_key(private_key_str, public_key_str):

    private_key = serialization.load_der_private_key(
                base64.b64decode(private_key_str),
                password=None
            )
    public_key = serialization.load_der_public_key(
        base64.b64decode(public_key_str)
    )

    shared_key = private_key.exchange(public_key)
    shared_key = base64.b64encode(shared_key).decode('utf-8')
    return shared_key