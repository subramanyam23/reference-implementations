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
from Crypto.Random import get_random_bytes
from Cryptodome.Util.Padding import pad,unpad



def encrypt_data(key, data):
    IV_BYTE_LENGTH=12
    shared_key = base64.b64decode(key)
    nonce = get_random_bytes(IV_BYTE_LENGTH)
    
    cipher = AES.new(shared_key, AES.MODE_GCM, nonce=nonce)
    ciphertext, auth_tag = cipher.encrypt_and_digest(data.encode())
    
    encrypted_payload = {
        'nonce': base64.b64encode(cipher.nonce).decode("utf-8"),
        'encrypted_data': base64.b64encode(ciphertext).decode("utf-8"),
        'hmac': base64.b64encode(auth_tag).decode("utf-8")
    }
    
    return base64.b64encode(json.dumps(encrypted_payload).encode()).decode("utf-8")

def decrypt_data(key, e_data):
    shared_key = base64.b64decode(key)
    
    decoded_payload = json.loads(base64.b64decode(e_data))

    print(decoded_payload)
    nonce = base64.b64decode(decoded_payload["nonce"])
    encrypted_data = base64.b64decode( decoded_payload["encrypted_data"])
    auth_tag =base64.b64decode( decoded_payload["hmac"])

    cipher = AES.new(shared_key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(encrypted_data, auth_tag)
    return plaintext.decode('utf-8')