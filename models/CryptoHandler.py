import tls
import hkdf
import hashlib
from cryptography.hazmat.primitives import hashes
from typing import Callable
from models.ECDH import *


class CryptoHandler:
    key_share_entry: tls.KeyShareEntry = None
    cipher_suite: int = None
    hash_algo: hashes.HashAlgorithm
    hashlib_algo: None
    hash_length: int
    
    ecdhparam: ECDH = None
    
    early_secret: bytes
    ecdh_secret: bytes
    handshake_secret: bytes
    master_secret: bytes

    def __init__(self, curve: str):
        self.ecdhparam = ECDH(curve)
    
    def calculate_handshake_secrets(self, server_keyshare: bytes):
        self.ecdh_secret = self.ecdhparam.generate_shared_secret(server_keyshare)
        zeros = self.gen_0_bytes()
        self.early_secret = self.hkdf_extract(zeros, zeros)
        self.handshake_secret = self.hkdf_extract(self.ecdh_secret, self.derive_secret(self.early_secret, "derived", b""))
        self.master_secret = self.hkdf_extract(zeros, self.derive_secret(self.handshake_secret, "derived", b""))
    
    def gen_0_bytes(self) -> bytearray:
        return bytearray(self.hash_length)

    def set_cipher_suite(self, cipher_suite: int):
        sha256_ciphers = (
            tls.TLS_AES_128_CCM_8_SHA256,
            tls.TLS_AES_128_CCM_SHA256,
            tls.TLS_AES_128_GCM_SHA256,
            tls.TLS_CHACHA20_POLY1305_SHA256,
        )
        if cipher_suite == tls.TLS_AES_256_GCM_SHA384:
            self.hash_algo = hashes.SHA384
            self.hash_length = hashes.SHA384.digest_size
            self.hashlib_algo = hashlib.sha384
            return hashes.SHA384
        elif cipher_suite in sha256_ciphers:
            self.hash_algo = hashes.SHA256
            self.hash_length = hashes.SHA256.digest_size
            self.hashlib_algo = hashlib.sha256
            return hashes.SHA256
        else:
            raise Exception("Error setting cipher suite")

    def get_hash_algo(self) -> hashes.HashAlgorithm:
        return self.hash_algo

    def derive_secret(self, secret: bytes, label: str, messages: bytes) -> bytes:
        if self.hash_algo == hashes.SHA256:
            transcript_hash = hashlib.sha256(messages).digest()
        elif self.hash_algo == hashes.SHA384:
            transcript_hash = hashlib.sha384(messages).digest()
        else:
            raise Exception("Error calculating derive secret")
        return self.hkdf_expand_label(
            secret, label, transcript_hash, self.hash_length
        )

    def hkdf_expand_label(self, secret: bytes, label: str, context: bytes, length: int) -> bytes:
        hkdf_label = length.to_bytes(2, "big") + bytes("tls13 " + label, "utf-8") + context
        res = hkdf.hkdf_expand(secret, hkdf_label, length, hash = self.hashlib_algo)
        return res
    
    def hkdf_extract(self, salt: bytes, key: bytes) -> bytes:
        if self.hash_algo == hashes.SHA256:
            hash = hashlib.sha256
        elif self.hash_algo == hashes.SHA384:
            hash = hashlib.sha384
        else:
            raise Exception("Error performing hkdf extract")
        return hkdf.hkdf_extract(salt, key, hash = hash)

    def print_secrets(self):
        print(
            f"{'ECDH secret:':20}" + self.ecdh_secret.hex() + "\n" +
            f"{'Early secret:':20}" + self.early_secret.hex() + "\n" +
            f"{'Handshake secret:':20}" + self.handshake_secret.hex() + "\n" +
            f"{'Master secret:':20}" + self.master_secret.hex() + "\n"
        )