import tls
import hkdf
import hashlib

from Crypto.Cipher import AES
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from models.ECDH import *


class CryptoHandler:
    key_share_entry: tls.KeyShareEntry = None
    cipher_suite: int = None
    hashlib_algo: None  # hashlib hash function
    hash_length: int
    traffic_key_length: int
    traffic_iv_length: int

    ecdhparam: ECDH = None

    early_secret: bytes
    ecdh_secret: bytes
    handshake_secret: bytes
    master_secret: bytes

    handshake_bytes: bytes
    full_handshake_bytes: bytes
    transcript_hash: bytes

    client_handshake_write_key: bytes
    client_handshake_write_iv: bytes
    server_handshake_write_key: bytes
    server_handshake_write_iv: bytes

    # 64 bit sequence number
    sequence_number: int

    def __init__(self, curve: str):
        self.ecdhparam = ECDH(curve)
        self.sequence_number = 1

    def xor(self, b1: bytes, b2: bytes):
        return bytes(a ^ b for a, b in zip(b1, b2))

    def decrypt_handshake(self, tlsct: tls.TLSCiphertext):
        encbytes = tlsct.encrypted_record
        # nonce as per section 5.3, rfc 8446
        padded_seq = self.sequence_number.to_bytes(
            self.traffic_iv_length, "big")
        nonce = self.xor(padded_seq, self.server_handshake_write_iv)
        additional_data = tlsct.type.to_bytes(
            1, "big") + tlsct.legacy_record_version.to_bytes(2, "big") + tlsct.length.to_bytes(2, "big")
        
        
        aesgcm = AESGCM(self.server_handshake_write_key)
        testdecrypt = aesgcm.decrypt(nonce, encbytes, additional_data)
        print(testdecrypt)
        pass

    def set_handshake_bytes(self, clienthello: tls.ClientHello, serverhello: tls.ServerHello):
        hsbytes = clienthello.to_bytes() + serverhello.to_bytes()
        self.handshake_bytes = hsbytes

    def calculate_handshake_secrets(self, server_keyshare: bytes):
        self.ecdh_secret = self.ecdhparam.generate_shared_secret(
            server_keyshare)
        zeros = self.gen_0_bytes()
        self.early_secret = self.hkdf_extract(zeros, zeros)
        self.handshake_secret = self.hkdf_extract(
            self.ecdh_secret, self.derive_secret(
                self.early_secret, "derived", b"")
        )
        self.master_secret = self.hkdf_extract(
            zeros, self.derive_secret(self.handshake_secret, "derived", b"")
        )

        client_handshake_traffic_secret = self.derive_secret(
            self.handshake_secret, "c hs traffic", self.handshake_bytes)
        server_handshake_traffic_secret = self.derive_secret(
            self.handshake_secret, "s hs traffic", self.handshake_bytes)
        self.client_handshake_write_key = self.hkdf_expand_label(
            client_handshake_traffic_secret, "key", b"", self.traffic_key_length)
        self.client_handshake_write_iv = self.hkdf_expand_label(
            client_handshake_traffic_secret, "iv", b"", self.traffic_iv_length)
        self.server_handshake_write_key = self.hkdf_expand_label(
            server_handshake_traffic_secret, "key", b"", self.traffic_key_length)
        self.server_handshake_write_iv = self.hkdf_expand_label(
            server_handshake_traffic_secret, "iv", b"", self.traffic_iv_length)

    def calculate_application_secrets(self):
        client_application_traffic_secret = self.derive_secret(
            self.master_secret, "c ap traffic", self.full_handshake_bytes)
        self.client_application_write_key = self.hkdf_expand_label(
            client_application_traffic_secret, "key", b"", self.traffic_key_length)
        self.client_application_write_iv = self.hkdf_expand_label(
            client_application_traffic_secret, "iv", b"", self.traffic_iv_length)

    def gen_0_bytes(self) -> bytearray:
        return bytearray(self.hash_length)

    def set_cipher_suite(self, cipher_suite: int):
        sha256_ciphers = (
            tls.TLS_AES_128_CCM_8_SHA256,
            tls.TLS_AES_128_CCM_SHA256,
            tls.TLS_AES_128_GCM_SHA256,
            tls.TLS_CHACHA20_POLY1305_SHA256,
        )
        aes128_ciphers = (
            tls.TLS_AES_128_CCM_8_SHA256,
            tls.TLS_AES_128_CCM_SHA256,
            tls.TLS_AES_128_GCM_SHA256,
        )
        if cipher_suite == tls.TLS_AES_256_GCM_SHA384:
            self.hash_length = 48
            self.hashlib_algo = hashlib.sha384
            self.traffic_key_length = 32
            self.traffic_iv_length = 12
        elif cipher_suite in sha256_ciphers and cipher_suite in aes128_ciphers:
            self.hash_length = 32
            self.hashlib_algo = hashlib.sha256
            self.traffic_key_length = 16
            self.traffic_iv_length = 12
        elif cipher_suite == tls.TLS_CHACHA20_POLY1305_SHA256:
            self.hash_length = 32
            self.hashlib_algo = hashlib.sha256
            self.traffic_key_length = 32
            self.traffic_iv_length = 12
        else:
            raise Exception("Error setting cipher suite")

    def derive_secret(self, secret: bytes, label: str, messages: bytes) -> bytes:
        transcript_hash = self.hashlib_algo(messages).digest()
        return self.hkdf_expand_label(secret, label, transcript_hash, self.hash_length)

    # length: length in bytes
    def hkdf_expand_label(
        self, secret: bytes, label: str, context: bytes, length: int
    ) -> bytes:
        hkdf_label = (
            length.to_bytes(2, "big") + bytes("tls13 " +
                                              label, "utf-8") + context
        )
        res = hkdf.hkdf_expand(
            secret, hkdf_label, length, hash=self.hashlib_algo)
        return res

    def hkdf_extract(self, salt: bytes, key: bytes) -> bytes:
        return hkdf.hkdf_extract(salt, key, hash=self.hashlib_algo)

    def print_secrets(self):
        print(
            f"{'ECDH secret:':20}"
            + self.ecdh_secret.hex()
            + "\n"
            + f"{'Early secret:':20}"
            + self.early_secret.hex()
            + "\n"
            + f"{'Handshake secret:':20}"
            + self.handshake_secret.hex()
            + "\n"
            + f"{'Master secret:':20}"
            + self.master_secret.hex()
            + "\n"
        )
