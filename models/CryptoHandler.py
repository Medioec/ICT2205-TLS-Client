import tls
import hkdf
import hashlib
import hmac

<<<<<<< Updated upstream
=======
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
import base64
import re
#from crypto.Cipher import AES
>>>>>>> Stashed changes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from models.ECDH import *


class CryptoHandler:
    key_share_entry: tls.KeyShareEntry = None
    cipher_suite: int = None
    hashlib_algo: None  # hashlib hash function
    hash_length: int
    traffic_key_length: int
    traffic_iv_length: int
    auth_tag_length: int

    ecdhparam: ECDH = None

    clientrandom: bytes

    early_secret: bytes
    ecdh_secret: bytes
    handshake_secret: bytes
    master_secret: bytes

    handshake_bytes: bytes
    # verification as per 4.4
    client_handshake_context: bytes
    server_handshake_context: bytes
    full_handshake_bytes: bytes

    client_handshake_write_key: bytes
    client_handshake_write_iv: bytes
    server_handshake_write_key: bytes
    server_handshake_write_iv: bytes

    # 64 bit sequence number
    server_sequence_number: int
    client_sequence_number: int

    def __init__(self, curve: str):
        self.ecdhparam = ECDH(curve)
        self.server_sequence_number = 0
        self.client_sequence_number = 0

    def xor(self, b1: bytes, b2: bytes):
        return bytes(a ^ b for a, b in zip(b1, b2))

    def get_next_server_nonce(self, iv: bytes) -> bytes:
        padded_seq = self.server_sequence_number.to_bytes(
            self.traffic_iv_length, "big")
        nonce = self.xor(padded_seq, iv)
        self.server_sequence_number += 1
        return nonce

    def get_next_client_nonce(self, iv: bytes) -> bytes:
        padded_seq = self.client_sequence_number.to_bytes(
            self.traffic_iv_length, "big")
        nonce = self.xor(padded_seq, iv)
        self.client_sequence_number += 1
        return nonce

    def encrypt_message(self, message: str) -> 'tls.TLSCiphertext':
        tlsinnerbytes = tls.TLSInnerPlaintext(
            message.encode(), tls.ContentType.application_data, b"").to_bytes()
        enc_length = len(tlsinnerbytes) + self.auth_tag_length
        additional_data = tls.ContentType.application_data.to_bytes(
            1, "big") + b"\x03\x03" + enc_length.to_bytes(2, "big")
        cipher = AESGCM(self.client_application_write_key)
        nonce = self.get_next_client_nonce(self.client_application_write_iv)
        enc_bytes = cipher.encrypt(nonce, tlsinnerbytes, additional_data)
        tlsct = tls.TLSCiphertext(
            tls.ContentType.application_data, tls.TLS12_PROTOCOL_VERSION, enc_length, enc_bytes)
        return tlsct

    def decrypt_application_ct(self, tlsct: tls.TLSCiphertext) -> bytes:
        enc_bytes = tlsct.encrypted_record
        nonce = self.get_next_server_nonce(self.server_application_write_iv)
        additional_data = tlsct.type.to_bytes(
            1, "big") + tlsct.legacy_record_version.to_bytes(2, "big") + tlsct.length.to_bytes(2, "big")
        aesgcm = AESGCM(self.server_application_write_key)
        decrypted = aesgcm.decrypt(nonce, enc_bytes, additional_data)
        return decrypted

    def decrypt_application_bytes(self, raw_bytes: bytes) -> str:
        tls_rl = tls.TLSRecordLayer.parse_records(raw_bytes)
        decrypted: list[bytes] = []
        for tlsct in tls_rl.records:
            decrypted.append(self.decrypt_application_ct(tlsct))
        text = ""
        print("\n\nServer Response:\n\n")
        for data in decrypted:
            try:
                text += data.decode()
            except Exception:
                print("\n\nNon-text data: " + data.hex() + "\n\n")
        print("Text:\n" + text)
        return text

    def decrypt_handshake(self, tlsct: tls.TLSCiphertext):
        encbytes = tlsct.encrypted_record
        # nonce as per section 5.3, rfc 8446
        nonce = self.get_next_server_nonce(self.server_handshake_write_iv)
        additional_data = tlsct.type.to_bytes(
            1, "big") + tlsct.legacy_record_version.to_bytes(2, "big") + tlsct.length.to_bytes(2, "big")
        aesgcm = AESGCM(self.server_handshake_write_key)
        decrypted = aesgcm.decrypt(nonce, encbytes, additional_data)
        tlsinner = tls.TLSInnerPlaintext.from_bytes(decrypted)

        # TODO replace with correct code, need unwrap?
        hslist = tlsinner.parse_encrypted_handshake()
        self.client_handshake_context = self.handshake_bytes
        self.server_handshake_context = self.handshake_bytes
        enc_ext = cert = certverify = finished = bytes()
        finished_hs: tls.Handshake = None
        print("Decrypting server handshake response: ")
        for hs in hslist:
            if hs.msg_type == 11:
                print("Cert found")
                cert = hs.to_bytes()


                print("\n\nCert is confirm in here somewhere \n\n")


                certItSelf = hs.data

                if int.from_bytes(certItSelf[0:1], "big") == 0:
                    print("This shit is X509")
                elif int.from_bytes(certItSelf[0:1], "big") == 2:
                    print("This shit is RawPublicKey")

                TotalSize = int.from_bytes(certItSelf[1:4], "big") # calculate size of cert
                
                print ("Total Size of cert is: ")
                print(TotalSize)
                iteratorFront = 4 
                iteratorBack = 7
                certificates = []
                while iteratorBack <= TotalSize + 4:
                    #this part handles data
                    print("Size of sector")
                    print (certItSelf[iteratorFront:iteratorBack].hex()) # this print size of data
                    certCalInt = int.from_bytes(certItSelf[iteratorFront:iteratorBack], "big")
                    print("Size of sector in int")
                    print (certCalInt) # this print the size of data in int
                    iteratorFront = iteratorBack
                    iteratorBack = iteratorBack + certCalInt
                    print("Data of sector")
                    print (certItSelf[iteratorFront:iteratorBack].hex()) # this print data itself
                    # Your X.509 certificate in hex format (as a string)
                    hex_cert = certItSelf[iteratorFront:iteratorBack].hex()
                    # Convert the hex string to binary (DER) format
                    der_cert = bytes.fromhex(hex_cert)
                    # Parse the binary (DER) certificate
                    Server_hs_cert = x509.load_der_x509_certificate(der_cert, default_backend())

                    found_match = False

                    with open("IncludedRootsPEM.txt", "rb") as f:
                        root_ca_pem = f.read()
                        regex_pattern = b"-----BEGIN CERTIFICATE-----\r?\n(.*?)\r?\n-----END CERTIFICATE-----"
                        matches = re.findall(regex_pattern, root_ca_pem, re.DOTALL)

                        # Decoding the certificates and creating a list of certificates in PEM format
                        certificates = [b"-----BEGIN CERTIFICATE-----\n" + match + b"\n-----END CERTIFICATE-----" for match in matches]

                    for cert_pem in certificates:
                        root_ca_cert = x509.load_pem_x509_certificate(cert_pem, default_backend())

                        # Compare the certificates' public keys
                        if Server_hs_cert.public_key().public_bytes(
                                encoding=serialization.Encoding.PEM,
                                format=serialization.PublicFormat.SubjectPublicKeyInfo
                        ) == root_ca_cert.public_key().public_bytes(
                            encoding=serialization.Encoding.PEM,
                            format=serialization.PublicFormat.SubjectPublicKeyInfo
                        ):
                            print(f"The certificate matches the root CA in IncludedRootsPEM.txt")
                            found_match = True
                            break

                    if not found_match:
                        print("The certificate doesn't match any of the root CA files.")

                    #this part handles ext
                    iteratorFront = iteratorBack
                    iteratorBack = iteratorBack + 2
                    print("Size of extensions")
                    print (certItSelf[iteratorFront:iteratorBack].hex()) # this print size of ext
                    certCalInt = int.from_bytes(certItSelf[iteratorFront:iteratorBack], "big") 
                    print("Size of extensions in int")
                    print (certCalInt) # this print the size of ext in int
                    iteratorFront = iteratorBack
                    iteratorBack = iteratorBack + certCalInt
                    print("Data of extensions")
                    print (certItSelf[iteratorFront:iteratorBack].hex()) # this print ext itself
              

                    #set up for next loop
                    iteratorFront = iteratorBack
                    iteratorBack = iteratorBack + 3
  


                print("\n\nCert is confirm up there somewhere \n\n")



            elif hs.msg_type == 15:
                print("Cert verify found")
                certverify = hs.to_bytes()
            elif hs.msg_type == 8:
                print("Encrypted extensions found")
                enc_ext = hs.to_bytes()
            elif hs.msg_type == 20:
                print("Finished found")
                finished = hs.to_bytes()
        self.client_handshake_context += enc_ext + cert + certverify + finished
        self.server_handshake_context += enc_ext + cert + certverify
        # Calculate verify_data as per 4.4.4
        finished_key = self.hkdf_expand_label(
            self.server_handshake_traffic_secret, "finished", b"", self.hash_length)
        server_mac = hmac.new(finished_key, self.transcript_hash(
            self.server_handshake_context), self.hashlib_algo)
        verify_data = server_mac.digest()
        if finished_hs is not None and verify_data != finished_hs.data:
            raise Exception("Calculated MAC is different from server MAC")

    def generate_client_finished_handshake(self) -> 'tls.TLSCiphertext':
        finished_key = self.hkdf_expand_label(
            self.client_handshake_traffic_secret, "finished", b"", self.hash_length)
        client_mac = hmac.new(finished_key, self.transcript_hash(
            self.client_handshake_context), self.hashlib_algo)
        verify_data = client_mac.digest()
        contenttype = tls.ContentType.application_data
        version = tls.TLS12_PROTOCOL_VERSION
        tlsinnerdata = tls.Handshake(
            tls.HandshakeType.finished, len(verify_data), data=verify_data)
        tlsinnerpt = tls.TLSInnerPlaintext(
            tlsinnerdata.to_bytes(), tls.ContentType.handshake, b"")
        ctlen = len(tlsinnerpt.to_bytes()) + self.auth_tag_length
        additional_data = contenttype.to_bytes(
            1, "big") + version.to_bytes(2, "big") + ctlen.to_bytes(2, "big")

        nonce = self.get_next_client_nonce(self.client_handshake_write_iv)
        enc_bytes = self.encrypt_bytes(tlsinnerpt.to_bytes(
        ), additional_data, self.client_handshake_write_key, nonce)
        tlsct = tls.TLSCiphertext(contenttype, version, ctlen, enc_bytes)
        self.client_sequence_number = 0
        self.server_sequence_number = 0
        return tlsct

    def generate_change_cipher_spec(self) -> 'tls.TLSPlaintext':
        return tls.TLSPlaintext(tls.ContentType.change_cipher_spec, tls.TLS12_PROTOCOL_VERSION, 1, b"\x01")

    def encrypt_bytes(self, data: bytes, additional_data: bytes, key: bytes, nonce: bytes):
        return AESGCM(key).encrypt(nonce, data, additional_data)

    def set_handshake_bytes(self, handshake: tls.Handshake, server_handshake: tls.Handshake):
        hsbytes = handshake.to_bytes() + server_handshake.to_bytes()
        self.handshake_bytes = hsbytes

    def calculate_handshake_secrets(self, server_keyshare: bytes):
        self.ecdh_secret = self.ecdhparam.generate_shared_secret(
            server_keyshare)
        zeros = self.gen_0_bytes()
        self.early_secret = self.hkdf_extract(zeros, zeros)
        self.handshake_secret = self.hkdf_extract(
            self.derive_secret(self.early_secret, "derived", b""),
            self.ecdh_secret
        )
        self.master_secret = self.hkdf_extract(
            self.derive_secret(self.handshake_secret, "derived", b""),
            zeros
        )

        self.client_handshake_traffic_secret = self.derive_secret(
            self.handshake_secret, "c hs traffic", self.handshake_bytes)
        self.server_handshake_traffic_secret = self.derive_secret(
            self.handshake_secret, "s hs traffic", self.handshake_bytes)
        self.client_handshake_write_key = self.hkdf_expand_label(
            self.client_handshake_traffic_secret, "key", b"", self.traffic_key_length)
        self.client_handshake_write_iv = self.hkdf_expand_label(
            self.client_handshake_traffic_secret, "iv", b"", self.traffic_iv_length)
        self.server_handshake_write_key = self.hkdf_expand_label(
            self.server_handshake_traffic_secret, "key", b"", self.traffic_key_length)
        self.server_handshake_write_iv = self.hkdf_expand_label(
            self.server_handshake_traffic_secret, "iv", b"", self.traffic_iv_length)

    def calculate_application_secrets(self):
        self.client_application_traffic_secret = self.derive_secret(
            self.master_secret, "c ap traffic", self.client_handshake_context
        )
        self.server_application_traffic_secret = self.derive_secret(
            self.master_secret, "s ap traffic", self.client_handshake_context
        )
        self.client_application_write_key = self.hkdf_expand_label(
            self.client_application_traffic_secret, "key", b"", self.traffic_key_length)
        self.client_application_write_iv = self.hkdf_expand_label(
            self.client_application_traffic_secret, "iv", b"", self.traffic_iv_length)
        self.server_application_write_key = self.hkdf_expand_label(
            self.server_application_traffic_secret, "key", b"", self.traffic_key_length
        )
        self.server_application_write_iv = self.hkdf_expand_label(
            self.server_application_traffic_secret, "iv", b"", self.traffic_iv_length
        )

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
            self.auth_tag_length = 16
        elif cipher_suite in sha256_ciphers and cipher_suite in aes128_ciphers:
            self.hash_length = 32
            self.hashlib_algo = hashlib.sha256
            self.traffic_key_length = 16
            self.traffic_iv_length = 12
            self.auth_tag_length = 16
        elif cipher_suite == tls.TLS_CHACHA20_POLY1305_SHA256:
            self.hash_length = 32
            self.hashlib_algo = hashlib.sha256
            self.traffic_key_length = 32
            self.traffic_iv_length = 12
        else:
            raise Exception("Error setting cipher suite")

    def derive_secret(self, secret: bytes, label: str, messages: bytes) -> bytes:
        transcript_hash = self.transcript_hash(messages)
        return self.hkdf_expand_label(secret, label, transcript_hash, self.hash_length)

    def transcript_hash(self, context: bytes) -> bytes:
        return self.hashlib_algo(context).digest()

    # length: length in bytes
    def hkdf_expand_label(
        self, secret: bytes, label: str, context: bytes, length: int
    ) -> bytes:
        labelstring = "tls13 " + label
        labellen = len(labelstring).to_bytes(1, "big")
        contextlen = len(context).to_bytes(1, "big")
        hkdf_label = (
            length.to_bytes(2, "big") + labellen +
            labelstring.encode() + contextlen + context
        )
        res = hkdf.hkdf_expand(
            secret, hkdf_label, length, hash=self.hashlib_algo)
        return res

    def hkdf_extract(self, salt: bytes, key: bytes) -> bytes:
        return hkdf.hkdf_extract(salt, key, hash=self.hashlib_algo)

    def print_secrets(self):
        print(
            f"{'ECDH secret:':20} {self.ecdh_secret.hex()}\n"
            f"{'Early secret:':20} {self.early_secret.hex()}\n"
            f"{'Handshake secret:':20} {self.handshake_secret.hex()}\n"
            f"{'Master secret:':20} {self.master_secret.hex()}\n"
            f"{'Client hs key:':20} {self.client_handshake_write_key.hex()}\n"
            f"{'Client hs iv:':20} {self.client_handshake_write_iv.hex()}\n"
            f"{'Server hs key:':20} {self.server_handshake_write_key.hex()}\n"
            f"{'Server hs iv:':20} {self.server_handshake_write_iv.hex()}\n"
            f"{'Client app key: ':20} {self.client_application_write_key.hex()}\n"
            f"{'Client app iv: ':20} {self.client_application_write_iv.hex()}\n"
            f"{'Server app key: ':20} {self.server_application_write_key.hex()}\n"
            f"{'Server app iv: ':20} {self.server_application_write_iv.hex()}\n"
        )

