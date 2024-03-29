import cryptography
import requests as requests

import tls
import hkdf
import hashlib
import hmac
from cryptography.exceptions import UnsupportedAlgorithm, InvalidSignature
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
import re
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from models.ECDH import *
from cryptography.hazmat.primitives.asymmetric import rsa, dsa, ec
from cryptography.hazmat.primitives.asymmetric import padding
from datetime import datetime


class CryptoHandler:
    key_share_entry: tls.KeyShareEntry = None
    cipher_suite: int = None
    hashlib_algo = None  # hashlib hash function
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

    client_handshake_write_key: bytes
    client_handshake_write_iv: bytes
    server_handshake_write_key: bytes
    server_handshake_write_iv: bytes

    # 64 bit sequence number as per rfc8446 section 5.3
    server_sequence_number: int
    client_sequence_number: int

    def __init__(self, curve: str):
        self.ecdhparam = ECDH(curve)
        self.init_sequence_number()

    def xor(self, b1: bytes, b2: bytes):
        return bytes(a ^ b for a, b in zip(b1, b2))

    def init_sequence_number(self):
        self.server_sequence_number = self.client_sequence_number = 0

    # nonce generation as per rfc8446 section 5.3
    def get_next_server_nonce(self, iv: bytes) -> bytes:
        padded_seq = self.server_sequence_number.to_bytes(
            self.traffic_iv_length, "big")
        nonce = self.xor(padded_seq, iv)
        self.server_sequence_number += 1
        return nonce

    # nonce generation as per rfc8446 section 5.3
    def get_next_client_nonce(self, iv: bytes) -> bytes:
        padded_seq = self.client_sequence_number.to_bytes(
            self.traffic_iv_length, "big")
        nonce = self.xor(padded_seq, iv)
        self.client_sequence_number += 1
        return nonce

    # encryption as per rfc8446 section 5.2 and 5.3
    def encrypt_message(self, message: str) -> 'tls.TLSCiphertext':
        tlsinnerbytes = tls.TLSInnerPlaintext(
            message.encode(), tls.ContentType.application_data, b"").to_bytes()
        enc_length = len(tlsinnerbytes) + self.auth_tag_length
        additional_data = tls.ContentType.application_data.to_bytes(
            1, "big") + b"\x03\x03" + enc_length.to_bytes(2, "big")
        nonce = self.get_next_client_nonce(self.client_application_write_iv)
        enc_bytes = self.encrypt_bytes(
            tlsinnerbytes, additional_data, self.client_application_write_key, nonce)
        tlsct = tls.TLSCiphertext(
            tls.ContentType.application_data, tls.TLS12_PROTOCOL_VERSION, enc_length, enc_bytes)
        return tlsct

    # decrytion as per rfc8446 section 5.2 and 5.3
    def decrypt_application_ct(self, tlsct: tls.TLSCiphertext) -> bytes:
        enc_bytes = tlsct.encrypted_record
        nonce = self.get_next_server_nonce(self.server_application_write_iv)
        additional_data = tlsct.type.to_bytes(
            1, "big") + tlsct.legacy_record_version.to_bytes(2, "big") + tlsct.length.to_bytes(2, "big")
        decrypted = self.decrypt_bytes(
            enc_bytes, additional_data, self.server_application_write_key, nonce)
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
            except:
                print("Non-text data:\n" + data.hex() + "\n")
        print("Text data:\n" + text)
        print(f"Total Application TLS records received: {len(decrypted)}")
        return text

    # decrypt, parse and verify encrypted handshake
    def decrypt_handshake(self, tlsct: tls.TLSCiphertext):

        encbytes = tlsct.encrypted_record
        nonce = self.get_next_server_nonce(self.server_handshake_write_iv)
        additional_data = tlsct.type.to_bytes(
            1, "big") + tlsct.legacy_record_version.to_bytes(2, "big") + tlsct.length.to_bytes(2, "big")
        decrypted = self.decrypt_bytes(
            encbytes, additional_data, self.server_handshake_write_key, nonce)
        tlsinner = tls.TLSInnerPlaintext.from_bytes(decrypted)

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
                certificate_verify(hs.data)


            elif hs.msg_type == 15:
                # we do certificate chain verification here
                print("Cert verify found")
                certverify = hs.to_bytes()
                # print(hs)

            elif hs.msg_type == 8:
                print("Encrypted extensions found")
                enc_ext = hs.to_bytes()
            elif hs.msg_type == 20:
                print("Finished found")
                finished = hs.to_bytes()
                finished_hs = hs
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

    # generate as per rfc8446 section 4.4.4
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
        self.init_sequence_number()
        return tlsct

    def generate_change_cipher_spec(self) -> 'tls.TLSPlaintext':
        return tls.TLSPlaintext(tls.ContentType.change_cipher_spec, tls.TLS12_PROTOCOL_VERSION, 1, b"\x01")

    def encrypt_bytes(self, data: bytes, additional_data: bytes, key: bytes, nonce: bytes):
        return AESGCM(key).encrypt(nonce, data, additional_data)

    def decrypt_bytes(self, data: bytes, additional_data: bytes, key: bytes, nonce: bytes):
        return AESGCM(key).decrypt(nonce, data, additional_data)

    def set_handshake_bytes(self, handshake: tls.Handshake, server_handshake: tls.Handshake):
        hsbytes = handshake.to_bytes() + server_handshake.to_bytes()
        self.handshake_bytes = hsbytes

    # calculation as per rfc8446 section 7.1
    def calculate_handshake_secrets(self):
        self.ecdh_secret = self.ecdhparam.generate_shared_secret(
            self.key_share_entry.key_exchange)
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

    # calculation as per rfc8446 section 7.1
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

    def gen_0_bytes(self) -> bytes:
        return bytes(self.hash_length)

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

    # calculation as per rfc8446 section 7.1
    def derive_secret(self, secret: bytes, label: str, messages: bytes) -> bytes:
        transcript_hash = self.transcript_hash(messages)
        return self.hkdf_expand_label(secret, label, transcript_hash, self.hash_length)

    # calculation as per rfc8446 section 7.1
    def transcript_hash(self, context: bytes) -> bytes:
        return self.hashlib_algo(context).digest()

    # length: length in bytes
    # calculation as per rfc8446 section 7.1
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

    # calculation as per rfc8446 section 7.1
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


def certificate_verify(certItSelf):
    server_certs_from_hs = []

    # calculate size of cert
    TotalSize = int.from_bytes(certItSelf[1:4], "big")

    iteratorFront = 4
    iteratorBack = 7

    found_match = False
    root_ca_cert = ""

    while iteratorBack <= TotalSize + 4:
        certCalInt = int.from_bytes(
            certItSelf[iteratorFront:iteratorBack], "big")

        iteratorFront = iteratorBack
        iteratorBack = iteratorBack + certCalInt

        # binary (DER) format
        der_cert = certItSelf[iteratorFront:iteratorBack]
        # Load the server handshake response certificate
        Server_hs_cert = x509.load_der_x509_certificate(der_cert, default_backend())
        # append the server hs certs into a list
        server_certs_from_hs.append(x509.load_der_x509_certificate(der_cert, default_backend()))

        # Load the list of included root CAs
        with open("IncludedRootsPEM.txt", "rb") as f:
            root_ca_pem = f.read()
            regex_pattern = b"-----BEGIN CERTIFICATE-----\r?\n(.*?)\r?\n-----END CERTIFICATE-----"
            matches = re.findall(
                regex_pattern, root_ca_pem, re.DOTALL)

            # Decoding the certificates and creating a list of certificates in PEM format
            root_ca_certs = [b"-----BEGIN CERTIFICATE-----\n" + match + b"\n-----END CERTIFICATE-----" for match in matches]

        for cert_pem in root_ca_certs:
            root_ca_cert = x509.load_pem_x509_certificate(cert_pem, default_backend())

            # Compare the certificates' public keys
            if Server_hs_cert.public_key().public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
            ) == root_ca_cert.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ):
                print(f"This certificate is signed by a trusted root CA {root_ca_cert.subject.rfc4514_string()}.")
                found_match = True
                rootCAMatchedPkCert = Server_hs_cert
                break

        # this part handles ext
        iteratorFront = iteratorBack
        iteratorBack = iteratorBack + 2

        certCalInt = int.from_bytes(
            certItSelf[iteratorFront:iteratorBack], "big")

        iteratorFront = iteratorBack
        iteratorBack = iteratorBack + certCalInt

        # set up for next loop
        iteratorFront = iteratorBack
        iteratorBack = iteratorBack + 3

    if not found_match:
        return print("The certificate trusted root CA is not found in IncludedRootsPEM\n")

    # Verify the certificate chain: Ensure that the server's certificate is signed by a trusted intermediate certificate, which is in turn signed by a trusted root CA.
    # You can do this by checking the signature on each certificate in the chain.
    # This process involves checking if the issuer of each certificate in the chain is the subject of the next certificate in the chain.
    # If any of these steps fail, the certificate chain should be considered invalid and the TLS handshake should be terminated.
    ccv_found_match = False
    now = datetime.utcnow()
    # This part check if the certificate chain is valid and find the server's certificate
    if server_certs_from_hs:
        # Get the issuer of the 1st certificate in the chain (the root CA)
        root_issuer = server_certs_from_hs[0].issuer

        if len(server_certs_from_hs) > 1 and server_certs_from_hs[1].subject == root_issuer:
            # The first certificate in the chain is the server's certificate
            server_cert_index = 0
        else:
            # Check if the subject of the second last certificate in the chain matches the issuer of the last certificate
            if len(server_certs_from_hs) > 1 and server_certs_from_hs[-2].subject == server_certs_from_hs[-1].issuer:
                # The last certificate in the chain is the server's certificate
                server_certs_from_hs = server_certs_from_hs.reverse()
            else:
                # The certificate chain is invalid
                print("Certificate chain is invalid: issuer and subject do not match")
                return None
        #  check for certificate expiration &  whether certificate is revoked
        for scfh in server_certs_from_hs:
            crl_distribution_points = scfh.extensions.get_extension_for_class(x509.CRLDistributionPoints).value
            for crl_dp in crl_distribution_points:
                crl_url = crl_dp.full_name[0].value
                crl_pem_data = requests.get(crl_url)

                # crl_der_data is the fetched DER data from the CRL URL
                crl = x509.load_der_x509_crl(crl_pem_data.content, default_backend())

                if scfh.not_valid_before <= now <= scfh.not_valid_after:

                    print(f"Certificate {scfh.subject.rfc4514_string()} at {now} is still valid.")
                else:
                    print(f"Certificate {scfh.subject.rfc4514_string()} is expired.")
                    ccv_found_match = False
                    break
                # Check if the certificate is revoked
                revoked_cert = crl.get_revoked_certificate_by_serial_number(scfh.serial_number)
                if revoked_cert is not None:
                    print(f"Certificate {scfh.subject.rfc4514_string()} is revoked.")
                    ccv_found_match = False
                else:
                    print(f"Certificate {scfh.subject.rfc4514_string()} is not revoked.")

        # Verify the certificate chain and signature of each certificate
        # Check if the subject of the following certificate in the chain matches the issuer of the prior certificate
        len_of_cert = len(server_certs_from_hs)
        for x in range(0, len_of_cert - 1):
            if server_certs_from_hs[x].issuer != server_certs_from_hs[x + 1].subject:
                print("Certificate chain is invalid: issuer and subject do not match")
                ccv_found_match = False
                break
            else:
                print(f"\nCertificate chain issuer matches subject: \n{server_certs_from_hs[x].subject.rfc4514_string()} -> {server_certs_from_hs[x+1].subject.rfc4514_string()}")

            # before that we check if the signature algorithm used supports the padding scheme; PKCS1v15, for poc not exhaustive
            if server_certs_from_hs[x + 1].signature_algorithm_oid in (
                    x509.SignatureAlgorithmOID.RSA_WITH_SHA256,
                    x509.SignatureAlgorithmOID.RSA_WITH_SHA384,
                    x509.SignatureAlgorithmOID.RSA_WITH_SHA512,
            ):
                padding_scheme = padding.PKCS1v15()
            else:
                raise ValueError(f"Unsupported signature algorithm")

            # verify() method of the PublicKey object takes the signature of the certificate, the bytes of the certificate's to-be-signed portion,
            # the padding algorithm used for the signature, and the signature hash algorithm as arguments.

            # the current order
            # Identified server certificate
            # Intermediate certificate(s)
            # Root certificate

            # If the current server cert is CA1, we should use the pk from our matched rootCA in RootsREM
            # use that rootCA pk and validate CA1 to validate  CA1 cert signature
            # if signature is valid. verify() returns none, prog continues. This means CA1 cert signature is validated and valid
            try:
                server_certs_from_hs[len_of_cert - x - 1].public_key().verify(
                    server_certs_from_hs[len_of_cert - x - 2].signature,
                    server_certs_from_hs[len_of_cert - x - 2].tbs_certificate_bytes,
                    padding_scheme,
                    server_certs_from_hs[len_of_cert - x - 2].signature_hash_algorithm,
                )
            except cryptography.exceptions.InvalidSignature:
                print("\nCertificate chain is invalid: signature is not valid\n")
                ccv_found_match = False
                break
            print("\nCertificate chain is valid: cert signature is valid")
            print("'" + server_certs_from_hs[len_of_cert - x - 1].subject.rfc4514_string() + "'s\t" + " public key was used to verify signature of\t" + "'" + server_certs_from_hs[
                len_of_cert - x - 2].subject.rfc4514_string() + "'")
            # current chain cert validation is valid
            ccv_found_match = True
    if not ccv_found_match:
        print("Server's certificate is not signed by a trusted root CA")
    elif ccv_found_match:
        print(f"Certificate chain verification complete, Server's certificate is signed by a trusted root CA: {root_ca_cert.subject.rfc4514_string()}\n")
