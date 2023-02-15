from dataclasses import dataclass, asdict
from enum import IntEnum
import struct
from typing import List, Union

TLS10_PROTOCOL_VERSION = 0x0301
TLS11_PROTOCOL_VERSION = 0x0302
TLS12_PROTOCOL_VERSION = 0x0303
TLS13_PROTOCOL_VERSION = 0x0304
TLS_ALL_VERSIONS = [TLS10_PROTOCOL_VERSION, TLS11_PROTOCOL_VERSION, TLS12_PROTOCOL_VERSION, TLS13_PROTOCOL_VERSION]

TLS_AES_128_GCM_SHA256 = 0x1301
TLS_AES_256_GCM_SHA384 = 0x1302
TLS_CHACHA20_POLY1305_SHA256 = 0x1303
TLS_AES_128_CCM_SHA256 = 0x1304
TLS_AES_128_CCM_8_SHA256 = 0x1305
TLS_EMPTY_RENEGOTIATION_INFO_SCSV = 0x00ff

class ContentType(IntEnum):
    invalid: int = 0
    change_cipher_spec: int = 20
    alert: int = 21
    handshake: int = 22
    application_data: int = 23
    heartbeat: int = 24
    max_value: int = 255


@dataclass
class TLSPlaintext:
    type: ContentType
    legacy_record_version: int
    length: int
    fragment: bytes

    def to_bytes(self):
        return struct.pack('!BH', self.type.value, self.legacy_record_version) + struct.pack('!H', self.length) + self.fragment

    @classmethod
    def from_bytes(cls, data: bytes):
        type, legacy_record_version = struct.unpack('!BH', data[:3])
        length, = struct.unpack('!H', data[3:5])
        fragment = data[5: 5 + length]
        return cls(ContentType(type), legacy_record_version, length, fragment)


@dataclass
class TLSInnerPlaintext:
    content: bytes
    type: ContentType
    zeros: bytes

    def to_bytes(self):
        return self.content + struct.pack('!B', self.type.value) + self.zeros

    @classmethod
    def from_bytes(cls, data: bytes):
        type = ContentType(data[-1])
        zeros = data[-1:]
        content = data[:-1]
        return cls(content, type, zeros)


@dataclass
class TLSCiphertext:
    opaque_type: ContentType
    legacy_record_version: int
    length: int
    encrypted_record: bytes

    def to_bytes(self):
        return struct.pack('!BH', self.opaque_type.value, self.legacy_record_version) + struct.pack('!H', self.length) + self.encrypted_record

    @classmethod
    def from_bytes(cls, data: bytes):
        opaque_type, legacy_record_version = struct.unpack('!BH', data[:3])
        length, = struct.unpack('!H', data[3:5])
        encrypted_record = data[5: 5 + length]
        return cls(ContentType(opaque_type), legacy_record_version, length, encrypted_record)


class AlertLevel(IntEnum):
    warning = 1
    fatal = 2


class AlertDescription(IntEnum):
    close_notify = 0
    unexpected_message = 10
    bad_record_mac = 20
    decryption_failed_RESERVED = 21
    record_overflow = 22
    decompression_failure_RESERVED = 30
    handshake_failure = 40
    no_certificate_RESERVED = 41
    bad_certificate = 42
    unsupported_certificate = 43
    certificate_revoked = 44
    certificate_expired = 45
    certificate_unknown = 46
    illegal_parameter = 47
    unknown_ca = 48
    access_denied = 49
    decode_error = 50
    decrypt_error = 51
    export_restriction_RESERVED = 60
    protocol_version = 70
    insufficient_security = 71
    internal_error = 80
    inappropriate_fallback = 86
    user_canceled = 90
    no_renegotiation_RESERVED = 100
    missing_extension = 109
    unsupported_extension = 110
    certificate_unobtainable_RESERVED = 111
    unrecognized_name = 112
    bad_certificate_status_response = 113
    bad_certificate_hash_value_RESERVED = 114
    unknown_psk_identity = 115
    certificate_required = 116
    no_application_protocol = 120


@dataclass
class Alert:
    level: AlertLevel
    description: AlertDescription

    def to_bytes(self):
        return self.level.value.to_bytes(1, "big") + self.description.value.to_bytes(1, "big")

    @classmethod
    def from_bytes(cls, data):
        level = AlertLevel(int.from_bytes(data[:1], "big"))
        description = AlertDescription(int.from_bytes(data[1:2], "big"))
        return cls(level, description)


class HandshakeType(IntEnum):
    hello_request_RESERVED = 0
    client_hello = 1
    server_hello = 2
    hello_verify_request_RESERVED = 3
    new_session_ticket = 4
    end_of_early_data = 5
    hello_retry_request_RESERVED = 6
    encrypted_extensions = 8
    certificate = 11
    server_key_exchange_RESERVED = 12
    certificate_request = 13
    server_hello_done_RESERVED = 14
    certificate_verify = 15
    client_key_exchange_RESERVED = 16
    finished = 20
    certificate_url_RESERVED = 21
    certificate_status_RESERVED = 22
    supplemental_data_RESERVED = 23
    key_update = 24
    message_hash = 254


@dataclass
class Handshake:
    msg_type: int
    length: int
    client_hello: 'ClientHello' = None
    server_hello: 'ServerHello' = None

    @classmethod
    def from_bytes(cls, data: bytes):
        msg_type, length = struct.unpack('!B3s', data[:4])
        length = int.from_bytes(length, 'big')
        data = data[4:]

        if msg_type == 1:
            client_hello = ClientHello.from_bytes(data)
            return cls(msg_type, length, client_hello=client_hello)
        elif msg_type == 2:
            server_hello = ServerHello.from_bytes(data)
            return cls(msg_type, length, server_hello=server_hello)
        else:
            raise ValueError(f'Unrecognized msg_type: {msg_type}')

    def to_bytes(self):
        msg_type = struct.pack('!B', self.msg_type)
        length = struct.pack('!I', self.length)[1:]

        if self.client_hello:
            client_hello = self.client_hello.to_bytes()
            return msg_type + length + client_hello
        elif self.server_hello:
            server_hello = self.server_hello.to_bytes()
            return msg_type + length + server_hello
        else:
            raise ValueError('Either client_hello or server_hello must be set')


class ClientHello:
    def __init__(self, random_bytes, legacy_session_id, extensions):
        self.ProtocolVersion = TLS12_PROTOCOL_VERSION
        self.random = random_bytes
        self.legacy_session_id = legacy_session_id
        self.cipher_suites = [TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256, TLS_AES_128_CCM_SHA256, TLS_AES_128_CCM_8_SHA256, TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
        self.legacy_compression_methods = [0x00]
        self.extensions = extensions

    @classmethod
    def from_bytes(cls, data: bytes):
        ProtocolVersion = int.from_bytes(data[:2], byteorder='big')
        random = data[2:34]
        legacy_session_id_len = data[34]
        legacy_session_id = data[35:35+legacy_session_id_len]
        cipher_suites_len = int.from_bytes(
            data[35+legacy_session_id_len:35+legacy_session_id_len+2], byteorder='big')
        cipher_suites = []
        start = 35 + legacy_session_id_len + 2
        end = start + cipher_suites_len
        for i in range(start, end, 2):
            cipher_suites.append(int.from_bytes(data[i:i+2], byteorder='big'))
        legacy_compression_methods_len = data[end]
        legacy_compression_methods = []
        start = end + 1
        end = start + legacy_compression_methods_len
        for i in range(start, end):
            legacy_compression_methods.append(data[i])
        extensions = data[end:]
        return cls(ProtocolVersion, random, legacy_session_id, cipher_suites, legacy_compression_methods, extensions)

    def to_bytes(self):
        protocol_version_bytes = struct.pack('!H', self.ProtocolVersion)
        legacy_session_id_len_bytes = struct.pack('!B', len(self.legacy_session_id))
        cipher_suites_len_bytes = struct.pack('!H', len(self.cipher_suites) * 2)
        cipher_suites_bytes = b''.join([struct.pack('!H', c) for c in self.cipher_suites])
        legacy_compression_methods_len_bytes = struct.pack('!B', len(self.legacy_compression_methods))
        legacy_compression_methods_bytes = b''.join([struct.pack('!B', c) for c in self.legacy_compression_methods])
        extensions_len_bytes = struct.pack('!H', len(self.extensions))
        return protocol_version_bytes + self.random + legacy_session_id_len_bytes + self.legacy_session_id + cipher_suites_len_bytes + cipher_suites_bytes + legacy_compression_methods_len_bytes + legacy_compression_methods_bytes + extensions_len_bytes + self.extensions

@dataclass
class ServerHello:
    legacy_version: int
    random: bytes
    legacy_session_id_echo: bytes
    cipher_suite: bytes
    legacy_compression_method: int
    extensions: bytes

    @classmethod
    def from_bytes(cls, data: bytes):
        legacy_version = int.from_bytes(data[:2], "big")
        random = data[2:34]
        legacy_session_id_echo_length = data[34]
        legacy_session_id_echo = data[35:35 + legacy_session_id_echo_length]
        cipher_suite = data[35 + legacy_session_id_echo_length:37 +
                            legacy_session_id_echo_length]
        legacy_compression_method = data[37 + legacy_session_id_echo_length]
        extensions_length = int.from_bytes(
            data[38 + legacy_session_id_echo_length:40 + legacy_session_id_echo_length], "big")
        extensions = data[40 + legacy_session_id_echo_length: 40 +
                          legacy_session_id_echo_length + extensions_length]
        return cls(legacy_version, random, legacy_session_id_echo, cipher_suite, legacy_compression_method, extensions)

    def to_bytes(self):
        legacy_version_bytes = self.legacy_version.to_bytes(2, "big")
        legacy_session_id_echo_length = len(self.legacy_session_id_echo)
        legacy_session_id_echo_length_bytes = legacy_session_id_echo_length.to_bytes(
            1, "big")
        extensions_length_bytes = len(self.extensions).to_bytes(2, "big")
        return legacy_version_bytes + self.random + legacy_session_id_echo_length_bytes + self.legacy_session_id_echo + self.cipher_suite + bytes([self.legacy_compression_method]) + extensions_length_bytes + self.extensions



@dataclass
class Extension:
    extension_type: int
    extension_data: bytes

    def to_bytes(self):
        return struct.pack('!H', self.extension_type) + struct.pack('!H', len(self.extension_data)) + self.extension_data

    @classmethod
    def from_bytes(cls, data):
        extension_type, data = struct.unpack('!H', data[:2])[0], data[2:]
        length, data = struct.unpack('!H', data[:2])[0], data[2:]
        extension_data = data[:length]
        return cls(extension_type, extension_data), data[length:]

class ExtensionType(IntEnum):
    server_name = 0
    max_fragment_length = 1
    client_certificate_url = 2
    trusted_ca_keys = 3
    truncated_hmac = 4
    status_request = 5
    supported_groups = 10
    ec_point_formats = 11
    signature_algorithms = 13
    use_srtp = 14
    heartbeat = 15
    application_layer_protocol_negotiation = 16
    signed_certificate_timestamp = 18
    client_certificate_type = 19
    server_certificate_type = 20
    padding = 21
    pre_shared_key = 41
    early_data = 42
    supported_versions = 43
    cookie = 44
    psk_key_exchange_modes = 45
    certificate_authorities = 47
    oid_filters = 48
    post_handshake_auth = 49
    signature_algorithms_cert = 50
    key_share = 51

class NameType(IntEnum):
    host_name = 0

class NamedGroup(IntEnum):
    unallocated_RESERVED = 0x0000
    obsolete_RESERVED = 0x0001
    # Elliptic Curve Groups (ECDHE)
    secp256r1 = 0x0017
    secp384r1 = 0x0018
    secp521r1 = 0x0019
    obsolete_RESERVED2 = 0x001A
    x25519 = 0x001D
    x448 = 0x001E
    # Finite Field Groups (DHE)
    ffdhe2048 = 0x0100
    ffdhe3072 = 0x0101
    ffdhe4096 = 0x0102
    ffdhe6144 = 0x0103
    ffdhe8192 = 0x0104
    ffdhe_private_use = 0x01FC
    ecdhe_private_use = 0xFE00
    obsolete_RESERVED3 = 0xFF01

@dataclass
class KeyShareEntry:
    group: NamedGroup
    key_exchange: bytes

    def to_bytes(self):
        return struct.pack("!H", self.group) + struct.pack('!H', len(self.key_exchange)) + self.key_exchange

    @classmethod
    def from_bytes(cls, data):
        group, = struct.unpack("!H", data[:2])
        key_exchange = data[2:]
        return cls(group=NamedGroup(group), key_exchange=key_exchange)

@dataclass
class KeyShareClientHello:
    client_shares: List[KeyShareEntry]

    def to_bytes(self):
        shares_bytes = b"".join(share.to_bytes() for share in self.client_shares)
        return struct.pack("!H", len(shares_bytes)) + shares_bytes

    @classmethod
    def from_bytes(cls, data):
        n, = struct.unpack("!H", data[:2])
        shares_bytes = data[2:]
        client_shares = [KeyShareEntry.from_bytes(shares_bytes[i:i + len(shares_bytes) // n]) for i in range(0, len(shares_bytes), len(shares_bytes) // n)]
        return cls(client_shares=client_shares)

@dataclass
class KeyShareHelloRetryRequest:
    selected_group: NamedGroup

    def to_bytes(self):
        return struct.pack('!H', self.selected_group)

    @classmethod
    def from_bytes(cls, data):
        selected_group, = struct.unpack('!H', data)
        return cls(NamedGroup(selected_group))

@dataclass
class KeyShareServerHello:
    server_share: KeyShareEntry

    def to_bytes(self):
        return self.server_share.to_bytes()

    @classmethod
    def from_bytes(cls, data):
        server_share, data = KeyShareEntry.from_bytes(data)
        return cls(server_share)

class UncompressedPointRepresentation:
    def __init__(self, X, Y):
        self.legacy_form = 4
        self.X = X
        self.Y = Y
    
    @classmethod
    def from_bytes(cls, data: bytes):
        legacy_form, X, Y = struct.unpack("!B32s32s", data)
        return cls(legacy_form, X, Y)

    def to_bytes(self):
        return struct.pack("!B32s32s", self.legacy_form, self.X, self.Y)

class PskKeyExchangeMode(IntEnum):
    psk_ke = 0
    psk_dhe_ke = 1

@dataclass
class PskKeyExchangeModes:
    ke_modes: list

    def to_bytes(self):
        return struct.pack(f"B{len(self.ke_modes)}B", len(self.ke_modes), *self.ke_modes)

    @classmethod
    def from_bytes(cls, data):
        ke_modes_len, *ke_modes = struct.unpack(f"B{ke_modes_len}B", data)
        return cls(ke_modes=ke_modes)

@dataclass
class SupportedVersions:
    msg_type: int
    versions: List[int] = None
    selected_version: bytes = None
    
    def to_bytes(self):
        if self.msg_type == HandshakeType.client_hello: # client_hello
            
            num_versions = struct.pack('!B', len(self.versions) * 2)
            versions = b''.join([struct.pack('!H', v) for v in self.versions])

            return num_versions + versions
        elif self.msg_type == HandshakeType.server_hello: # server_hello or HelloRetryRequest
            return self.selected_version
        else:
            raise ValueError("Invalid value for msg_type")

    @classmethod
    def from_bytes(cls, data: bytes):
        msg_type, = struct.unpack('!H', data[:2])
        if msg_type == HandshakeType.client_hello:
            versions_len = data[2:4]
            versions = []
            for i in range(versions_len):
                offset = 4 + 2 * i
                version, = struct.unpack('!H', data[offset:offset + 2])
                versions.append(version)
            return cls(msg_type, versions=versions)
        elif msg_type == HandshakeType.server_hello:
            selected_version = data[2:4]
            return cls(msg_type, selected_version=selected_version)

@dataclass
class ServerName:
    name_type: int
    name: str

    def to_bytes(self):
        return struct.pack("!B", self.name_type) + \
            struct.pack("!B", len(self.name)) + self.name.encode()

    
@dataclass
class ServerNameList:
    server_name_list: List[ServerName]

    def to_bytes(self):
        server_name_list_bytes = b''
        for sn in self.server_name_list:
            name_len = len(sn.name)
            server_name_list_bytes += struct.pack('!BH', sn.name_type, name_len) + sn.name.encode()
        return struct.pack('!H', len(server_name_list_bytes)) + server_name_list_bytes

    @classmethod
    def from_bytes(cls, data):
        pos = 0
        list_len, = struct.unpack('!H', data[pos:pos+2])
        pos += 2
        server_name_list = []
        while pos < list_len:
            name_type, name_len = struct.unpack('!BH', data[pos:pos+3])
            pos += 3
            name = data[pos:pos+name_len]
            pos += name_len
            server_name_list.append(ServerName(name_type, name))
        return cls(server_name_list)

class SignatureScheme(IntEnum):
    rsa_pkcs1_sha256 = 0x0401
    rsa_pkcs1_sha384 = 0x0501
    rsa_pkcs1_sha512 = 0x0601
    ecdsa_secp256r1_sha256 = 0x0403
    ecdsa_secp384r1_sha384 = 0x0503
    ecdsa_secp521r1_sha512 = 0x0603
    rsa_pss_rsae_sha256 = 0x0804
    rsa_pss_rsae_sha384 = 0x0805
    rsa_pss_rsae_sha512 = 0x0806
    ed25519 = 0x0807
    ed448 = 0x0808
    rsa_pss_pss_sha256 = 0x0809
    rsa_pss_pss_sha384 = 0x080a
    rsa_pss_pss_sha512 = 0x080b
    rsa_pkcs1_sha1 = 0x0201
    ecdsa_sha1 = 0x0203

class SignatureSchemeList:
    def __init__(self, supported_signature_algorithms):
        self.supported_signature_algorithms = supported_signature_algorithms

    def to_bytes(self):
        supported_signature_algorithms_len = len(self.supported_signature_algorithms) * 2
        supported_signature_algorithms_bytes = b''.join(
            [s.to_bytes(2, byteorder='big') for s in self.supported_signature_algorithms]
        )
        return supported_signature_algorithms_len.to_bytes(2, byteorder='big') + supported_signature_algorithms_bytes

    @classmethod
    def from_bytes(cls, data):
        supported_signature_algorithms_len = int.from_bytes(
            data[:2], byteorder='big'
        )
        supported_signature_algorithms = [
            SignatureScheme(int.from_bytes(data[i:i+2], byteorder='big'))
            for i in range(2, supported_signature_algorithms_len + 2, 2)
        ]
        return cls(supported_signature_algorithms)


class NamedGroupList:
    def __init__(self, named_group_list):
        self.named_group_list = named_group_list

    def to_bytes(self):
        named_group_list = len(self.named_group_list) * 2
        named_group_list_bytes = b''.join(
            [s.to_bytes(2, byteorder='big') for s in self.named_group_list]
        )
        return named_group_list.to_bytes(2, byteorder='big') + named_group_list_bytes

    @classmethod
    def from_bytes(cls, data):
        named_group_list_len = int.from_bytes(
            data[:2], byteorder='big'
        )
        named_group_list = [
            NamedGroup(int.from_bytes(data[i:i+2], byteorder='big'))
            for i in range(2, named_group_list_len + 2, 2)
        ]
        return cls(named_group_list)

class ECPointFormat(IntEnum):
    uncompressed = 0
    ansiX962_compressed_prime = 1
    ansiX962_compressed_char2 = 2

class ECPointFormatList:
    def __init__(self, ec_point_format_list):
        self.ec_point_format_list = ec_point_format_list

    def to_bytes(self):
        ec_point_format_list = len(self.ec_point_format_list)
        ec_point_format_list_bytes = b''.join(
            [p.to_bytes(1, byteorder='big') for p in self.ec_point_format_list]
        )
        return ec_point_format_list.to_bytes(1, byteorder='big') + ec_point_format_list_bytes

