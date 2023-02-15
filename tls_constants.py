from dataclasses import dataclass
from enum import IntEnum
import struct
# https://datatracker.ietf.org/doc/rfc8446/
'''
B.1.  Record Layer
enum {
    invalid(0),
    change_cipher_spec(20),
    alert(21),
    handshake(22),
    application_data(23),
    heartbeat(24),  /* RFC 6520 */
    (255)
} ContentType;

struct {
    ContentType type;
    ProtocolVersion legacy_record_version;
    uint16 length;
    opaque fragment[TLSPlaintext.length];
} TLSPlaintext;

struct {
    opaque content[TLSPlaintext.length];
    ContentType type;
    uint8 zeros[length_of_padding];
} TLSInnerPlaintext;

struct {
    ContentType opaque_type = application_data; /* 23 */
    ProtocolVersion legacy_record_version = 0x0303; /* TLS v1.2 */
    uint16 length;
    opaque encrypted_record[TLSCiphertext.length];
} TLSCiphertext;
'''

TLS10_PROTOCOL_VERSION = b'\x03\x01'
TLS12_PROTOCOL_VERSION = b'\x03\x03'

TLS_AES_128_GCM_SHA256 = b'\x13\x01'
TLS_AES_256_GCM_SHA384 = b'\x13\x02'
TLS_CHACHA20_POLY1305_SHA256 = b'\x13\x03'
TLS_AES_128_CCM_SHA256 = b'\x13\x04'
TLS_AES_128_CCM_8_SHA256 = b'\x13\x05'

class ContentType(IntEnum):
    invalid = 0
    change_cipher_spec = 20
    alert = 21
    handshake = 22
    application_data = 23
    heartbeat = 24
    UNKNOWN = 255

@dataclass
class TLSPlaintext:
    type: ContentType
    legacy_record_version = TLS10_PROTOCOL_VERSION #always 0x0301
    length: int
    fragment: bytes

    def to_bytes(self) -> bytes:
        return struct.pack('B', self.type) + self.legacy_record_version + struct.pack("!H", self.length) + self.fragment

    @classmethod
    def from_bytes(cls, data):
        type, legacy_ver, length = struct.unpack('!B2sH', data[:5])
        return cls(type, length, data[5:])

@dataclass
class TLSInnerPlaintext:
    content: bytes
    type: ContentType
    zeros: bytes
    TLS_INNER_SIZE_LIMIT = 0x4001

    def to_bytes(self) -> bytes:
        if not self.is_valid_length():
            raise Exception(f"TLSInnerPlaintext exceeds size limit of {self.TLS_INNER_SIZE_LIMIT} bytes.")
        return self.content + struct.pack('B', type) + self.zeros

    @classmethod
    def from_bytes(cls, data):
        n: int
        type: ContentType
        for index, byte in reversed(list(enumerate(data))):
            if byte == b'\x00':
                continue
            n = index
            type = int(byte)
            break
        content = data[:n]
        return cls(content, type, data[n + 1:])

    def is_valid_length(self) -> bool:
        return len(self.content) + len(self.zeros) + 1 <= self.TLS_INNER_SIZE_LIMIT

#TODO: investigate AEAD expansions
@dataclass
class TLSCiphertext:
    opaque_type = ContentType.application_data
    legacy_record_version = TLS12_PROTOCOL_VERSION #always 0x0303
    length: int
    encrypted_record: bytes
    LENGTH_LIMIT = 0x4100

    def to_bytes(self) -> bytes:
        return struct.pack('B', self.opaque_type) + self.legacy_record_version + struct.pack("!H", self.length) + self.encrypted_record

    @classmethod
    def from_bytes(cls, data):
        op_type, legacy_ver, length = struct.unpack('!B2sH', data[:5])
        ct = cls(op_type, length, data[5:])
        if not ct.is_valid_length():
            raise Exception(f"TLSCiphertext excees size limit of {ct.LENGTH_LIMIT} bytes.")
        return ct

    def is_valid_length(self) -> bool:
        return self.length < self.LENGTH_LIMIT and len(self.encrypted_record) < self.LENGTH_LIMIT

'''
B.2.  Alert Messages

enum { warning(1), fatal(2), (255) } AlertLevel;

enum {
    close_notify(0),
    unexpected_message(10),
    bad_record_mac(20),
    decryption_failed_RESERVED(21),
    record_overflow(22),
    decompression_failure_RESERVED(30),
    handshake_failure(40),
    no_certificate_RESERVED(41),
    bad_certificate(42),
    unsupported_certificate(43),
    certificate_revoked(44),
    certificate_expired(45),
    certificate_unknown(46),
    illegal_parameter(47),
    unknown_ca(48),
    access_denied(49),
    decode_error(50),
    decrypt_error(51),
    export_restriction_RESERVED(60),
    protocol_version(70),
    insufficient_security(71),
    internal_error(80),
    inappropriate_fallback(86),
    user_canceled(90),
    no_renegotiation_RESERVED(100),
    missing_extension(109),
    unsupported_extension(110),
    certificate_unobtainable_RESERVED(111),
    unrecognized_name(112),
    bad_certificate_status_response(113),
    bad_certificate_hash_value_RESERVED(114),
    unknown_psk_identity(115),
    certificate_required(116),
    no_application_protocol(120),
    (255)
} AlertDescription;

struct {
    AlertLevel level;
    AlertDescription description;
} Alert;
'''

class AlertLevel(IntEnum):
    warning = 1
    fatal = 2
    UNKNOWN = 255

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
    UNKNOWN = 255

class Alert:
    def __init__(self, level, description):
        self.level = level
        self.description = description

'''
B.3.  Handshake Protocol

enum {
    hello_request_RESERVED(0),
    client_hello(1),
    server_hello(2),
    hello_verify_request_RESERVED(3),
    new_session_ticket(4),
    end_of_early_data(5),
    hello_retry_request_RESERVED(6),
    encrypted_extensions(8),
    certificate(11),
    server_key_exchange_RESERVED(12),
    certificate_request(13),
    server_hello_done_RESERVED(14),
    certificate_verify(15),
    client_key_exchange_RESERVED(16),
    finished(20),
    certificate_url_RESERVED(21),
    certificate_status_RESERVED(22),
    supplemental_data_RESERVED(23),
    key_update(24),
    message_hash(254),
    (255)
} HandshakeType;

struct {
    HandshakeType msg_type;    /* handshake type */
    uint24 length;             /* bytes in message */
    select (Handshake.msg_type) {
        case client_hello:          ClientHello;
        case server_hello:          ServerHello;
        case end_of_early_data:     EndOfEarlyData;
        case encrypted_extensions:  EncryptedExtensions;
        case certificate_request:   CertificateRequest;
        case certificate:           Certificate;
        case certificate_verify:    CertificateVerify;
        case finished:              Finished;
        case new_session_ticket:    NewSessionTicket;
        case key_update:            KeyUpdate;
    };
} Handshake;
'''
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
    UNKNOWN = 255

class Handshake:
    FORMAT = '!B3s'
    LENGTH_FORMAT = '!I'

    def __init__(self, msg_type, length, payload=None):
        self.msg_type = msg_type
        self.length = length
        self.payload = payload

    @classmethod
    def from_bytes(cls, data):
        msg_type, length_bytes = struct.unpack(cls.FORMAT, data[:4])
        length, = struct.unpack(cls.LENGTH_FORMAT, length_bytes)
        payload = data[4:]
        return cls(msg_type, length, payload)

    def to_bytes(self):
        return struct.pack(self.FORMAT, self.msg_type, struct.pack(self.LENGTH_FORMAT, self.length)) + self.payload
'''
B.3.1.  Key Exchange Messages

uint16 ProtocolVersion;
opaque Random[32];

uint8 CipherSuite[2];    /* Cryptographic suite selector */

struct {
    ProtocolVersion legacy_version = 0x0303;    /* TLS v1.2 */
    Random random;
    opaque legacy_session_id<0..32>;
    CipherSuite cipher_suites<2..2^16-2>;
    opaque legacy_compression_methods<1..2^8-1>;
    Extension extensions<8..2^16-1>;
} ClientHello;

struct {
    ProtocolVersion legacy_version = 0x0303;    /* TLS v1.2 */
    Random random;
    opaque legacy_session_id_echo<0..32>;
    CipherSuite cipher_suite;
    uint8 legacy_compression_method = 0;
    Extension extensions<6..2^16-1>;
} ServerHello;
'''

class ClientHello:
    def __init__(self, random_bytes, legacy_session_id, extensions):
        self.legacy_version = TLS12_PROTOCOL_VERSION
        self.random = random_bytes
        self.legacy_session_id = legacy_session_id
        self.cipher_suites = TLS_AES_128_GCM_SHA256 + TLS_AES_256_GCM_SHA384 + TLS_CHACHA20_POLY1305_SHA256 + TLS_AES_128_CCM_SHA256 + TLS_AES_128_CCM_8_SHA256
        self.legacy_compression_methods = b'\x00'
        self.extensions = extensions

    def to_bytes(self):
        legacy_session_id = struct.pack('B', len(self.legacy_session_id)) + self.legacy_session_id
        cipher_suites = struct.pack('!H', len(self.cipher_suites)) + self.cipher_suites
        legacy_compression_methods = struct.pack('B', len(self.legacy_compression_methods)) + self.legacy_compression_methods
        extensions = struct.pack('!H', len(self.extensions)) + self.extensions

        return self.legacy_version + self.random + legacy_session_id + cipher_suites + legacy_compression_methods + extensions

class ServerHello:
    def __init__(self, random_bytes, cipher_suite, extensions):
        self.legacy_version = TLS12_PROTOCOL_VERSION
        self.random = random_bytes
        self.legacy_session_id_echo = b''
        self.cipher_suite = cipher_suite
        self.legacy_compression_method = 0
        self.extensions = extensions

    def to_bytes(self):
        legacy_session_id_echo = struct.pack('B', len(self.legacy_session_id_echo)) + self.legacy_session_id_echo

        return struct.pack('!H', self.legacy_version) + self.random + legacy_session_id_echo + self.cipher_suite + struct.pack('B', self.legacy_compression_method) + struct.pack('!H', len(self.extensions)) + self.extensions

class ExtensionType(IntEnum):
    server_name = 0
    max_fragment_length = 1
    status_request = 5
    supported_groups = 10
    signature_algorithms = 13
    use_srtp = 14
    heartbeat = 15
    application_layer_protocol_negotiation = 16
    signed_certificate_timestamp = 18
    client_certificate_type = 19
    server_certificate_type = 20
    padding = 21
    RESERVED1 = 40
    pre_shared_key = 41
    early_data = 42
    supported_versions = 43
    cookie = 44
    psk_key_exchange_modes = 45
    RESERVED2 = 46
    certificate_authorities = 47
    oid_filters = 48
    post_handshake_auth = 49
    signature_algorithms_cert = 50
    key_share = 51

