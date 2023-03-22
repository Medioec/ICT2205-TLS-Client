import argparse
import re
import secrets
import socket
import tls
import tls_constants
import x25519

from typing import Tuple
from models.CryptoHandler import *

pattern = re.compile(
    r"^(([a-zA-Z]{1})|([a-zA-Z]{1}[a-zA-Z]{1})|"
    r"([a-zA-Z]{1}[0-9]{1})|([0-9]{1}[a-zA-Z]{1})|"
    r"([a-zA-Z0-9][-_.a-zA-Z0-9]{0,61}[a-zA-Z0-9]))\."
    r"([a-zA-Z]{2,13}|[a-zA-Z0-9-]{2,30}.[a-zA-Z]{2,3})$"
)


def hostname(hostname):
    if pattern.match(hostname):
        return hostname
    else:
        raise argparse.ArgumentTypeError(f"{hostname} is an invalid hostname.")


def port(port_num):
    port = int(port_num, 10)
    if port < 1 or port > 65535:
        raise argparse.ArgumentTypeError(
            f"{port_num} is an invalid port number. Valid choices: 1-65535"
        )
    return port


parser = argparse.ArgumentParser(
    prog="TLS 1.3 Client",
    description="A program to connect to services secured with TLS 1.3.\n"
    + "For your convenience the Mozilla Root CA is included with this program, however if you do not trust it you may choose to use your own.\n"
    + "A trusted Root CA file is required to use this program.\n"
    "You can download it at https://wiki.mozilla.org/CA/Included_Certificates",
    epilog="ICT2205",
    formatter_class=argparse.RawDescriptionHelpFormatter,
)
parser.add_argument("hostname", help="Target hostname.", type=hostname)
parser.add_argument(
    "port", help="Target port number in base 10. Valid choices: 1-65535", type=port
)
parser.add_argument(
    "-ca",
    metavar="certificate_authorities",
    help="Trusted Root CA file",
    required=False,
)
parser.add_argument(
    "-debug",
    metavar="debug_filename",
    help="Save session keys to this file",
    required=False,
)


def main():
    args = parser.parse_args()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            # sni, ec, groups, session ticket, etm, extended master secret, sigalgo, versions, psk key exchange modes, key share
            crypto = CryptoHandler("x25519")
            x25519_public = crypto.ecdhparam.public
            ip = socket.gethostbyname(args.hostname)
            print("Destination ip: " + ip)
            clientrandom = secrets.token_bytes(32)
            legacy_session_id = secrets.token_bytes(32)
            sni = tls.ServerName(tls.NameType.host_name, args.hostname)
            snilist = tls.ServerNameList([sni])
            sniext = tls.Extension(tls.ExtensionType.server_name, snilist.to_bytes())
            tls13 = tls.Extension(
                tls.ExtensionType.supported_versions,
                tls.SupportedVersions(
                    tls.HandshakeType.client_hello, [tls.TLS13_PROTOCOL_VERSION]
                ).to_bytes(),
            )
            signaturealgo = tls.Extension(
                tls.ExtensionType.signature_algorithms,
                tls.SignatureSchemeList(
                    [
                        tls.SignatureScheme.ecdsa_secp256r1_sha256,
                        tls.SignatureScheme.ecdsa_secp384r1_sha384,
                        tls.SignatureScheme.ecdsa_secp521r1_sha512,
                        tls.SignatureScheme.ed25519,
                        tls.SignatureScheme.ed448,
                    ]
                ).to_bytes(),
            )
            groups = tls.Extension(
                tls.ExtensionType.supported_groups,
                tls.NamedGroupList([tls.NamedGroup.x25519]).to_bytes(),
            )
            session_ticket = tls.Extension(
                tls.ExtensionType.session_ticket,
                "".encode(),
            )
            encrypt_then_mac = tls.Extension(
                tls.ExtensionType.encrypt_then_mac,
                "".encode(),
            )
            extended_master_secret = tls.Extension(
                tls.ExtensionType.extended_master_secret,
                "".encode(),
            )
            psk_key_exchange_modes = tls.Extension(
                tls.ExtensionType.psk_key_exchange_modes,
                tls.PskKeyExchangeModes([tls.PskKeyExchangeMode.psk_dhe_ke]).to_bytes(),
            )
            keyshare = tls.Extension(
                tls.ExtensionType.key_share,
                tls.KeyShareClientHello(
                    [tls.KeyShareEntry(tls.NamedGroup.x25519, x25519_public)]
                ).to_bytes(),
            )
            ec_point_format_list = tls.Extension(
                tls.ExtensionType.ec_point_formats,
                tls.ECPointFormatList([tls.ECPointFormat.uncompressed]).to_bytes(),
            )
            extensions = (
                sniext.to_bytes()
                + ec_point_format_list.to_bytes()
                + groups.to_bytes()
                + session_ticket.to_bytes()  # optional
                + encrypt_then_mac.to_bytes()  # optional
                + extended_master_secret.to_bytes()  # optional
                + signaturealgo.to_bytes()
                + tls13.to_bytes()
                + psk_key_exchange_modes.to_bytes()
                + keyshare.to_bytes()
            )
            clienthello = tls.ClientHello(clientrandom, legacy_session_id, extensions)
            handshake = tls.Handshake(
                tls.HandshakeType.client_hello, len(clienthello.to_bytes()), clienthello
            )
            tlspt_clienthello = tls.TLSPlaintext(
                tls.ContentType.handshake,
                tls.TLS10_PROTOCOL_VERSION,
                len(handshake.to_bytes()),
                handshake.to_bytes(),
            )
            s.connect((ip, args.port))
            s.sendall(tlspt_clienthello.to_bytes())

            done = False
            tls_list: list[tls.TLSRecordLayer] = []
            while not done:
                sh_bytes = s.recv(16384)
                done, clienthello, tls_record_layer = verify_response(
                    clienthello, sh_bytes, s
                )
                tls_list.append(tls_record_layer)
            parse_server_hello(handshake, tls_list, crypto)
            # TODO ECDHE calculation for decryption of server certs, verify server certs
            # rfc7748
            crypto.calculate_handshake_secrets(crypto.key_share_entry.key_exchange)
            crypto.print_secrets()
            encrypted_handshakes: list[tls.TLSCiphertext] = []
            for packet in tls_list:
                for record in packet.records:
                    if record.type == tls.ContentType.application_data:
                        encrypted_handshakes.append(record)
            for enc in encrypted_handshakes:
                crypto.decrypt_handshake(enc)
        except socket.gaierror:
            # this means could not resolve the host
            print(f"Could not find host {args.hostname}")
    return


def parse_server_hello(handshake: tls.Handshake, tls_list: list[tls.TLSRecordLayer], crypto: CryptoHandler):
    server_handshake = None
    for recordlayer in tls_list:
        server_handshake = recordlayer.parse_handshake()
        if server_handshake == None or server_handshake.server_hello == None:
            continue
        else:
            break
    if server_handshake == None or server_handshake.server_hello == None:
        raise Exception("Unexpected error")
    extlist = server_handshake.server_hello.list_extensions()
    for ext in extlist:
        etype = ext.extension_type
        if etype == tls.ExtensionType.key_share:
            key_share_entry = tls.KeyShareEntry.from_bytes(ext.extension_data)
            crypto.key_share_entry = key_share_entry
            break
    crypto.set_cipher_suite(server_handshake.server_hello.cipher_suite)
    ################
    crypto.set_handshake_bytes(handshake, server_handshake)


def verify_response(
    clienthello: tls.ClientHello, server_response: bytes, s: socket
) -> Tuple[bool, tls.ClientHello, tls.TLSRecordLayer]:
    recordlayer = tls.TLSRecordLayer.parse_records(server_response)
    check_for_alerts(recordlayer)
    handshake = recordlayer.parse_handshake()
    if handshake == None or handshake.server_hello == None:
        # no handshake found
        return
    res, clienthello, serverhello = check_server_hello(
        handshake.server_hello, clienthello
    )
    if res != True:
        # TODO handle hello retry request
        raise Exception("Hello retry not implemented")
    return recordlayer.is_handshake_complete(), clienthello, recordlayer


def check_server_hello(
    serverhello: tls.ServerHello, clienthello: tls.ClientHello
) -> Tuple[bool, tls.ClientHello, tls.ServerHello]:
    # check for special values in random
    if serverhello.random == bytes.fromhex(
        "CF21AD74E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A8339C"
    ):  # indicates hello retry request
        return False, clienthello, serverhello
    elif serverhello.random[-8:] == bytes.fromhex("444F574E47524401"):
        raise Exception("illegal parameter")
    elif serverhello.random[-8:] == bytes.fromhex("444F574E47524400"):
        raise Exception("illegal parameter")
    # handle normally
    if serverhello.legacy_version != 0x0303:
        raise Exception("illegal parameter")
    if serverhello.legacy_session_id_echo != clienthello.legacy_session_id:
        raise Exception("illegal parameter")
    if serverhello.cipher_suite not in clienthello.cipher_suites:
        raise Exception("illegal parameter")
    if serverhello.legacy_compression_method != 0:
        raise Exception("illegal parameter")
    server_ext = serverhello.list_extensions()
    supported_versions_present = False
    for s in server_ext:
        # must have supported versions extension
        if s.extension_type != tls.ExtensionType.supported_versions:
            continue
        if s.extension_data != tls.TLS13_PROTOCOL_VERSION.to_bytes(2, "big"):
            raise Exception(
                "Unexpected value in server hello supported versions extension"
            )
        supported_versions_present = True
    if not supported_versions_present:
        raise Exception("illegal parameter")
    # TODO: to check that only extensions that are required for negotiation are present
    return True, clienthello, serverhello


def check_for_alerts(recordlayer: tls.TLSRecordLayer):
    alert = recordlayer.parse_alert()
    if alert == None:
        return
    print(f"Alert: {alert.level.name}: {alert.description.name}")
    # TODO: more alert handling
    raise Exception("alert received")


if __name__ == "__main__":
    main()
