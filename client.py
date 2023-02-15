import argparse
import re
import secrets
import socket
import tls
import tls_constants
import x25519

pattern = re.compile(
    r'^(([a-zA-Z]{1})|([a-zA-Z]{1}[a-zA-Z]{1})|'
    r'([a-zA-Z]{1}[0-9]{1})|([0-9]{1}[a-zA-Z]{1})|'
    r'([a-zA-Z0-9][-_.a-zA-Z0-9]{0,61}[a-zA-Z0-9]))\.'
    r'([a-zA-Z]{2,13}|[a-zA-Z0-9-]{2,30}.[a-zA-Z]{2,3})$'
)

def hostname(hostname):
    if pattern.match(hostname):
        return hostname
    else:
        raise argparse.ArgumentTypeError(f'{hostname} is an invalid hostname.')

def port(port_num):
    port = int(port_num, 10)
    if port < 1 or port > 65535:
        raise argparse.ArgumentTypeError(
            f'{port_num} is an invalid port number. Valid choices: 1-65535')
    return port


parser = argparse.ArgumentParser(prog='TLS 1.3 Client',
                                 description='A program to connect to services secured with TLS 1.3.\n' +
                                 'For your convenience the Mozilla Root CA is included with this program, however if you do not trust it you may choose to use your own.\n' +
                                 'A trusted Root CA file is required to use this program.\n'
                                 'You can download it at https://wiki.mozilla.org/CA/Included_Certificates',
                                 epilog='ICT2205',
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
parser.add_argument('hostname', help='Target hostname.', type=hostname)
parser.add_argument(
    'port', help='Target port number in base 10. Valid choices: 1-65535', type=port)
parser.add_argument('-ca', metavar='certificate_authorities',
                    help='Trusted Root CA file', required=False)
parser.add_argument('-debug', metavar='debug_filename',
                    help='Save session keys to this file', required=False)


def main():
    args = parser.parse_args()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            # sni, ec, groups, session ticket, etm, extended master secret, sigalgo, versions, psk key exchange modes, key share
            ip = socket.gethostbyname(args.hostname)
            clientrandom = secrets.token_bytes(32)
            legacy_session_id = secrets.token_bytes(32)
            x25519_private = secrets.token_bytes(32)
            sni = tls.ServerName(tls.NameType.host_name, args.hostname)
            snilist = tls.ServerNameList([sni])
            sniext = tls.Extension(tls.ExtensionType.server_name, snilist.to_bytes())
            tls13 = tls.Extension(tls.ExtensionType.supported_versions, tls.SupportedVersions(tls.HandshakeType.client_hello, [tls.TLS13_PROTOCOL_VERSION]).to_bytes())
            signaturealgo = tls.Extension(tls.ExtensionType.signature_algorithms, tls.SignatureSchemeList([tls.SignatureScheme.ed25519, tls.SignatureScheme.ecdsa_secp256r1_sha256]).to_bytes())
            groups = tls.Extension(tls.ExtensionType.supported_groups, tls.NamedGroupList([tls.NamedGroup.x25519]).to_bytes())
            keyshare = tls.Extension(tls.ExtensionType.key_share, tls.KeyShareClientHello([tls.KeyShareEntry(tls.NamedGroup.x25519, x25519_private)]).to_bytes())
            ec_point_format_list = tls.Extension(tls.ExtensionType.ec_point_formats, tls.ECPointFormatList([tls.ECPointFormat.uncompressed]).to_bytes())
            extensions = sniext.to_bytes() + ec_point_format_list.to_bytes() + groups.to_bytes() + signaturealgo.to_bytes() + tls13.to_bytes() + keyshare.to_bytes()
            clienthello = tls.ClientHello(clientrandom, legacy_session_id, extensions)
            handshake = tls.Handshake(tls.HandshakeType.client_hello, len(clienthello.to_bytes()), clienthello)
            tlspt_clienthello = tls.TLSPlaintext(tls.ContentType.handshake, tls.TLS10_PROTOCOL_VERSION, len(handshake.to_bytes()), handshake.to_bytes())
            s.connect((ip, args.port))
            s.sendall(tlspt_clienthello.to_bytes())
            res, data = parse_server_hello(s)
        except socket.gaierror:
            # this means could not resolve the host
            print(f'Could not find host {args.hostname}')
    return

def parse_server_hello(clienthello: tls.ClientHello, s: socket.socket):
    data = s.recv()
    recordlayer = tls.TLSRecordLayer.parse_records(data)
    handshake = recordlayer.parse_handshake()
    if handshake.server_hello == None:
        return
    res = check_server_hello(handshake.server_hello, clienthello)

def check_server_hello(serverhello: tls.ServerHello, clienthello: tls.ClientHello):
    return

if __name__ == '__main__':
    main()
