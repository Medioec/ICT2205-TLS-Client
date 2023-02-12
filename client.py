import argparse
import re
import socket
import tls_constants

pattern = re.compile(
    r'^(([a-zA-Z]{1})|([a-zA-Z]{1}[a-zA-Z]{1})|'
    r'([a-zA-Z]{1}[0-9]{1})|([0-9]{1}[a-zA-Z]{1})|'
    r'([a-zA-Z0-9][-_.a-zA-Z0-9]{0,61}[a-zA-Z0-9]))\.'
    r'([a-zA-Z]{2,13}|[a-zA-Z0-9-]{2,30}.[a-zA-Z]{2,3})$'
)

def port(port_num):
    port = int(port_num, 10)
    if port < 1 or port > 65535:
        raise argparse.ArgumentTypeError(f'{port_num} is an invalid port number. Valid choices: 1-65535')
    return port

parser = argparse.ArgumentParser(prog = 'TLS 1.3 Client',
                    description = 'A program to connect to services secured with TLS 1.3.\n' + 
                    'For your convenience the Mozilla Root CA is included with this program, however if you do not trust it you may choose to use your own.\n' + 
                    'A trusted Root CA file is required to use this program.\n'
                    'You can download it at https://wiki.mozilla.org/CA/Included_Certificates',
                    epilog = 'ICT2205',
                    formatter_class=argparse.RawDescriptionHelpFormatter)
parser.add_argument('hostname', help='Target hostname.')
parser.add_argument('port', help='Target port number in base 10. Valid choices: 1-65535', type=port)
parser.add_argument('-ca', metavar='certificate_authorities', help='Trusted Root CA file', required=False)
parser.add_argument('-debug', metavar='debug_filename', help='Save session keys to this file', required=False)

def main():
    args = parser.parse_args()
    print(args.hostname, args.port, args.debug)
    return

if __name__ == '__main__':
    main()
