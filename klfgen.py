from models.CryptoHandler import *


def generate_klf(crypto: CryptoHandler):
    filename = "client.klf"
    clientrandom = crypto.clientrandom.hex()
    client_hs = crypto.client_handshake_traffic_secret.hex()
    server_hs = crypto.server_handshake_traffic_secret.hex()
    client_app = crypto.client_application_traffic_secret.hex()
    server_app = crypto.server_application_traffic_secret.hex()
    txt = (
        f"CLIENT_HANDSHAKE_TRAFFIC_SECRET {clientrandom} {client_hs}\n"
        f"SERVER_HANDSHAKE_TRAFFIC_SECRET {clientrandom} {server_hs}\n"
        f"CLIENT_TRAFFIC_SECRET_0 {clientrandom} {client_app}\n"
        f"SERVER_TRAFFIC_SECRET_0 {clientrandom} {server_app}\n"
    )
    fd = open(filename, "a")
    fd.write(txt)
    fd.close()
    print("Saved secrets to file", filename, "(For demonstration purposes)")
