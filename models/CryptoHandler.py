import tls


class CryptoHandler:
    key_share_entry: tls.KeyShareEntry = None
    cipher_suite: int = None
    early_secret: bytes = None

    def __init__(self):
        pass
