import x25519
import secrets

# rfc 7748
class ECDH:
    private: bytes
    public: bytes
    server_public: bytes
    shared_secret: bytes
    key_length: int

    def __init__(self, type: str):
        if type == "x25519":
            self.key_length = 32
            self.private = secrets.token_bytes(self.key_length)
            self.public = x25519.scalar_base_mult(self.private)
        else:
            raise Exception("Unsupported operation, please fix the code")

    def generate_private(self):
        self.private = secrets.token_bytes(self.key_length)

    def generate_shared_secret(self, server_public: bytes) -> bytes:
        self.server_public = bytes(server_public)
        self.shared_secret = bytes(x25519.scalar_mult(self.private, self.server_public))
        # reject a 0 result as per rfc 7748 section 6.1
        if self.shared_secret == bytes(self.key_length):
            raise ValueError("Bad keyshare, ECDH shared key is 0")
        return self.shared_secret

    def sanity_check(self):
        private = bytes.fromhex(
            "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
        )
        public = x25519.scalar_base_mult(private)
        server_public = bytes.fromhex(
            "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"
        )
        print(f"Public: {public.hex()}")
        print(f"Shared secret: {x25519.scalar_mult(private, server_public).hex()}")
