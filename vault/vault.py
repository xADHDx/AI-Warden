import json
import os
import secrets
import threading
from cryptography.fernet import Fernet
from vault.prime import generate_prime, verify_token, checksum

VAULT_PATH = "/opt/aiwarden/vault/.vault.enc"  # Path to the encrypted vault file
KEY_PATH = "/opt/aiwarden/vault/.vault.key"    # Path to the encryption key file

class TokenVault:
    # Main class for managing the token vault

    def __init__(self):
        self._lock = threading.Lock()  # mutex lock prevents concurrent write race conditions
        self._vault = {}               # real value → token mapping
        self._reverse = {}             # token → real value mapping for detokenization
        self._hashes = {}              # token → BLAKE3 hash mapping for Layer 4 verification
        self._prime = None             # session prime, generated fresh each session
        self._fernet = None            # Fernet encryption instance for vault file
        self._load_or_create_key()

    def _load_or_create_key(self):
        # Load the encryption key from file or create a new one if it doesn't exist
        if os.path.exists(KEY_PATH):
            with open(KEY_PATH, "rb") as f:
                self._fernet = Fernet(f.read())
        else:
            key = Fernet.generate_key()
            with open(KEY_PATH, "wb") as f:
                f.write(key)
            os.chmod(KEY_PATH, 0o600)
            self._fernet = Fernet(key)

    def new_session(self):
        # Start a new session by clearing the vault and generating a new prime
        with self._lock:
            self._vault = {}
            self._reverse = {}
            self._hashes = {}
            self._prime = generate_prime()
            self._save()

    def tokenize(self, real_value):
        # Replace a real value with a valid session token
        with self._lock:
            if real_value in self._vault:
                return self._vault[real_value]  # return existing token if already mapped
            token = self._generate_valid_token()
            token_hash = checksum(token, self._prime)  # generate BLAKE3 hash for Layer 4
            self._vault[real_value] = token
            self._reverse[token] = real_value          # reverse map for detokenization
            self._hashes[token] = token_hash           # store hash for verification
            self._save()
            return token

    def detokenize(self, token):
        # Look up the real value from a token
        with self._lock:
            return self._reverse.get(token)

    def verify(self, token):
        # Layer 4 proof — verify token against its stored BLAKE3 hash
        stored_hash = self._hashes.get(token)
        if stored_hash is None:
            return False  # token not in vault — automatic fail
        return verify_token(token, self._prime, stored_hash)

    def get_prime(self):
        # Return the current session prime
        return self._prime

    def _generate_valid_token(self):
        # Generate a random 8-digit token and compute its BLAKE3 hash
        # Token validity is now defined by having a stored hash, not arithmetic
        while True:
            candidate = secrets.randbelow(90000000) + 10000000
            if candidate not in self._reverse:  # ensure uniqueness
                return candidate

    def _save(self):
        # Encrypt and persist vault to disk — called after every write operation
        data = json.dumps({
            "vault": self._vault,
            "reverse": {str(k): v for k, v in self._reverse.items()},
            "hashes": self._hashes,
            "prime": self._prime
        }).encode()
        encrypted = self._fernet.encrypt(data)
        with open(VAULT_PATH, "wb") as f:
            f.write(encrypted)
        os.chmod(VAULT_PATH, 0o600)