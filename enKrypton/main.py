
import getpass
import hashlib
import hmac
import json
import math
import secrets
import string
import struct

from pathlib import Path


# =========================================================
# KRYPTION: key derivation and educational encryption
# =========================================================

class Kryption:
    SALT_SIZE = 16
    NONCE_SIZE = 16
    MAC_SIZE = 32
    KEY_SIZE = 64

    def __init__(self, master_password):
        if not isinstance(master_password, str) or not master_password:
            raise ValueError("Master password cannot be empty")

        self.master_password = master_password.encode("utf-8")

    @staticmethod
    def generate_random_password(length=32):
        if not isinstance(length, int) or isinstance(length, bool):
            raise TypeError("Length must be an integer")

        if length < 1:
            raise ValueError("Length must be positive")

        alphabet = string.ascii_letters + string.digits + string.punctuation

        return "".join(
            secrets.choice(alphabet) for _ in range(length)
        )

    def derive_keys(self, salt):
        if len(salt) != self.SALT_SIZE:
            raise ValueError("Invalid salt size")

        # Derive separate keys for encryption and authentication.
        master_key = hashlib.scrypt(
            self.master_password,
            salt=salt,
            n=2**17,
            r=8,
            p=1,
            dklen=self.KEY_SIZE,
            maxmem=130 * 1024 * 1024
        )

        encryption_key = hmac.digest(
            master_key, b"krypt-encryption-v1", "sha256"
        )

        authentication_key = hmac.digest(
            master_key, b"krypt-authentication-v1", "sha256"
        )

        return encryption_key, authentication_key

    @staticmethod
    def _keystream(key, nonce, length):
        # Educational construction only: this is NOT a
        # standard, independently reviewed encryption scheme.
        output = bytearray()
        counter = 0

        while len(output) < length:
            block = hmac.digest(
                key,
                nonce + counter.to_bytes(8, "big"),
                "sha256"
            )

            output.extend(block)
            counter += 1

        return bytes(output[:length])

    def encrypt_data(self, plaintext, salt):
        encryption_key, authentication_key = self.derive_keys(salt)
        nonce = secrets.token_bytes(self.NONCE_SIZE)

        stream = self._keystream(
            encryption_key, nonce, len(plaintext)
        )

        ciphertext = bytes(
            a ^ b for a, b in zip(plaintext, stream)
        )

        return nonce, ciphertext, authentication_key

    def decrypt_data(self, nonce, ciphertext, salt):
        encryption_key, authentication_key = self.derive_keys(salt)

        stream = self._keystream(
            encryption_key, nonce, len(ciphertext)
        )

        plaintext = bytes(
            a ^ b for a, b in zip(ciphertext, stream)
        )

        return plaintext, authentication_key


# =========================================================
# KRYPT: binary file format and vault management
# =========================================================

class Krypt:
    TAG = b"Krypt"
    VERSION = 1

    HEADER_FORMAT = ">5sBI"
    HEADER_SIZE = struct.calcsize(HEADER_FORMAT)

    SALT_SIZE = 16
    NONCE_SIZE = 16
    MAC_SIZE = 32

    MAX_PAYLOAD_SIZE = 10_000_000

    def __init__(self, filename):
        self.path = Path(filename)

        if self.path.suffix != ".krypt":
            raise ValueError("Krypt files must end in .krypt")

    @staticmethod
    def create_vault(username, password, balance, metadata=None):
        if not isinstance(username, str) or not username:
            raise ValueError("Username must be a non-empty string")

        if not isinstance(password, str):
            raise TypeError("Password must be a string")

        if (
            not isinstance(balance, (int, float))
            or isinstance(balance, bool)
            or not math.isfinite(balance)
        ):
            raise ValueError("Balance must be a finite number")

        if metadata is None:
            metadata = {}

        if not isinstance(metadata, dict):
            raise TypeError("Metadata must be a dictionary")

        return {
            "password": password,
            "balance": balance,
            "metadata": metadata
        }

    def save_krypt(self, vaults, master_password):
        if not isinstance(vaults, dict):
            raise TypeError("Vault collection must be a dictionary")

        payload = json.dumps(
            {"vaults": vaults},
            separators=(",", ":"),
            allow_nan=False
        ).encode("utf-8")

        if len(payload) > self.MAX_PAYLOAD_SIZE:
            raise ValueError("Vault data is too large")

        salt = secrets.token_bytes(self.SALT_SIZE)
        kryption = Kryption(master_password)

        nonce, ciphertext, auth_key = kryption.encrypt_data(
            payload, salt
        )

        header = struct.pack(
            self.HEADER_FORMAT,
            self.TAG,
            self.VERSION,
            len(ciphertext)
        )

        # Authenticate the header and all encrypted-file fields.
        authenticated_data = header + salt + nonce + ciphertext

        mac = hmac.digest(
            auth_key, authenticated_data, "sha256"
        )

        file_data = authenticated_data + mac

        # Write to a temporary sibling file, then replace the
        # destination after the complete file has been written.
        temp_path = self.path.with_name(self.path.name + ".tmp")

        try:
            with temp_path.open("xb") as file:
                file.write(file_data)
                file.flush()

            temp_path.replace(self.path)

        finally:
            if temp_path.exists():
                temp_path.unlink()

        print(f"Vault saved to {self.path}")

    def load(self, master_password):
        if not self.path.is_file():
            raise FileNotFoundError(f"File not found: {self.path}")

        expected_minimum = (
            self.HEADER_SIZE
            + self.SALT_SIZE
            + self.NONCE_SIZE
            + self.MAC_SIZE
        )

        # Reject oversized files before loading them into memory.
        if self.path.stat().st_size > (
            expected_minimum + self.MAX_PAYLOAD_SIZE
        ):
            raise ValueError("Krypt file is too large")

        file_data = self.path.read_bytes()

        if len(file_data) < expected_minimum:
            raise ValueError("Krypt file is truncated")

        header = file_data[:self.HEADER_SIZE]

        tag, version, payload_length = struct.unpack(
            self.HEADER_FORMAT, header
        )

        if tag != self.TAG:
            raise ValueError("Invalid Krypt signature")

        if version != self.VERSION:
            raise ValueError("Unsupported Krypt version")

        if not 1 <= payload_length <= self.MAX_PAYLOAD_SIZE:
            raise ValueError("Invalid payload length")

        expected_size = (
            self.HEADER_SIZE
            + self.SALT_SIZE
            + self.NONCE_SIZE
            + payload_length
            + self.MAC_SIZE
        )

        if len(file_data) != expected_size:
            raise ValueError("File is truncated or contains extra data")

        offset = self.HEADER_SIZE

        salt = file_data[offset:offset + self.SALT_SIZE]
        offset += self.SALT_SIZE

        nonce = file_data[offset:offset + self.NONCE_SIZE]
        offset += self.NONCE_SIZE

        ciphertext = file_data[offset:offset + payload_length]
        offset += payload_length

        stored_mac = file_data[offset:offset + self.MAC_SIZE]

        kryption = Kryption(master_password)

        # Derive keys and authenticate before accepting plaintext.
        encryption_key, auth_key = kryption.derive_keys(salt)

        authenticated_data = file_data[:offset]

        calculated_mac = hmac.digest(
            auth_key, authenticated_data, "sha256"
        )

        if not hmac.compare_digest(stored_mac, calculated_mac):
            raise ValueError(
                "Authentication failed: wrong password or modified file"
            )

        # Authentication succeeded; now decrypt.
        stream = kryption._keystream(
            encryption_key, nonce, len(ciphertext)
        )

        plaintext = bytes(
            a ^ b for a, b in zip(ciphertext, stream)
        )

        try:
            data = json.loads(plaintext.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ValueError("Invalid decrypted vault data") from error

        if not isinstance(data, dict):
            raise ValueError("Invalid vault collection")

        vaults = data.get("vaults")

        if not isinstance(vaults, dict):
            raise ValueError("Invalid vault collection")

        for username, vault in vaults.items():
            if not isinstance(username, str) or not isinstance(vault, dict):
                raise ValueError("Invalid vault entry")

            if not isinstance(vault.get("password"), str):
                raise ValueError("Invalid vault password field")

            if not isinstance(vault.get("metadata"), dict):
                raise ValueError("Invalid vault metadata")

            balance = vault.get("balance")

            if (
                not isinstance(balance, (int, float))
                or isinstance(balance, bool)
                or not math.isfinite(balance)
            ):
                raise ValueError("Invalid vault balance")

        return vaults


# =========================================================
# MAIN PROGRAM
# =========================================================

def makePw():
    # Always use the file beside this Python script, regardless of
    # the terminal/VS Code working directory.
    filename = Path(__file__).resolve().parent / "test.krypt"
    krypt = Krypt(filename)
    print("Using vault file:", krypt.path)
    master_password = getpass.getpass("Master password: ")

    # Preserve the vaults already in the file.
    if krypt.path.exists():
        # If the master password is wrong, load() raises an error.
        # That stops us from replacing the existing file.
        vaults = krypt.load(master_password)
    else:
        vaults = {}

    username = input("Username for the new vault: ").strip()
    if not username:
        raise ValueError("Username cannot be empty")

    # Avoid silently replacing a vault with the same username.
    if username in vaults:
        confirm = input(
            f"Vault {username!r} already exists. Replace it? (y/N): "
        ).strip().lower()
        if confirm != "y":
            print("Cancelled; existing vaults were not changed.")
            return

    password = Kryption.generate_random_password()

    vaults[username] = Krypt.create_vault(
        username,
        password,
        100,
        {"type": "account", "version": 1}
    )

    krypt.save_krypt(vaults, master_password)

    print("Generated account password:", password)


def getPw():
    # Use the same absolute path as makePw().
    filename = Path(__file__).resolve().parent / "test.krypt"
    master_password = getpass.getpass("Master password: ")

    krypt = Krypt(filename)
    vaults = krypt.load(master_password)

    print("\nAvailable usernames:")
    for username in vaults:
        print("-", username)

    username = input("Which vault do you want to read? ").strip()

    if username not in vaults:
        print("Username not found")
        return

    vault = vaults[username]

    print("Password:", vault["password"])
    print("Balance:", vault["balance"])
    print("Metadata:", vault["metadata"])


if __name__ == "__main__":
    print("1. Create/save vault")
    print("2. Load vault")

    choice = input("Choice: ").strip()

    try:
        if choice == "1":
            makePw()
        elif choice == "2":
            getPw()
        else:
            print("Invalid choice")
    except (ValueError, OSError, MemoryError) as error:
        print(f"Error: {error}")
