#!/usr/bin/env python3
import argparse
import base64
import getpass
import hashlib
import hmac
import os
import sys

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    AES_AVAILABLE = True
except ImportError:
    AES_AVAILABLE = False


MAGIC_HEADER = b"CRX2"
AES_HEADER = b"AES2"

# Scrypt parameters (Memory-hard key derivation)
SCRYPT_N = 32768  # CPU/Memory cost (2^15)
SCRYPT_R = 8      # Block size
SCRYPT_P = 1      # Parallelization factor


def _derive_keys(password: str, salt: bytes, key_len: int = 64) -> bytes:
    """Uses scrypt KDF to derive cryptographically strong master keys resistant to GPU cracking."""
    return hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
        dklen=key_len
    )


def _generate_csprng_bytes(key: bytes, length: int) -> bytes:
    """Derives deterministic keystream/CSPRNG bytes using HMAC-SHA256 in counter mode."""
    stream = bytearray()
    counter = 0
    while len(stream) < length:
        block = hmac.new(key, counter.to_bytes(4, "big"), hashlib.sha256).digest()
        stream.extend(block)
        counter += 1
    return bytes(stream[:length])


def _substitution_table(sub_key: bytes) -> list[int]:
    """Generates a Fisher-Yates shuffled substitution table using HMAC CSPRNG."""
    table = list(range(256))
    random_bytes = _generate_csprng_bytes(sub_key, 256 * 4)
    
    for i in range(255, 0, -1):
        idx = (255 - i) * 4
        rand_val = int.from_bytes(random_bytes[idx:idx + 4], "big")
        j = rand_val % (i + 1)
        table[i], table[j] = table[j], table[i]
    return table


def _transposition_order(trans_key: bytes, length: int) -> list[int]:
    """Generates a CSPRNG-driven block permutation order."""
    order = list(range(length))
    random_bytes = _generate_csprng_bytes(trans_key, length * 4)
    
    for i in range(length - 1, 0, -1):
        idx = (length - 1 - i) * 4
        rand_val = int.from_bytes(random_bytes[idx:idx + 4], "big")
        j = rand_val % (i + 1)
        order[i], order[j] = order[j], order[i]
    return order


def custom_encrypt(plaintext: str, password: str) -> str:
    salt = os.urandom(16)
    # Derive 96 bytes: 32 enc_key, 32 mac_key, 16 sub_key, 16 trans_key
    derived = _derive_keys(password, salt, key_len=96)
    enc_key = derived[:32]
    mac_key = derived[32:64]
    sub_key = derived[64:80]
    trans_key = derived[80:96]

    data = bytearray(plaintext.encode("utf-8"))

    # Layer 1: Cryptographic Substitution
    sub_table = _substitution_table(sub_key)
    for i in range(len(data)):
        data[i] = sub_table[(data[i] + i) % 256]

    # Layer 2: HMAC-SHA256 Keystream XOR
    keystream = _generate_csprng_bytes(enc_key, len(data))
    for i in range(len(data)):
        data[i] ^= keystream[i]

    # Layer 3: CSPRNG Transposition
    block_size = 32
    order = _transposition_order(trans_key, block_size)
    shuffled = bytearray(len(data))
    for start in range(0, len(data), block_size):
        chunk = data[start:start + block_size]
        n = len(chunk)
        local_order = [p for p in order if p < n]
        new_chunk = bytearray(n)
        for pos, orig in enumerate(local_order):
            new_chunk[pos] = chunk[orig]
        shuffled[start:start + n] = new_chunk

    raw_payload = MAGIC_HEADER + salt + bytes(shuffled)
    
    # Layer 4: Encrypt-then-MAC Authentication Tag (32 bytes)
    mac = hmac.new(mac_key, raw_payload, hashlib.sha256).digest()
    final_payload = raw_payload + mac

    return base64.b85encode(final_payload).decode("ascii")


def custom_decrypt(ciphertext: str, password: str) -> str:
    try:
        payload = base64.b85decode(ciphertext.encode("ascii"))
    except Exception as e:
        raise ValueError(f"Invalid ciphertext (not valid Base85): {e}")

    if len(payload) < 4 + 16 + 32:  # Header + Salt + MAC
        raise ValueError("Ciphertext is too short or corrupted.")

    if not payload.startswith(MAGIC_HEADER):
        raise ValueError("Invalid header - unsupported format or wrong script.")

    # Extract MAC and verify integrity before processing
    mac_received = payload[-32:]
    raw_payload = payload[:-32]
    salt = raw_payload[4:20]
    data = bytearray(raw_payload[20:])

    derived = _derive_keys(password, salt, key_len=96)
    enc_key = derived[:32]
    mac_key = derived[32:64]
    sub_key = derived[64:80]
    trans_key = derived[80:96]

    # Constant-time MAC comparison prevents timing attacks
    expected_mac = hmac.new(mac_key, raw_payload, hashlib.sha256).digest()
    if not hmac.compare_digest(mac_received, expected_mac):
        raise ValueError("Wrong password or tampered message (Authentication failed).")

    # Undo Layer 3: CSPRNG Transposition
    block_size = 32
    order = _transposition_order(trans_key, block_size)
    unshuffled = bytearray(len(data))
    for start in range(0, len(data), block_size):
        chunk = data[start:start + block_size]
        n = len(chunk)
        local_order = [p for p in order if p < n]
        new_chunk = bytearray(n)
        for pos, orig in enumerate(local_order):
            new_chunk[orig] = chunk[pos]
        unshuffled[start:start + n] = new_chunk
    data = unshuffled

    # Undo Layer 2: HMAC-SHA256 Keystream XOR
    keystream = _generate_csprng_bytes(enc_key, len(data))
    for i in range(len(data)):
        data[i] ^= keystream[i]

    # Undo Layer 1: Substitution
    sub_table = _substitution_table(sub_key)
    inverse_table = [0] * 256
    for idx, val in enumerate(sub_table):
        inverse_table[val] = idx
    for i in range(len(data)):
        data[i] = (inverse_table[data[i]] - i) % 256

    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        raise ValueError("Decryption produced invalid characters.")


def aes_encrypt(plaintext: str, password: str) -> str:
    if not AES_AVAILABLE:
        raise RuntimeError("The 'cryptography' package is required for AES mode. Run: pip install cryptography")

    salt = os.urandom(16)
    nonce = os.urandom(12)
    key = _derive_keys(password, salt, key_len=32)

    aesgcm = AESGCM(key)
    ct = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)

    payload = AES_HEADER + salt + nonce + ct
    return base64.b85encode(payload).decode("ascii")


def aes_decrypt(ciphertext: str, password: str) -> str:
    if not AES_AVAILABLE:
        raise RuntimeError("The 'cryptography' package is required for AES mode. Run: pip install cryptography")

    try:
        payload = base64.b85decode(ciphertext.encode("ascii"))
    except Exception as e:
        raise ValueError(f"Invalid ciphertext: {e}")

    if not payload.startswith(AES_HEADER):
        raise ValueError("Invalid header - message was not encrypted with AES mode.")

    salt = payload[4:20]
    nonce = payload[20:32]
    ct = payload[32:]

    key = _derive_keys(password, salt, key_len=32)

    aesgcm = AESGCM(key)
    try:
        pt = aesgcm.decrypt(nonce, ct, None)
    except Exception:
        raise ValueError("Wrong password or tampered message (Authentication failed).")

    return pt.decode("utf-8")


def get_password(confirm: bool = False) -> str:
    pw = getpass.getpass("Password: ")
    if confirm:
        pw2 = getpass.getpass("Confirm password: ")
        if pw != pw2:
            print("Passwords do not match.")
            sys.exit(1)
    if len(pw) < 6:
        print("Warning: Short password provided. Consider using 8+ characters.")
    return pw


def run_interactive():
    print("=" * 50)
    print("    CRYPTOR V2 - Hardened Text Encryption")
    print("=" * 50)
    print("Available modes:")
    print("  1) Custom Cryptographic Pipeline (Hardened)")
    print("  2) AES-256-GCM (Standard AEAD)")
    mode = input("Choose mode [1/2]: ").strip()

    action = input("Do you want to (e)ncrypt or (d)ecrypt? [e/d]: ").strip().lower()

    if action.startswith("e"):
        text = input("Enter the message to encrypt:\n> ")
        pw = get_password(confirm=True)
        result = aes_encrypt(text, pw) if mode == "2" else custom_encrypt(text, pw)
        print("\nEncrypted message:\n")
        print(result)
    elif action.startswith("d"):
        text = input("Enter the encrypted message:\n> ").strip()
        pw = get_password(confirm=False)
        try:
            result = aes_decrypt(text, pw) if mode == "2" else custom_decrypt(text, pw)
            print("\nDecrypted message:\n")
            print(result)
        except ValueError as e:
            print(f"\nError: {e}")


def main():
    parser = argparse.ArgumentParser(description="CRYPTOR V2 - Hardened encryption tool")
    parser.add_argument("-e", "--encrypt", metavar="TEXT", help="text to encrypt")
    parser.add_argument("-d", "--decrypt", metavar="TEXT", help="text to decrypt")
    parser.add_argument("-p", "--password", metavar="PASSWORD", help="password")
    parser.add_argument("--mode", choices=["custom", "aes"], default="custom", help="algorithm mode")

    args = parser.parse_args()

    if not args.encrypt and not args.decrypt:
        run_interactive()
        return

    password = args.password or get_password(confirm=bool(args.encrypt))

    try:
        if args.encrypt:
            fn = aes_encrypt if args.mode == "aes" else custom_encrypt
            print(fn(args.encrypt, password))
        elif args.decrypt:
            fn = aes_decrypt if args.mode == "aes" else custom_decrypt
            print(fn(args.decrypt, password))
    except (ValueError, RuntimeError) as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
