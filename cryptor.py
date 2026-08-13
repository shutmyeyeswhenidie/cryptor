#!/usr/bin/env python3
import argparse
import base64
import getpass
import hashlib
import os
import sys

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    AES_AVAILABLE = True
except ImportError:
    AES_AVAILABLE = False


MAGIC_HEADER = b"CRX1"


def _derive_keystream(password: str, length: int, salt: bytes) -> bytes:
    stream = bytearray()
    counter = 0
    seed = password.encode("utf-8") + salt
    while len(stream) < length:
        block = hashlib.sha256(seed + counter.to_bytes(4, "big")).digest()
        stream.extend(block)
        counter += 1
    return bytes(stream[:length])


def _substitution_table(password: str, salt: bytes):
    table = list(range(256))
    seed = hashlib.sha256(password.encode("utf-8") + salt + b"SUBST").digest()
    rng_state = int.from_bytes(seed, "big")

    def next_rand(bound):
        nonlocal rng_state
        rng_state = (rng_state * 6364136223846793005 + 1442695040888963407) & ((1 << 256) - 1)
        return rng_state % bound

    for i in range(255, 0, -1):
        j = next_rand(i + 1)
        table[i], table[j] = table[j], table[i]
    return table


def _transposition_order(password: str, salt: bytes, length: int):
    order = list(range(length))
    seed = hashlib.sha256(password.encode("utf-8") + salt + b"TRANS").digest()
    rng_state = int.from_bytes(seed, "big")

    def next_rand(bound):
        nonlocal rng_state
        rng_state = (rng_state * 6364136223846793005 + 1442695040888963407) & ((1 << 256) - 1)
        return rng_state % bound

    for i in range(length - 1, 0, -1):
        j = next_rand(i + 1)
        order[i], order[j] = order[j], order[i]
    return order


def custom_encrypt(plaintext: str, password: str) -> str:
    salt = os.urandom(16)
    data = bytearray(plaintext.encode("utf-8"))

    sub_table = _substitution_table(password, salt)
    for i in range(len(data)):
        data[i] = sub_table[(data[i] + i) % 256]

    keystream = _derive_keystream(password, len(data), salt)
    for i in range(len(data)):
        data[i] ^= keystream[i]

    block_size = 32
    order = _transposition_order(password, salt, block_size)
    shuffled = bytearray(len(data))
    for start in range(0, len(data), block_size):
        chunk = data[start:start + block_size]
        n = len(chunk)
        local_order = [p for p in order if p < n]
        new_chunk = bytearray(n)
        for pos, orig in enumerate(local_order):
            new_chunk[pos] = chunk[orig]
        shuffled[start:start + n] = new_chunk

    payload = MAGIC_HEADER + salt + bytes(shuffled)
    return base64.b85encode(payload).decode("ascii")


def custom_decrypt(ciphertext: str, password: str) -> str:
    try:
        payload = base64.b85decode(ciphertext.encode("ascii"))
    except Exception as e:
        raise ValueError(f"Invalid ciphertext (not valid Base85): {e}")

    if not payload.startswith(MAGIC_HEADER):
        raise ValueError("Invalid header - this text was not encrypted with this script.")

    salt = payload[4:20]
    data = bytearray(payload[20:])

    block_size = 32
    order = _transposition_order(password, salt, block_size)
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

    keystream = _derive_keystream(password, len(data), salt)
    for i in range(len(data)):
        data[i] ^= keystream[i]

    sub_table = _substitution_table(password, salt)
    inverse_table = [0] * 256
    for idx, val in enumerate(sub_table):
        inverse_table[val] = idx
    for i in range(len(data)):
        data[i] = (inverse_table[data[i]] - i) % 256

    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        raise ValueError("Wrong password or corrupted text (decryption failed).")


def aes_encrypt(plaintext: str, password: str) -> str:
    if not AES_AVAILABLE:
        raise RuntimeError("The 'cryptography' package is not installed. Run: pip install cryptography")

    salt = os.urandom(16)
    nonce = os.urandom(12)

    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=390_000)
    key = kdf.derive(password.encode("utf-8"))

    aesgcm = AESGCM(key)
    ct = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)

    payload = b"AESG" + salt + nonce + ct
    return base64.b85encode(payload).decode("ascii")


def aes_decrypt(ciphertext: str, password: str) -> str:
    if not AES_AVAILABLE:
        raise RuntimeError("The 'cryptography' package is not installed. Run: pip install cryptography")

    try:
        payload = base64.b85decode(ciphertext.encode("ascii"))
    except Exception as e:
        raise ValueError(f"Invalid ciphertext: {e}")

    if not payload.startswith(b"AESG"):
        raise ValueError("Invalid header - this does not look like AES ciphertext from this script.")

    salt = payload[4:20]
    nonce = payload[20:32]
    ct = payload[32:]

    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=390_000)
    key = kdf.derive(password.encode("utf-8"))

    aesgcm = AESGCM(key)
    try:
        pt = aesgcm.decrypt(nonce, ct, None)
    except Exception:
        raise ValueError("Wrong password or corrupted/tampered message (authentication failed).")

    return pt.decode("utf-8")


def get_password(confirm: bool = False) -> str:
    pw = getpass.getpass("Password: ")
    if confirm:
        pw2 = getpass.getpass("Confirm password: ")
        if pw != pw2:
            print("Passwords do not match.")
            sys.exit(1)
    if len(pw) < 4:
        print("Warning: this password is very short, encryption will be weak.")
    return pw


def run_interactive():
    print("=" * 50)
    print("   CRYPTOR - text encryption/decryption")
    print("=" * 50)
    print("Available modes:")
    print("  1) Custom (multi-layer, fun)")
    print("  2) AES-256-GCM (standard, very strong)")
    mode = input("Choose mode [1/2]: ").strip()

    action = input("Do you want to (e)ncrypt or (d)ecrypt? [e/d]: ").strip().lower()

    if action.startswith("e"):
        text = input("Enter the message to encrypt:\n> ")
        pw = get_password(confirm=True)
        if mode == "2":
            result = aes_encrypt(text, pw)
        else:
            result = custom_encrypt(text, pw)
        print("\nEncrypted message:\n")
        print(result)
    elif action.startswith("d"):
        text = input("Enter the encrypted message:\n> ").strip()
        pw = get_password(confirm=False)
        try:
            if mode == "2":
                result = aes_decrypt(text, pw)
            else:
                result = custom_decrypt(text, pw)
            print("\nDecrypted message:\n")
            print(result)
        except ValueError as e:
            print(f"\nError: {e}")
    else:
        print("Unknown option.")


def main():
    parser = argparse.ArgumentParser(
        description="CRYPTOR - encrypt/decrypt text (custom cipher or AES-256-GCM)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python cryptor.py -e "hello world" -p myPassword123 --mode aes
  python cryptor.py -d "xJ8f..." -p myPassword123 --mode custom
  python cryptor.py                       (starts the interactive menu)
"""
    )
    parser.add_argument("-e", "--encrypt", metavar="TEXT", help="text to encrypt")
    parser.add_argument("-d", "--decrypt", metavar="TEXT", help="text to decrypt")
    parser.add_argument("-p", "--password", metavar="PASSWORD", help="password (if omitted, prompted securely)")
    parser.add_argument("--mode", choices=["custom", "aes"], default="custom", help="algorithm to use (default: custom)")

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
    except ValueError as e:
        print(f"Error: {e}")
        sys.exit(1)
    except RuntimeError as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()