# CRYPTOR

CRYPTOR is a Python command-line tool for encrypting and decrypting text.

It supports two encryption modes:

- **AES-256-GCM** — recommended for real data
- **Custom cipher** — a custom multi-layer cipher made for experimentation and learning

## Features

- Encrypt and decrypt text from the terminal
- Interactive menu
- AES-256-GCM encryption
- PBKDF2-HMAC-SHA256 password-based key derivation
- Custom multi-layer encryption
- Base85 encoded encrypted output
- Configurable encrypted code length

## Requirements

Python 3.9+ is recommended.

For AES-256-GCM, install the `cryptography` package:

```bash
pip install cryptography
```

## How the Password Works

The password is the secret key that locks and unlocks the encrypted message.

- Without the correct password, the message cannot be decrypted.
- With the correct password, the original message can be recovered.
- Someone who has the encrypted code but does not know the password should not be able to recover the original message.

Example:

```text
"Hello" + password "1234"
        ↓
    encryption
        ↓
 encrypted code
```

To decrypt it:

```text
encrypted code + password "1234"
        ↓
    decryption
        ↓
      "Hello"
```

Using the wrong password will cause decryption to fail.

## Usage

### Interactive Mode

Run:

```bash
python cryptor.py
```

The program will ask you to:

1. Choose an encryption mode
2. Choose encryption or decryption
3. Choose the desired encrypted code length
4. Enter the text
5. Enter the password

The encrypted code must be longer than the original text.

### AES-256-GCM

Encrypt:

```bash
python cryptor.py -e "Hello World" -l 100 --mode aes
```

Decrypt:

```bash
python cryptor.py -d "YOUR_ENCRYPTED_CODE" -l 100 --mode aes
```

### Custom Mode

Encrypt:

```bash
python cryptor.py -e "Hello World" -l 100 --mode custom
```

Decrypt:

```bash
python cryptor.py -d "YOUR_ENCRYPTED_CODE" -l 100 --mode custom
```

### Password

You can provide a password directly:

```bash
python cryptor.py -e "Hello World" -p "myPassword123" -l 100 --mode aes
```

Or omit `-p` and CRYPTOR will securely ask for the password.

## Encryption Modes

### AES-256-GCM

AES-256-GCM is the recommended mode.

CRYPTOR uses:

- AES-256-GCM
- PBKDF2-HMAC-SHA256
- A random 16-byte salt
- A random 12-byte nonce
- 390,000 PBKDF2 iterations

AES-GCM also provides authentication, meaning modified or corrupted ciphertext can be detected.

### Custom Cipher

The custom mode uses several layers:

1. Byte substitution
2. SHA-256 based XOR keystream
3. Block transposition
4. Base85 encoding

This mode is primarily intended for experimentation and learning about cryptographic concepts.

**Do not use the custom mode to protect sensitive real-world data.**

## Code Length

CRYPTOR allows you to choose how many characters the encrypted code should contain.

For example:

```bash
python cryptor.py -e "Hello" -l 100 --mode aes
```

The resulting encrypted code will contain exactly **100 characters**.

The requested length must be greater than the original text length.

Extra characters are added as padding and do not provide additional cryptographic security.

## Command-Line Options

| Option | Description |
|---|---|
| `-e`, `--encrypt` | Text to encrypt |
| `-d`, `--decrypt` | Text to decrypt |
| `-p`, `--password` | Password to use |
| `-l`, `--length` | Desired encrypted code length |
| `--mode` | `aes` or `custom` |
| `-h`, `--help` | Show help |

## Security Notes

For real data, use **AES-256-GCM** rather than the custom mode.

Avoid using very short passwords.

When possible, do not provide the password directly with `-p`, because command-line arguments may be stored in shell history.

Instead:

```bash
python cryptor.py -e "Secret message" -l 100 --mode aes
```

CRYPTOR will ask for the password securely.

## Project Structure

```text
cryptor/
├── cryptor.py
└── README.md
```

## Example

```text
$ python cryptor.py

==================================================
   CRYPTOR - text encryption/decryption
==================================================
Available modes:
  1) Custom (multi-layer, fun)
  2) AES-256-GCM (standard, very strong)

Choose mode [1/2]: 2
Do you want to (e)ncrypt or (d)ecrypt? [e/d]: e
How many characters should the encrypted code have? 100

Enter the message to encrypt:
> Hello World

Password:
Confirm password:

Encrypted message:

YOUR_ENCRYPTED_CODE
```

## License

This project is provided for educational and experimental purposes.
