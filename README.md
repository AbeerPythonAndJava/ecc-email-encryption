# 🔐 ECC Mail — End-to-End Email Encryption with Elliptic Curves

![tests](https://github.com/<your-username>/ecc-email-encryption/actions/workflows/tests.yml/badge.svg)
![python](https://img.shields.io/badge/python-3.10%2B-blue)
![license](https://img.shields.io/badge/license-MIT-green)

Encrypt email messages so that **only the intended recipient** can read them — not the
mail provider, not anyone in between. Built on **ECIES** (X25519 + HKDF-SHA256 + AES-256-GCM)
using the audited [`cryptography`](https://cryptography.io) library.

This project is a modern Python rewrite of an earlier Java/Swing academic project that
implemented EC-ElGamal from scratch. The original algorithm is preserved in
[`toy_ecc.py`](src/ecc_mail/toy_ecc.py) as a **teaching module**.

---

## ✨ Features

- 🔑 X25519 key pairs, private key protected by a passphrase (PKCS#8)
- 🛡️ Authenticated encryption — tampering and wrong keys are detected
- 🎲 Fresh ephemeral key + random nonce per message (forward secrecy for the sender side)
- 📧 Send over SMTP/STARTTLS, read over IMAP/SSL (certificates verified)
- 📦 ASCII-armored output that survives copy/paste and any mail client
- 🎓 Educational EC-ElGamal on the original curve `y² = x³ + 7x + 9 (mod 491)`
- ✅ Unit tests + GitHub Actions CI

## 📁 Project Structure

```
ecc-email-encryption/
├── src/ecc_mail/
│   ├── __init__.py       # public API
│   ├── __main__.py       # python -m ecc_mail
│   ├── cli.py            # command-line interface
│   ├── config.py         # settings from environment variables
│   ├── crypto.py         # ECIES encryption (production)
│   ├── exceptions.py     # error hierarchy
│   ├── keys.py           # key generation & PEM storage
│   ├── mail_client.py    # SMTP send / IMAP read
│   └── toy_ecc.py        # educational EC math (original algorithm)
├── tests/                # unit tests
├── .env.example
├── pyproject.toml
└── requirements.txt
```

## 🚀 Installation

```bash
git clone https://github.com/<your-username>/ecc-email-encryption.git
cd ecc-email-encryption
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -e ".[dotenv,dev]"
```

## 🧪 Quick Start (no email account needed)

```bash
# 1. Create your key pair (stored in ~/.ecc_mail)
ecc-mail keygen

# 2. Encrypt a message for a recipient's public key
echo "Meet at 5pm" | ecc-mail encrypt -r ~/.ecc_mail/public_key.pem > msg.txt

# 3. Decrypt it with your private key
ecc-mail decrypt -i msg.txt
```

Encrypted output looks like:

```
-----BEGIN ECC-MAIL MESSAGE-----
AdJv3bY0p7Q2c1Kx0V9mLZ...
-----END ECC-MAIL MESSAGE-----
```

## 📧 Sending & Reading Email

1. Copy `.env.example` → `.env` and fill it in.
   For Gmail, enable 2-Step Verification and create an **App Password** — your normal
   password will not work and must never be stored in code.
2. Enable IMAP in your mail settings.

```bash
# Send an encrypted email
ecc-mail send --to friend@example.com -r friend_public_key.pem -i message.txt

# List the latest emails and decrypt any ECC-MAIL blocks
ecc-mail inbox -n 5 --decrypt
```

### Use as a library

```python
from ecc_mail import generate_keypair, encrypt_message, decrypt_message

priv, pub = generate_keypair()
armored = encrypt_message("Hello 👋", pub)
assert decrypt_message(armored, priv) == "Hello 👋"
```

## 📐 ECC Concepts in 60 Seconds

An **elliptic curve** over a prime field is the set of points satisfying
`y² = x³ + ax + b (mod p)`. Points can be *added* (chord-and-tangent rule), and adding a
point `G` to itself `k` times gives `k·G` (**scalar multiplication**).

- Computing `Q = d·G` is fast (double-and-add).
- Recovering `d` from `Q` and `G` is the **Elliptic Curve Discrete Log Problem** — infeasible
  on a 256-bit curve. That asymmetry is the whole security basis.

**ECIES flow used here**

| Step | Sender | Recipient |
|------|--------|-----------|
| 1 | picks random `k`, computes `R = k·G` | owns `d`, published `Q = d·G` |
| 2 | shared secret `S = k·Q` | computes `S = d·R` (same point!) |
| 3 | `key = HKDF(S)` | `key = HKDF(S)` |
| 4 | `C = AES-GCM(key, message)` and sends `(R, nonce, C)` | decrypts and verifies `C` |

Because `k·Q = k·d·G = d·k·G = d·R`, both sides reach the same secret without ever sending it.

### Why X25519 instead of the original curve?

| | Original Java | This project |
|---|---|---|
| Field size | 491 (~9 bits) | 2²⁵⁵−19 (~255 bits) |
| Brute-force private key | microseconds | infeasible |
| Randomness | fixed `k = 3` | fresh CSPRNG key per message |
| Integrity | none | AES-GCM authentication tag |
| Side channels | naive loops | constant-time library code |

## 🎓 Educational Module

```bash
python -m ecc_mail.toy_ecc
```

Runs character-by-character EC-ElGamal with Koblitz encoding on the original curve
(`a=7, b=9, p=491, G=(120, 23)`). Great for classrooms — **never use it for real data.**

## 🧪 Running Tests

```bash
pytest -v
```

## 🔒 Security Notes

- Keep `private_key.pem` secret and use a strong passphrase.
- Verify a recipient's public key through a trusted channel (fingerprint check) before use.
- Only the message **body** is encrypted; subject, sender and recipient remain visible.
- This project has not been independently audited. For high-stakes use, prefer
  established standards such as OpenPGP or S/MIME.

## 📄 License

MIT — see [LICENSE](LICENSE).
