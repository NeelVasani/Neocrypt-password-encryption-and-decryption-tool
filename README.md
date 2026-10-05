# NeoCrypt - Reversible Encryption Suite

An animated, themeable desktop GUI (Python + Tkinter) for encrypting and decrypting
human-readable text with a secret key. Built for Kali Linux, works on any Linux
with Python 3.

> **Note on "hashing":** real hash functions (MD5, SHA-1, SHA-256, ...) are one-way
> and cannot be reversed. NeoCrypt therefore offers reversible **ciphers** instead.

---

## Features

- Encrypt plain text and decrypt it again with the **same secret key**
- **10 reversible methods** to choose from (see table below)
- Secret key is **hidden while typing** (`●`), with an optional REVEAL toggle
- **GENERATE** button creates a strong random key and copies it to the clipboard
  without displaying it
- Key is confirmed (typed twice) when encrypting, to avoid typos
- Live **key-strength meter** (WEAK / FAIR / STRONG / EXCELLENT)
- Wrong key or tampered data is **detected** and reported
- Cipher is **auto-detected** when decrypting
- Animations: matrix code rain, rotating lock, orbiting dots, scan line,
  colour-cycling title, glowing buttons, progress sweep, typewriter status text
- **5 colour themes** plus an AUTO-COLOUR mode that cycles through them

---

## Requirements

- Python 3.8+
- `tkinter` (GUI)
- `cryptography` library

### Install on Kali / Debian

```bash
sudo apt update
sudo apt install python3-tk python3-cryptography
```

or with pip:

```bash
sudo apt install python3-tk
pip install cryptography --break-system-packages
```

---

## Run

```bash
python3 neocrypt.py
```

---

## How to use

### Encrypt
1. Click **ENCRYPT** (default mode).
2. Type or paste your text into **PLAIN TEXT**.
3. Choose a cipher from the **CIPHER** drop-down.
4. Enter a **secret key** (min. 8 characters) and confirm it, or press **GENERATE**.
5. Click **ENCRYPT >>**. The result appears in **ENCRYPTED OUTPUT**
   as `NC1$<method>$<base64>`.
6. Press **COPY** to copy it.

### Decrypt
1. Click **DECRYPT**.
2. Paste the `NC1$...` text into the input box.
3. Enter the **same secret key** used to encrypt.
4. Click **DECRYPT >>**. The original text appears in **DECRYPTED TEXT**.

### Other buttons
| Button | Action |
|---|---|
| REVEAL / HIDE | Show or hide the typed secret key |
| GENERATE | Random 192-bit key, filled in (hidden) and copied to clipboard |
| COPY | Copy the output box to the clipboard |
| USE AS INPUT | Move the output into the input and switch mode |
| CLEAR | Clear input, output and both key fields |
| AUTO-COLOUR | Automatically cycle through all themes |
| Colour dots | Click to choose a theme |

---

## Supported methods

| Method | Type | Notes |
|---|---|---|
| AES-256-GCM | AEAD | Recommended default |
| ChaCha20-Poly1305 | AEAD | Fast on any CPU |
| AES-256-OCB3 | AEAD | Single-pass authenticated mode |
| AES-256-CCM | AEAD | Counter mode + CBC-MAC |
| AES-128-GCM | AEAD | 128-bit, lightweight |
| Fernet (AES-128-CBC + HMAC) | Token | Simple and safe, includes timestamp |
| AES-256-CBC + HMAC-SHA256 | Block + MAC | Classic mode with authentication tag |
| AES-256-CTR + HMAC-SHA256 | Stream + MAC | Counter mode with authentication tag |
| Camellia-256-CBC + HMAC-SHA256 | Block + MAC | Alternative standard cipher |
| SHA-512 XOR stream | Custom | **Educational only** - use a standard cipher for real data |

---

## How it works

1. A random 16-byte **salt** is generated for every encryption.
2. The secret key is stretched with **scrypt** (N=2^15, r=8, p=1) into 64 bytes:
   32 bytes for encryption and 32 bytes for authentication (MAC).
3. The chosen cipher encrypts the UTF-8 text with a fresh random nonce/IV.
4. Output format: `NC1$<method-id>$<urlsafe-base64(salt + payload)>`

Because of the random salt and nonce, encrypting the same text twice gives
different output each time. Decryption needs the exact same secret key; if the
key is wrong or the data was altered, decryption fails with an error instead of
returning garbage.

---

## Security notes

- Your security depends on the **secret key**. Use a long, unique key or the
  GENERATE button, and store it somewhere safe. **There is no recovery** if it
  is lost.
- The generated key is copied to the clipboard. Clear your clipboard after
  saving it.
- Keys shorter than 8 characters are rejected when encrypting.
- The "SHA-512 XOR stream" option is a learning demo, not a vetted cipher.
- This tool is meant for learning and personal use. It has not been audited.

---

## Troubleshooting

| Problem | Fix |
|---|---|
| `No module named 'tkinter'` | `sudo apt install python3-tk` |
| `No module named 'cryptography'` | `sudo apt install python3-cryptography` |
| Code-rain shows empty boxes instead of Japanese characters | Install a CJK font, e.g. `sudo apt install fonts-noto-cjk`, or ignore it (cosmetic only) |
| Window looks cramped | Resize or maximise; minimum size is 1000x740 |
| Animations feel slow | Lower the frame work: change `self.root.after(40, self.tick)` to a larger value, or shrink the window |
| `Wrong secret key, or the encrypted data was modified` | Check the key for typos/case, and make sure the full `NC1$...` text was pasted without edits |

---

## Customising

- **Add a theme:** add an entry to the `THEMES` dictionary in `neocrypt.py`
  (`bg`, `panel`, `field`, `fg`, `dim`, `a1`, `a2` hex colours).
- **Add a cipher:** write an `enc(data, key, mackey)` / `dec(payload, key, mackey)`
  pair and register it in the `METHODS` dictionary with a unique short id.
- **Change key stretching strength:** edit the scrypt parameters in `kdf()`.
  Changing them makes older encrypted text undecryptable.

---

## File overview

```
neocrypt.py   - the whole application (crypto engine + GUI)
README.md     - this file
```
