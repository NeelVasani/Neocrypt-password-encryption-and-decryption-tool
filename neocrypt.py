#!/usr/bin/env python3
"""
NeoCrypt - animated reversible encryption / decryption suite (Tkinter GUI)

Setup on Kali Linux:
    sudo apt install python3-tk python3-cryptography
    (or)  pip install cryptography --break-system-packages
Run:
    python3 neocrypt.py

How it works
  * You type human-readable text and pick a reversible cipher.
  * You enter a secret key (hidden while typing) - or press GENERATE.
  * The key is stretched with scrypt (random salt) into encryption + MAC keys.
  * Output looks like  NC1$<method-id>$<base64>  and can only be decrypted
    with the SAME secret key. A wrong key or edited data is detected.

NOTE: real hashes (MD5, SHA-1, SHA-256, ...) are one-way and CANNOT be
reversed, so they are not in the list. Only reversible ciphers are.
"""
import base64
import hashlib
import hmac
import math
import os
import random
import secrets
import threading

try:
    import tkinter as tk
    from tkinter import ttk, font as tkfont
    from cryptography.exceptions import InvalidTag
    from cryptography.fernet import Fernet, InvalidToken
    from cryptography.hazmat.primitives import padding
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.ciphers.aead import (
        AESCCM, AESGCM, AESOCB3, ChaCha20Poly1305)
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
except ImportError as exc:  # pragma: no cover
    raise SystemExit(
        f"Missing dependency: {exc}\n"
        "Install with:\n  sudo apt install python3-tk python3-cryptography\n"
        "or:\n  pip install cryptography --break-system-packages")

# ----------------------------------------------------------------------------
#  CRYPTO ENGINE
# ----------------------------------------------------------------------------
PREFIX = "NC1"
WRONG = "Wrong secret key, or the encrypted data was modified."
BAD = "This is not valid NeoCrypt data (corrupted or incomplete)."


class CryptoError(Exception):
    pass


def kdf(secret: str, salt: bytes) -> bytes:
    """scrypt -> 64 bytes (32 enc key + 32 MAC key)."""
    return Scrypt(salt=salt, length=64, n=2 ** 15, r=8, p=1).derive(secret.encode())


def _mac(key, body):
    return hmac.new(key, body, hashlib.sha256).digest()


def _seal(body, mkey):
    return body + _mac(mkey, body)


def _open(payload, mkey):
    if len(payload) < 33:
        raise CryptoError(BAD)
    body, tag = payload[:-32], payload[-32:]
    if not hmac.compare_digest(tag, _mac(mkey, body)):
        raise CryptoError(WRONG)
    return body


def _aead(cls, key_len=32, nonce_len=12):
    def enc(data, k, m):
        nonce = os.urandom(nonce_len)
        return nonce + cls(k[:key_len]).encrypt(nonce, data, None)

    def dec(p, k, m):
        if len(p) <= nonce_len:
            raise CryptoError(BAD)
        try:
            return cls(k[:key_len]).decrypt(p[:nonce_len], p[nonce_len:], None)
        except InvalidTag:
            raise CryptoError(WRONG)
    return enc, dec


def _block(algo, mode, padded):
    def enc(data, k, m):
        iv = os.urandom(16)
        if padded:
            pd = padding.PKCS7(128).padder()
            data = pd.update(data) + pd.finalize()
        e = Cipher(algo(k), mode(iv)).encryptor()
        return _seal(iv + e.update(data) + e.finalize(), m)

    def dec(p, k, m):
        body = _open(p, m)
        if len(body) < 16:
            raise CryptoError(BAD)
        d = Cipher(algo(k), mode(body[:16])).decryptor()
        out = d.update(body[16:]) + d.finalize()
        if padded:
            u = padding.PKCS7(128).unpadder()
            out = u.update(out) + u.finalize()
        return out
    return enc, dec


def _keystream(key, nonce, n):
    out, c = b"", 0
    while len(out) < n:
        out += hashlib.sha512(key + nonce + c.to_bytes(8, "big")).digest()
        c += 1
    return out[:n]


def _xor_enc(data, k, m):
    nonce = os.urandom(16)
    ks = _keystream(k, nonce, len(data))
    return _seal(nonce + bytes(a ^ b for a, b in zip(data, ks)), m)


def _xor_dec(p, k, m):
    body = _open(p, m)
    nonce, ct = body[:16], body[16:]
    ks = _keystream(k, nonce, len(ct))
    return bytes(a ^ b for a, b in zip(ct, ks))


def _fernet_enc(data, k, m):
    return Fernet(base64.urlsafe_b64encode(k)).encrypt(data)


def _fernet_dec(p, k, m):
    try:
        return Fernet(base64.urlsafe_b64encode(k)).decrypt(p)
    except InvalidToken:
        raise CryptoError(WRONG)


def _m(mid, pair, info):
    return {"id": mid, "enc": pair[0], "dec": pair[1], "info": info}


METHODS = {
    "AES-256-GCM": _m("g256", _aead(AESGCM), "AEAD | 256-bit | recommended"),
    "ChaCha20-Poly1305": _m("cc20", _aead(ChaCha20Poly1305), "AEAD | 256-bit | fast on any CPU"),
    "AES-256-OCB3": _m("ocb3", _aead(AESOCB3), "AEAD | 256-bit | single-pass"),
    "AES-256-CCM": _m("ccm", _aead(AESCCM), "AEAD | 256-bit | counter + CBC-MAC"),
    "AES-128-GCM": _m("g128", _aead(AESGCM, key_len=16), "AEAD | 128-bit | lightweight"),
    "Fernet (AES-128-CBC+HMAC)": _m("fern", (_fernet_enc, _fernet_dec), "Simple, safe, timestamped token"),
    "AES-256-CBC + HMAC": _m("cbc", _block(algorithms.AES, modes.CBC, True), "Classic block mode + auth tag"),
    "AES-256-CTR + HMAC": _m("ctr", _block(algorithms.AES, modes.CTR, False), "Stream mode + auth tag"),
    "Camellia-256-CBC + HMAC": _m("cam", _block(algorithms.Camellia, modes.CBC, True), "Japanese/EU standard cipher"),
    "SHA-512 XOR stream (educational)": _m("xor", (_xor_enc, _xor_dec), "Custom demo cipher - learning only"),
}
BY_ID = {v["id"]: k for k, v in METHODS.items()}


def parse_token(token: str):
    parts = "".join(token.split()).split("$")
    if len(parts) != 3 or parts[0] != PREFIX or parts[1] not in BY_ID:
        raise CryptoError(BAD)
    try:
        raw = base64.urlsafe_b64decode(parts[2].encode())
    except Exception:
        raise CryptoError(BAD)
    if len(raw) < 17:
        raise CryptoError(BAD)
    return BY_ID[parts[1]], raw


def encrypt(method: str, text: str, secret: str) -> str:
    meth = METHODS[method]
    salt = os.urandom(16)
    k = kdf(secret, salt)
    payload = meth["enc"](text.encode("utf-8"), k[:32], k[32:])
    return f"{PREFIX}${meth['id']}${base64.urlsafe_b64encode(salt + payload).decode()}"


def decrypt(token: str, secret: str) -> str:
    name, raw = parse_token(token)
    salt, payload = raw[:16], raw[16:]
    k = kdf(secret, salt)
    try:
        return METHODS[name]["dec"](payload, k[:32], k[32:]).decode("utf-8")
    except CryptoError:
        raise
    except Exception:
        raise CryptoError(WRONG)


# ----------------------------------------------------------------------------
#  GUI HELPERS
# ----------------------------------------------------------------------------
THEMES = {
    "Kali Cyber": dict(bg="#0b0f14", panel="#111a24", field="#0d141c", fg="#d7e3f4", dim="#6c7a89", a1="#00e5ff", a2="#7c4dff"),
    "Matrix":     dict(bg="#020a04", panel="#08170d", field="#04110a", fg="#c8ffd4", dim="#4d7a58", a1="#00ff6a", a2="#b6ff00"),
    "Blood Moon": dict(bg="#0f0809", panel="#1c1012", field="#150b0d", fg="#ffe1e1", dim="#8a6366", a1="#ff2e4d", a2="#ff9100"),
    "Neon Synth": dict(bg="#0d0a17", panel="#171230", field="#110d22", fg="#f1e6ff", dim="#7d6fa0", a1="#ff2bd6", a2="#00f0ff"),
    "Solar Gold": dict(bg="#0e0c07", panel="#1a160b", field="#131008", fg="#fff2cc", dim="#8f8460", a1="#ffc400", a2="#ff6d00"),
}
OK_COL, ERR_COL, WARN_COL = "#2ee59d", "#ff5470", "#ffd24a"
GLYPHS = "01ABCDEF<>/\\|+=*#$%&@アイウエオカキクケコ"
CELL, TRAIL, SIDE_W = 16, 14, 280
MONO = "DejaVu Sans Mono"


def lerp(c1, c2, t):
    t = max(0.0, min(1.0, t))
    a = [int(c1[i:i + 2], 16) for i in (1, 3, 5)]
    b = [int(c2[i:i + 2], 16) for i in (1, 3, 5)]
    return "#%02x%02x%02x" % tuple(int(a[i] + (b[i] - a[i]) * t) for i in range(3))


class GlowButton(tk.Canvas):
    """Canvas button with animated hover glow, gradient fill and pulse."""

    def __init__(self, master, app, text, command, width=150, height=38, primary=False):
        super().__init__(master, width=width, height=height, highlightthickness=0, bd=0, cursor="hand2")
        self.app, self.text, self.command = app, text, command
        self.w, self.h, self.primary = width, height, primary
        self.hover = self.target = 0.0
        self.active = False
        self.font = (MONO, 11 if not primary else 13, "bold")
        self.bind("<Enter>", lambda e: setattr(self, "target", 1.0))
        self.bind("<Leave>", lambda e: setattr(self, "target", 0.0))
        self.bind("<ButtonRelease-1>", lambda e: self.command())
        app.buttons.append(self)

    def draw(self):
        t = self.app.t
        self.hover += (self.target - self.hover) * 0.25
        lvl = max(self.hover, 0.9 if self.active else 0.0)
        pulse = (math.sin(self.app.frame * 0.12) + 1) / 2 if self.primary else 0
        self.delete("all")
        self.configure(bg=t["bg"])
        border = lerp(t["a1"], t["a2"], self.hover)
        if lvl > 0.02 or self.primary:
            slices = 24
            for i in range(slices):
                x0, x1 = i * self.w / slices, (i + 1) * self.w / slices + 1
                c = lerp(t["a1"], t["a2"], i / slices + 0.3 * math.sin(self.app.frame * 0.05))
                strength = max(lvl, 0.25 + 0.25 * pulse if self.primary else 0)
                self.create_rectangle(x0, 0, x1, self.h, fill=lerp(t["panel"], c, strength * 0.9), outline="")
        else:
            self.create_rectangle(0, 0, self.w, self.h, fill=t["panel"], outline="")
        self.create_rectangle(1, 1, self.w - 1, self.h - 1, outline=border, width=2)
        txt_col = lerp(t["fg"], "#000000", lvl) if lvl > 0.5 else t["fg"]
        self.create_text(self.w / 2, self.h / 2, text=self.text, fill=txt_col, font=self.font)


# ----------------------------------------------------------------------------
#  MAIN APP
# ----------------------------------------------------------------------------
class App:
    def __init__(self, root):
        self.root = root
        root.title("NeoCrypt  //  Reversible Encryption Suite")
        root.geometry("1120x800")
        root.minsize(1000, 740)
        self.tname = "Kali Cyber"
        self.t = THEMES[self.tname]
        self.mode = "encrypt"
        self.busy = False
        self.result = None
        self.frame = 0
        self.auto = False
        self.flash = 0.0
        self.reg, self.buttons = [], []
        self.drops, self.speeds = [], []
        self.status_full, self.status_shown, self.status_kind = "", 0, "info"
        self.meter_cur = self.meter_target = 0.0
        self.meter_label = ""
        self.title_font = tkfont.Font(family=MONO, size=22, weight="bold")
        self.method_var = tk.StringVar(value="AES-256-GCM")
        self._build()
        self._style()
        self.set_mode("encrypt")
        self.set_status("Ready. Type your text, choose a cipher and enter a secret key.", "info")
        self.tick()

    # ---- construction ------------------------------------------------------
    def _r(self, w, role):
        self.reg.append((w, role))
        return w

    def _build(self):
        r = self.root
        r.columnconfigure(1, weight=1)
        r.rowconfigure(0, weight=1)
        self.side = tk.Canvas(r, width=SIDE_W, highlightthickness=0, bd=0)
        self.side.grid(row=0, column=0, sticky="ns")
        m = self._r(tk.Frame(r), "bg")
        m.grid(row=0, column=1, sticky="nsew", padx=(14, 18), pady=10)
        m.columnconfigure(0, weight=1)
        self.main = m

        self.title_c = self._r(tk.Canvas(m, height=64, highlightthickness=0), "canvas")
        self.title_c.grid(row=0, column=0, sticky="ew")

        top = self._r(tk.Frame(m), "bg")
        top.grid(row=1, column=0, sticky="ew", pady=(4, 8))
        self.b_enc = GlowButton(top, self, "ENCRYPT", lambda: self.set_mode("encrypt"), 130, 34)
        self.b_dec = GlowButton(top, self, "DECRYPT", lambda: self.set_mode("decrypt"), 130, 34)
        self.b_enc.pack(side="left")
        self.b_dec.pack(side="left", padx=8)
        self.b_auto = GlowButton(top, self, "AUTO-COLOUR", self.toggle_auto, 140, 34)
        self.b_auto.pack(side="right")
        self.dots = self._r(tk.Canvas(top, width=len(THEMES) * 30, height=34, highlightthickness=0), "canvas")
        self.dots.pack(side="right", padx=12)
        self.dots.bind("<Button-1>", self._dot_click)

        row = self._r(tk.Frame(m), "bg")
        row.grid(row=2, column=0, sticky="ew")
        row.columnconfigure(2, weight=1)
        self._r(tk.Label(row, text="CIPHER", font=(MONO, 10, "bold")), "label").grid(row=0, column=0, padx=(0, 8))
        self.combo = ttk.Combobox(row, textvariable=self.method_var, values=list(METHODS), state="readonly",
                                  width=32, font=(MONO, 11), style="NC.TCombobox")
        self.combo.grid(row=0, column=1)
        self.combo.bind("<<ComboboxSelected>>", self._method_changed)
        self.info = self._r(tk.Label(row, font=(MONO, 9), anchor="w"), "dim")
        self.info.grid(row=0, column=2, sticky="w", padx=12)

        self.in_lbl = self._r(tk.Label(m, font=(MONO, 10, "bold"), anchor="w"), "label")
        self.in_lbl.grid(row=3, column=0, sticky="w", pady=(10, 2))
        self.inp = self._r(tk.Text(m, height=7, font=(MONO, 11), wrap="char", bd=0, highlightthickness=2, padx=8, pady=6), "field")
        self.inp.grid(row=4, column=0, sticky="nsew")
        m.rowconfigure(4, weight=1)

        self._r(tk.Label(m, text="SECRET KEY  (hidden)", font=(MONO, 10, "bold"), anchor="w"), "label").grid(row=5, column=0, sticky="w", pady=(10, 2))
        kr = self._r(tk.Frame(m), "bg")
        kr.grid(row=6, column=0, sticky="ew")
        kr.columnconfigure(0, weight=1)
        self.key = self._r(tk.Entry(kr, show="\u25cf", font=(MONO, 12), bd=0, highlightthickness=2), "field")
        self.key.grid(row=0, column=0, sticky="ew", ipady=6)
        self.key.bind("<KeyRelease>", self._key_changed)
        self.b_show = GlowButton(kr, self, "REVEAL", self.toggle_reveal, 100, 34)
        self.b_show.grid(row=0, column=1, padx=(8, 0))
        self.b_gen = GlowButton(kr, self, "GENERATE", self.generate_key, 120, 34)
        self.b_gen.grid(row=0, column=2, padx=(8, 0))

        self.conf_lbl = self._r(tk.Label(m, text="CONFIRM KEY", font=(MONO, 10, "bold"), anchor="w"), "label")
        self.conf_lbl.grid(row=7, column=0, sticky="w", pady=(8, 2))
        self.conf = self._r(tk.Entry(m, show="\u25cf", font=(MONO, 12), bd=0, highlightthickness=2), "field")
        self.conf.grid(row=8, column=0, sticky="ew", ipady=6)

        self.meter = self._r(tk.Canvas(m, height=22, highlightthickness=0), "canvas")
        self.meter.grid(row=9, column=0, sticky="ew", pady=(8, 4))

        act = self._r(tk.Frame(m), "bg")
        act.grid(row=10, column=0, sticky="ew", pady=6)
        self.b_go = GlowButton(act, self, "ENCRYPT  >>", self.run, 220, 46, primary=True)
        self.b_go.pack(side="left")
        for txt, cmd in (("COPY", self.copy_out), ("USE AS INPUT", self.swap), ("CLEAR", self.clear_all)):
            GlowButton(act, self, txt, cmd, 130 if txt != "USE AS INPUT" else 150, 38).pack(side="left", padx=(8, 0))

        self.out_lbl = self._r(tk.Label(m, font=(MONO, 10, "bold"), anchor="w"), "label")
        self.out_lbl.grid(row=11, column=0, sticky="w", pady=(6, 2))
        self.out = self._r(tk.Text(m, height=7, font=(MONO, 11), wrap="char", bd=0, highlightthickness=2, padx=8, pady=6), "field")
        self.out.grid(row=12, column=0, sticky="nsew")
        m.rowconfigure(12, weight=1)

        self.prog = self._r(tk.Canvas(m, height=6, highlightthickness=0), "canvas")
        self.prog.grid(row=13, column=0, sticky="ew", pady=(8, 4))
        self.status = self._r(tk.Label(m, font=(MONO, 10), anchor="w", justify="left"), "dim")
        self.status.grid(row=14, column=0, sticky="ew")

    def _style(self):
        t = self.t
        self.root.configure(bg=t["bg"])
        for w, role in self.reg:
            if role in ("bg", "canvas"):
                w.configure(bg=t["bg"])
            elif role == "label":
                w.configure(bg=t["bg"], fg=t["fg"])
            elif role == "dim":
                w.configure(bg=t["bg"], fg=t["dim"])
            elif role == "field":
                w.configure(bg=t["field"], fg=t["fg"], insertbackground=t["a1"],
                            highlightbackground=t["dim"], highlightcolor=t["a1"],
                            selectbackground=t["a2"], selectforeground="#000000")
        st = ttk.Style()
        st.theme_use("clam")
        st.configure("NC.TCombobox", fieldbackground=t["field"], background=t["panel"], foreground=t["fg"],
                     arrowcolor=t["a1"], bordercolor=t["a1"], lightcolor=t["panel"], darkcolor=t["panel"],
                     selectbackground=t["field"], selectforeground=t["fg"])
        st.map("NC.TCombobox", fieldbackground=[("readonly", t["field"])], foreground=[("readonly", t["fg"])],
               background=[("active", t["panel"])])
        try:
            pop = self.combo.tk.eval(f"ttk::combobox::PopdownWindow {self.combo}")
            self.combo.tk.call(f"{pop}.f.l", "configure", "-background", t["field"], "-foreground", t["fg"],
                               "-selectbackground", t["a2"], "-selectforeground", "#000000")
        except tk.TclError:
            pass
        self._method_changed()

    # ---- events ------------------------------------------------------------
    def _method_changed(self, _e=None):
        self.info.configure(text=METHODS[self.method_var.get()]["info"])

    def _dot_click(self, e):
        i = e.x // 30
        names = list(THEMES)
        if 0 <= i < len(names):
            self.auto = False
            self.b_auto.active = False
            self.apply_theme(names[i])

    def apply_theme(self, name):
        self.tname, self.t = name, THEMES[name]
        self._style()

    def toggle_auto(self):
        self.auto = not self.auto
        self.b_auto.active = self.auto

    def toggle_reveal(self):
        hidden = self.key.cget("show") != ""
        sh = "" if hidden else "\u25cf"
        self.key.configure(show=sh)
        self.conf.configure(show=sh)
        self.b_show.text = "HIDE" if hidden else "REVEAL"

    def generate_key(self):
        k = secrets.token_urlsafe(24)
        for e in (self.key, self.conf):
            e.delete(0, "end")
            e.insert(0, k)
        self.root.clipboard_clear()
        self.root.clipboard_append(k)
        self._key_changed()
        self.set_status("Strong random key generated (hidden) and copied to clipboard. "
                        "Save it safely - without it the data cannot be decrypted.", "warn")

    def _key_changed(self, _e=None):
        k = self.key.get()
        if not k:
            self.meter_target, self.meter_label = 0.0, ""
            return
        pool = 0
        pool += 26 if any(c.islower() for c in k) else 0
        pool += 26 if any(c.isupper() for c in k) else 0
        pool += 10 if any(c.isdigit() for c in k) else 0
        pool += 33 if any(not c.isalnum() for c in k) else 0
        bits = len(k) * math.log2(max(pool, 2))
        self.meter_target = min(bits / 100, 1.0)
        self.meter_label = ("WEAK" if bits < 40 else "FAIR" if bits < 60 else "STRONG" if bits < 80 else "EXCELLENT")

    def set_mode(self, mode):
        self.mode = mode
        enc = mode == "encrypt"
        self.b_enc.active, self.b_dec.active = enc, not enc
        self.in_lbl.configure(text="PLAIN TEXT (human readable)" if enc else "ENCRYPTED TEXT  (NC1$...)")
        self.out_lbl.configure(text="ENCRYPTED OUTPUT" if enc else "DECRYPTED TEXT")
        self.b_go.text = "ENCRYPT  >>" if enc else "DECRYPT  >>"
        if enc:
            self.conf_lbl.grid()
            self.conf.grid()
        else:
            self.conf_lbl.grid_remove()
            self.conf.grid_remove()
        self._set_out("")

    def _set_out(self, s):
        self.out.delete("1.0", "end")
        self.out.insert("1.0", s)

    def copy_out(self):
        s = self.out.get("1.0", "end-1c")
        if s:
            self.root.clipboard_clear()
            self.root.clipboard_append(s)
            self.set_status("Output copied to clipboard.", "ok")

    def swap(self):
        s = self.out.get("1.0", "end-1c")
        if not s:
            return
        self.inp.delete("1.0", "end")
        self.inp.insert("1.0", s)
        self.set_mode("decrypt" if self.mode == "encrypt" else "encrypt")
        self.set_status("Output moved to input. Enter the secret key to continue.", "info")

    def clear_all(self):
        self.inp.delete("1.0", "end")
        self.key.delete(0, "end")
        self.conf.delete(0, "end")
        self._set_out("")
        self._key_changed()
        self.set_status("Cleared.", "info")

    def set_status(self, msg, kind="info"):
        self.status_full, self.status_shown, self.status_kind = msg, 0, kind

    # ---- run ---------------------------------------------------------------
    def run(self):
        if self.busy:
            return
        text = self.inp.get("1.0", "end-1c").strip() if self.mode == "decrypt" else self.inp.get("1.0", "end-1c")
        key = self.key.get()
        if not text:
            return self.set_status("Please enter some text first.", "error")
        if not key:
            return self.set_status("Please enter a secret key.", "error")
        if self.mode == "encrypt":
            if len(key) < 8:
                return self.set_status("Use a secret key of at least 8 characters.", "error")
            if key != self.conf.get():
                return self.set_status("The two secret keys do not match.", "error")
        else:
            try:
                name, _ = parse_token(text)
                self.method_var.set(name)
                self._method_changed()
            except CryptoError as e:
                return self.set_status(str(e), "error")
        method, mode = self.method_var.get(), self.mode
        self.busy, self.result = True, None
        self.set_status("Deriving key with scrypt and processing...", "info")

        def work():
            try:
                out = encrypt(method, text, key) if mode == "encrypt" else decrypt(text, key)
                self.result = (True, out)
            except CryptoError as e:
                self.result = (False, str(e))
            except Exception as e:  # noqa
                self.result = (False, f"Unexpected error: {e}")
        threading.Thread(target=work, daemon=True).start()
        self.root.after(60, self._poll)

    def _poll(self):
        if self.result is None:
            return self.root.after(60, self._poll)
        ok, val = self.result
        self.busy = False
        if ok:
            self._set_out(val)
            self.flash = 1.0
            self.set_status(("Encrypted with " + self.method_var.get() + ". Keep the secret key safe!")
                            if self.mode == "encrypt" else "Decryption successful.", "ok")
        else:
            self._set_out("")
            self.set_status(val, "error")

    # ---- animation ---------------------------------------------------------
    def tick(self):
        try:
            self.frame += 1
            if self.auto and self.frame % 200 == 0:
                names = list(THEMES)
                self.apply_theme(names[(names.index(self.tname) + 1) % len(names)])
            self._draw_side()
            self._draw_title()
            self._draw_dots()
            self._draw_meter()
            self._draw_progress()
            for b in self.buttons:
                b.draw()
            self._type_status()
        finally:
            self.root.after(40, self.tick)

    def _draw_side(self):
        c, t, w = self.side, self.t, SIDE_W
        h = max(c.winfo_height(), 300)
        c.delete("all")
        c.configure(bg=t["bg"])
        cols = w // CELL
        if len(self.drops) != cols:
            self.drops = [random.uniform(-30, 0) for _ in range(cols)]
            self.speeds = [random.uniform(0.25, 0.7) for _ in range(cols)]
        rows = h // CELL + TRAIL + 2
        for i in range(cols):
            self.drops[i] += self.speeds[i]
            if self.drops[i] > rows:
                self.drops[i], self.speeds[i] = random.uniform(-15, -1), random.uniform(0.25, 0.7)
            hi = int(self.drops[i])
            base = t["a1"] if i % 3 else t["a2"]
            for j in range(TRAIL):
                row = hi - j
                y = row * CELL + CELL // 2
                if row < 0 or y > h:
                    continue
                col = lerp(t["bg"], base, 1 - j / TRAIL) if j else lerp(base, "#ffffff", 0.7)
                g = GLYPHS[(i * 13 + row * 7 + (self.frame // 6 if (row + i) % 5 == 0 else 0)) % len(GLYPHS)]
                c.create_text(i * CELL + CELL // 2, y, text=g, fill=col, font=(MONO, 11, "bold"))
        sy = (self.frame * 4) % h
        c.create_line(0, sy, w, sy, fill=lerp(t["bg"], t["a2"], 0.6), width=2)
        cx, cy = w // 2, h // 2 - 20
        c.create_oval(cx - 104, cy - 104, cx + 104, cy + 104, fill=t["bg"], outline="")
        for k in range(3):
            r = 66 + k * 15
            start = (self.frame * (3 + 2 * k) * (1 if k % 2 == 0 else -1)) % 360
            c.create_arc(cx - r, cy - r, cx + r, cy + r, start=start, extent=90 + k * 25, style="arc",
                         outline=t["a1"] if k % 2 == 0 else t["a2"], width=3)
        pr = 42 + 4 * math.sin(self.frame * 0.1)
        c.create_oval(cx - pr, cy - pr, cx + pr, cy + pr, outline=lerp(t["bg"], t["a1"], 0.5), width=2)
        c.create_arc(cx - 14, cy - 34, cx + 14, cy - 2, start=0, extent=180, style="arc", outline=t["a1"], width=5)
        c.create_rectangle(cx - 21, cy - 8, cx + 21, cy + 24, fill=t["a1"], outline="")
        c.create_oval(cx - 4, cy + 2, cx + 4, cy + 10, fill=t["bg"], outline="")
        c.create_rectangle(cx - 2, cy + 8, cx + 2, cy + 17, fill=t["bg"], outline="")
        for k in range(4):
            a = self.frame * 0.05 + k * math.pi / 2
            x, y = cx + 112 * math.cos(a), cy + 112 * math.sin(a)
            c.create_oval(x - 4, y - 4, x + 4, y + 4, fill=t["a2"] if k % 2 else t["a1"], outline="")
        c.create_text(cx, cy + 135, text="N E O C R Y P T", fill=t["a1"], font=(MONO, 13, "bold"))
        state = "PROCESSING" if self.busy else "SECURE"
        c.create_text(cx, cy + 156, text=f"[ {state} ]", fill=lerp(t["dim"], t["a2"], (math.sin(self.frame * 0.2) + 1) / 2),
                      font=(MONO, 9, "bold"))
        c.create_text(cx, cy + 174, text=self.tname.upper(), fill=t["dim"], font=(MONO, 8))

    def _draw_title(self):
        c, t = self.title_c, self.t
        c.delete("all")
        x, text = 4, "NEOCRYPT // ENCRYPTION SUITE"
        for i, ch in enumerate(text):
            col = lerp(t["a1"], t["a2"], (math.sin(self.frame * 0.08 + i * 0.35) + 1) / 2)
            c.create_text(x, 26, text=ch, fill=col, font=self.title_font, anchor="w")
            x += self.title_font.measure(ch)
        w = max(c.winfo_width(), 400)
        c.create_line(0, 54, w, 54, fill=t["dim"], width=1)
        px = (self.frame * 9) % (w + 200) - 100
        for i in range(10):
            c.create_line(px + i * 10, 54, px + i * 10 + 10, 54, fill=lerp(t["bg"], t["a1"], i / 10), width=3)

    def _draw_dots(self):
        c, t = self.dots, self.t
        c.delete("all")
        for i, (name, th) in enumerate(THEMES.items()):
            x = i * 30 + 15
            c.create_oval(x - 10, 7, x + 10, 27, fill=th["a1"], outline="")
            c.create_arc(x - 10, 7, x + 10, 27, start=90, extent=180, fill=th["a2"], outline="")
            if name == self.tname:
                r = 13 + 1.5 * math.sin(self.frame * 0.2)
                c.create_oval(x - r, 17 - r, x + r, 17 + r, outline=t["fg"], width=2)

    def _draw_meter(self):
        c, t = self.meter, self.t
        c.delete("all")
        w = max(c.winfo_width(), 200)
        self.meter_cur += (self.meter_target - self.meter_cur) * 0.15
        c.create_rectangle(0, 7, w - 110, 15, fill=t["field"], outline="")
        v = self.meter_cur
        col = lerp(ERR_COL, WARN_COL, v * 2) if v < 0.5 else lerp(WARN_COL, OK_COL, (v - 0.5) * 2)
        c.create_rectangle(0, 7, (w - 110) * v, 15, fill=col, outline="")
        c.create_text(w - 104, 11, text=self.meter_label or "KEY STRENGTH", anchor="w", fill=col if self.meter_label else t["dim"],
                      font=(MONO, 9, "bold"))

    def _draw_progress(self):
        c, t = self.prog, self.t
        c.delete("all")
        w = max(c.winfo_width(), 200)
        c.create_rectangle(0, 0, w, 6, fill=t["field"], outline="")
        if self.busy:
            x = (self.frame * 14) % (w + 200) - 160
            for i in range(16):
                c.create_rectangle(x + i * 10, 0, x + i * 10 + 10, 6, fill=lerp(t["a2"], t["a1"], i / 16), outline="")
        elif self.flash > 0.01:
            c.create_rectangle(0, 0, w * min(1, (1.2 - self.flash) * 6), 6, fill=lerp(t["field"], OK_COL, self.flash), outline="")
            self.flash *= 0.95

    def _type_status(self):
        full = self.status_full
        self.status_shown = min(len(full), self.status_shown + 2)
        cur = "\u258c" if (self.frame // 8) % 2 and self.status_shown < len(full) else ""
        col = {"ok": OK_COL, "error": ERR_COL, "warn": WARN_COL}.get(self.status_kind, self.t["a1"])
        self.status.configure(text="> " + full[:self.status_shown] + cur, fg=col)


if __name__ == "__main__":
    root = tk.Tk()
    App(root)
    root.mainloop()
