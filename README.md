# OTP
1. Kodingan Program
2. Screenshot Kodingan
3. Table ASCII
   
## Kodingan Program
```py
# otp_gui_dark_decrypt.py
# Modern Dark GUI for OTP XOR (encrypt + decrypt) with ASCII control-name handling
# Paste to VSCode and run: python otp_gui_dark_decrypt.py

import tkinter as tk
from tkinter import filedialog, scrolledtext, ttk, messagebox
import base64
import os
import re

# -------------------------
# Config & Defaults
# -------------------------
UPLOADED_FILE_PATH = "/mnt/data/10. Pertemuan 10_2025.pptx.pdf"

# Colors (Modern Dark)
BG = "#1e1e1e"
PANEL = "#252526"
CARD = "#2b2b2d"
FG = "#e6e6e6"
MUTED = "#9e9e9e"
ACCENT = "#3aa0ff"
COL_A_BG = "#2a2f36"
COL_A_BIN_BG = "#252a2f"
COL_B_BG = "#2a2f36"
COL_B_BIN_BG = "#252a2f"
COL_XOR_BG = "#2e2b3a"
COL_XOR_BIN_BG = "#241f2f"
TAG_DIFF = "#ffcc66"
TAG_CASE = "#66ccff"
HEADER_BG = "#111113"

DEFAULT_FONT = ("JetBrains Mono", 10)
MONO_FONT = ("Courier New", 10)

# -------------------------
# Control names mapping (0..31)
# -------------------------
CTRL_NAMES = {
    0: "NUL", 1: "Ctrl-A", 2: "Ctrl-B", 3: "Ctrl-C", 4: "Ctrl-D", 5: "Ctrl-E",
    6: "Ctrl-F", 7: "Ctrl-G", 8: "Backspace", 9: "Tab", 10: "LF", 11: "VT",
    12: "FF", 13: "CR", 14: "Ctrl-N", 15: "Ctrl-O", 16: "Ctrl-P", 17: "Ctrl-Q",
    18: "Ctrl-R", 19: "Ctrl-S", 20: "Ctrl-T", 21: "Ctrl-U", 22: "Ctrl-V", 23: "Ctrl-W",
    24: "Ctrl-X", 25: "Ctrl-Y", 26: "Ctrl-Z", 27: "ESC", 28: "FS", 29: "GS", 30: "RS", 31: "US"
}
NAME_TO_CTRL = {v.upper(): k for k, v in CTRL_NAMES.items()}
CONTROL_NAMES_SORTED = sorted(NAME_TO_CTRL.keys(), key=lambda x: -len(x))  # longest first

# -------------------------
# Helpers (format detection & parsing)
# -------------------------
HEX_RE = re.compile(r'^[0-9a-fA-F]+$')
BASE64_RE = re.compile(r'^[A-Za-z0-9+/]+={0,2}$')

def looks_like_hex(s: str) -> bool:
    s2 = s.strip().replace("0x", "").replace(" ", "")
    return len(s2) > 0 and len(s2) % 2 == 0 and HEX_RE.match(s2) is not None

def looks_like_base64(s: str) -> bool:
    s2 = s.strip()
    return len(s2) > 0 and BASE64_RE.match(s2) is not None and (len(s2) % 4 == 0)

def ascii_to_binary(v: int) -> str:
    return format(v, '08b')

def apply_case_mode(s: str, mode: str) -> str:
    if mode == 'upper':
        return s.upper()
    if mode == 'lower':
        return s.lower()
    return s

# -------------------------
# Text parse supporting control-name tokens (e.g. "Ctrl-Q" or "LF" or "FF")
# -------------------------
def parse_text_with_ctrls(s: str) -> bytes:
    i = 0
    out = bytearray()
    s_upper = s.upper()
    n = len(s)
    while i < n:
        matched = False
        # Try matching any control name (longest first)
        for name in CONTROL_NAMES_SORTED:
            L = len(name)
            if s_upper.startswith(name, i):
                out.append(NAME_TO_CTRL[name])
                i += L
                matched = True
                break
        if matched:
            continue
        # Generic CTRL-? form
        if s_upper.startswith("CTRL-", i):
            if i + 6 <= n:
                token = s_upper[i:i+6]
                if token in NAME_TO_CTRL:
                    out.append(NAME_TO_CTRL[token])
                    i += 6
                    continue
        # whitespace skip
        if s[i].isspace():
            i += 1
            continue
        # default: literal char
        out.append(ord(s[i]))
        i += 1
    return bytes(out)

# -------------------------
# XOR core
# -------------------------
def xor_bytes(data: bytes, key: bytes) -> bytes:
    if len(key) == 0:
        raise ValueError("Key must not be empty.")
    expanded = (key * ((len(data) // len(key)) + 1))[:len(data)]
    return bytes(a ^ b for a, b in zip(data, expanded))

# -------------------------
# Pretty render bytes (control-names for 0..31, printable chars otherwise, hex for others)
# -------------------------
def bytes_to_pretty_string(b: bytes) -> str:
    parts = []
    for byte in b:
        if 32 <= byte <= 126:
            parts.append(chr(byte))
        elif byte in CTRL_NAMES:
            parts.append(CTRL_NAMES[byte])
        else:
            parts.append(f"0x{byte:02X}")
    return ''.join(parts)

# -------------------------
# High-level decrypt that autodetects input format
# -------------------------
def decrypt_ciphertext(ciphertext_input: str, key: str) -> (bytes, str):
    s = ciphertext_input.strip()
    if looks_like_hex(s):
        hexstr = s.replace("0x", "").replace(" ", "")
        ct_bytes = bytes.fromhex(hexstr)
    elif looks_like_base64(s):
        try:
            ct_bytes = base64.b64decode(s)
        except Exception:
            ct_bytes = parse_text_with_ctrls(ciphertext_input)
    else:
        ct_bytes = parse_text_with_ctrls(ciphertext_input)
    key_bytes = key.encode('utf-8')
    pt_bytes = xor_bytes(ct_bytes, key_bytes)
    # attempt utf-8 decode
    try:
        pt_text = pt_bytes.decode('utf-8')
    except Exception:
        pt_text = bytes_to_pretty_string(pt_bytes)
    return pt_bytes, pt_text

# -------------------------
# High-level encrypt: plaintext string -> ciphertext bytes and pretty representation
# (produces control-names for non-printable bytes)
# -------------------------
def encrypt_plaintext(plaintext: str, key: str) -> (bytes, str, str, str):
    pt_bytes = plaintext.encode('utf-8')
    key_bytes = key.encode('utf-8')
    ct_bytes = xor_bytes(pt_bytes, key_bytes)
    pretty = bytes_to_pretty_string(ct_bytes)
    hex_out = ct_bytes.hex()
    b64_out = base64.b64encode(ct_bytes).decode()
    return ct_bytes, pretty, hex_out, b64_out

# -------------------------
# GUI Construction
# -------------------------
root = tk.Tk()
root.title("OTP XOR — Modern Dark (Encrypt & Decrypt)")
root.configure(bg=BG)
root.geometry("1200x820")

# Title
title_fr = tk.Frame(root, bg=BG)
title_fr.pack(fill='x', padx=12, pady=(8,4))
tk.Label(title_fr, text="OTP XOR — Modern Dark", fg=ACCENT, bg=BG,
         font=("Segoe UI", 14, "bold")).pack(side='left', padx=(6,10))
tk.Label(title_fr, text="(ASCII & Control-NAMES • Encrypt/Decrypt)", fg=MUTED, bg=BG, font=("Segoe UI", 10)).pack(side='left')

main_fr = tk.Frame(root, bg=BG)
main_fr.pack(fill='both', expand=True, padx=12, pady=8)

# Left panel: inputs
left = tk.Frame(main_fr, bg=PANEL)
left.pack(side='left', fill='y', padx=(0,8), pady=6)

tk.Label(left, text="Plaintext / Ciphertext:", fg=FG, bg=PANEL, font=DEFAULT_FONT).pack(anchor='w', padx=8, pady=(8,2))
input_txt = tk.Text(left, height=6, width=44, bg=CARD, fg=FG, insertbackground=FG, font=MONO_FONT)
input_txt.pack(padx=8, pady=(0,8))

tk.Label(left, text="Key:", fg=FG, bg=PANEL, font=DEFAULT_FONT).pack(anchor='w', padx=8)
key_entry = tk.Entry(left, width=40, bg=CARD, fg=FG, insertbackground=FG, font=MONO_FONT)
key_entry.pack(padx=8, pady=(0,8))

tk.Label(left, text="Auto-convert (case):", fg=FG, bg=PANEL, font=DEFAULT_FONT).pack(anchor='w', padx=8, pady=(6,0))
case_var = tk.StringVar(value='none')
case_combo = ttk.Combobox(left, textvariable=case_var, values=['none','upper','lower'], width=10, state='readonly')
case_combo.pack(padx=8, pady=(4,8))
case_combo.set('none')

btn_fr = tk.Frame(left, bg=PANEL)
btn_fr.pack(padx=8, pady=(6,12))
def style_btn(b):
    b.configure(bg=ACCENT, fg="#0a0a0a", activebackground="#2a9bff", bd=0, padx=8, pady=6)
enc_xor_btn = tk.Button(btn_fr, text="Encrypt XOR", command=lambda: gui_encrypt_xor(), width=20)
dec_xor_btn = tk.Button(btn_fr, text="Decrypt XOR (Auto-detect)", command=lambda: gui_decrypt_xor(), width=25)
ascii_btn = tk.Button(btn_fr, text="ASCII of Input", command=lambda: gui_ascii_of_input(), width=20)
load_btn = tk.Button(btn_fr, text="Load uploaded PDF", command=lambda: load_uploaded_file(), width=20)

for b in (enc_xor_btn, dec_xor_btn, ascii_btn, load_btn):
    b.pack(pady=6)
    style_btn(b)

tk.Label(left, text="(Ciphertext may be: Ctrl-QCtrl-R..., hex, base64, or printable)", fg=MUTED, bg=PANEL, font=("Segoe UI",9)).pack(anchor='w', padx=8, pady=(6,0))

# Right panel: output
right = tk.Frame(main_fr, bg=BG)
right.pack(side='left', fill='both', expand=True)

tk.Label(right, text="Output / Table", fg=FG, bg=BG, font=DEFAULT_FONT).pack(anchor='w', padx=6)
output = scrolledtext.ScrolledText(right, width=86, height=38, bg="#0f0f10", fg=FG, font=MONO_FONT, insertbackground=FG)
output.pack(padx=6, pady=6, fill='both', expand=True)

# Tags for styling
output.tag_configure('hdr', foreground=ACCENT, background=HEADER_BG, font=(MONO_FONT[0], 10, 'bold'))
output.tag_configure('col_a', background=COL_A_BG, foreground=FG)
output.tag_configure('col_a_bin', background=COL_A_BIN_BG, foreground=MUTED)
output.tag_configure('col_b', background=COL_B_BG, foreground=FG)
output.tag_configure('col_b_bin', background=COL_B_BIN_BG, foreground=MUTED)
output.tag_configure('col_x', background=COL_XOR_BG, foreground=FG)
output.tag_configure('col_x_bin', background=COL_XOR_BIN_BG, foreground=MUTED)
output.tag_configure('ctrl', background='#3b2b4a', foreground='#ffd9f0')  # control-name highlight
output.tag_configure('hexbase', foreground=MUTED)
output.tag_configure('plain', foreground=FG)

# -------------------------
# GUI logic functions
# -------------------------
def insert_xor_table_from_bytes(ct_bytes, key_bytes, case_mode):
    """
    Show table with: idx | plain_byte | plain_bin | key_byte | key_bin | xor_byte | xor_bin | 'p' XOR 'k'
    This works both for encrypt (plaintext->ct) where input was plaintext, or decrypt where input is ciphertext.
    For decrypt: ct_bytes is ciphertext; we'll show ct XOR key = plaintext bytes.
    """
    tb = ct_bytes
    kb = key_bytes
    if len(kb) < len(tb) and len(kb) > 0:
        kb = (kb * ((len(tb)//len(kb))+1))[:len(tb)]
    length = max(len(tb), len(kb))
    output.configure(state='normal')
    output.delete("1.0", tk.END)
    header = "IDX | A   | A_bin     | B   | B_bin     | XOR | XOR_bin     # 'A' XOR 'B'\n"
    output.insert(tk.END, header, 'hdr')
    output.insert(tk.END, "-"*95 + "\n")
    for i in range(length):
        a = tb[i] if i < len(tb) else 0
        b = kb[i] if i < len(kb) else 0
        x = a ^ b
        a_bin = ascii_to_binary(a)
        b_bin = ascii_to_binary(b)
        x_bin = ascii_to_binary(x)
        # character representation
        a_ch = chr(a) if 32 <= a <= 126 else (CTRL_NAMES[a] if a in CTRL_NAMES else f"0x{a:02X}")
        b_ch = chr(b) if 32 <= b <= 126 else (CTRL_NAMES[b] if b in CTRL_NAMES else f"0x{b:02X}")
        # build line with fixed widths
        line = f"{i+1:3d} | {a:3d} | {a_bin} | {b:3d} | {b_bin} | {x:3d} | {x_bin}    # '{a_ch}' XOR '{b_ch}'\n"
        start = output.index(tk.END)
        output.insert(tk.END, line)
        end = output.index(tk.END)
        # add tags per column using char offsets
        # segments lengths roughly match the formatting; we'll add tags by char offsets relative to start
        base = start
        segments = [4,3,1,3,1,8,1,3,1,8,1,3,1,8]  # approximate segmentation (safe enough)
        # simpler: we tag whole line as 'plain', and specially highlight control names substring
        # highlight control names if present in comment
        comment_pos = line.find("#")
        if comment_pos != -1:
            # compute comment range
            comment_start = f"{base} + {comment_pos} chars"
            comment_end = f"{base} + {len(line)} chars"
            # find any Ctrl- tokens in the comment and tag them 'ctrl'
            # brute force: search for 'Ctrl-' or any control name tokens
            for ctrl_name in CONTROL_NAMES_SORTED:
                pos = line.upper().find(ctrl_name, 0)
                while pos != -1:
                    sidx = f"{base} + {pos} chars"
                    eidx = f"{base} + {pos + len(ctrl_name)} chars"
                    output.tag_add('ctrl', sidx, eidx)
                    pos = line.upper().find(ctrl_name, pos + 1)
        # tag whole line as plain for consistent color
        output.tag_add('plain', start, end)
    output.insert(tk.END, "\n")  # trailing space
    output.configure(state='disabled')

def gui_encrypt_xor():
    mode = case_var.get()
    txt = input_txt.get("1.0", tk.END).rstrip('\n')
    ky = key_entry.get()
    if ky.strip() == "":
        messagebox.showerror("Error", "Key cannot be empty for XOR encryption")
        return
    txt_conv = apply_case_mode(txt, mode)
    input_txt.delete("1.0", tk.END)
    input_txt.insert(tk.END, txt_conv)
    key_entry.delete(0, tk.END)
    key_entry.insert(0, ky)
    ct_bytes, pretty, hx, b64 = encrypt_plaintext(txt_conv, ky)
    # show table: plain bytes XOR key -> ciphertext (we'll display table with A=plain, B=key, XOR=cipher)
    insert_xor_table_from_bytes(txt_conv.encode('utf-8'), ky.encode('utf-8'), mode)
    # footer with cipher representations
    output.configure(state='normal')
    output.insert(tk.END, f"Ciphertext (pretty): {pretty}\n", 'hexbase')
    output.insert(tk.END, f"Ciphertext (hex)   : {hx}\n", 'hexbase')
    output.insert(tk.END, f"Ciphertext (base64): {b64}\n", 'hexbase')
    output.configure(state='disabled')

def gui_decrypt_xor():
    mode = case_var.get()
    txt = input_txt.get("1.0", tk.END).strip()
    ky = key_entry.get()
    if ky.strip() == "":
        messagebox.showerror("Error", "Key cannot be empty for XOR decryption")
        return
    # detect and parse ciphertext automatically
    try:
        pt_bytes, pt_text = decrypt_ciphertext(txt, ky)
    except Exception as e:
        messagebox.showerror("Decryption error", str(e))
        return
    # For table display we need ciphertext bytes (ct_bytes) and key bytes
    # Determine ct_bytes from input by same detection used in decrypt_ciphertext
    if looks_like_hex(txt):
        ct_bytes = bytes.fromhex(txt.replace("0x","").replace(" ",""))
    elif looks_like_base64(txt):
        try:
            ct_bytes = base64.b64decode(txt)
        except Exception:
            ct_bytes = parse_text_with_ctrls(txt)
    else:
        ct_bytes = parse_text_with_ctrls(txt)
    # reflect used converted plaintext/key into input fields (plaintext result shown separately)
    input_txt.delete("1.0", tk.END)
    # show decrypted text in input area for convenience
    try:
        input_txt.insert(tk.END, pt_text)
    except Exception:
        input_txt.insert(tk.END, pt_bytes.decode('latin1', errors='replace'))
    key_entry.delete(0, tk.END)
    key_entry.insert(0, ky)
    # show table: ciphertext XOR key -> plaintext
    insert_xor_table_from_bytes(ct_bytes, ky.encode('utf-8'), mode)
    # footer: show plaintext representations
    output.configure(state='normal')
    output.insert(tk.END, f"Plaintext (decoded): {pt_text}\n", 'plain')
    output.insert(tk.END, f"Plaintext (hex)    : {pt_bytes.hex()}\n", 'hexbase')
    output.configure(state='disabled')

def gui_ascii_of_input():
    mode = case_var.get()
    txt = input_txt.get("1.0", tk.END)
    txt_conv = apply_case_mode(txt, mode)
    input_txt.delete("1.0", tk.END)
    input_txt.insert(tk.END, txt_conv)
    output.configure(state='normal')
    output.delete("1.0", tk.END)
    output.insert(tk.END, "Char | ASCII | Binary\n", 'hdr')
    output.insert(tk.END, "-"*40 + "\n")
    for ch in txt_conv:
        if ch == '\n': continue
        output.insert(tk.END, f"{repr(ch):4s} | {ord(ch):5d} | {ascii_to_binary(ord(ch))}\n")
    output.configure(state='disabled')

def load_uploaded_file():
    path = UPLOADED_FILE_PATH
    if not os.path.exists(path):
        messagebox.showerror("File not found", f"Uploaded path not found:\n{path}")
        return
    try:
        with open(path, 'rb') as f:
            data = f.read()
        text = data.decode('latin1', errors='ignore')
        input_txt.delete("1.0", tk.END)
        input_txt.insert(tk.END, text[:1000])
    except Exception as e:
        messagebox.showerror("Error loading file", str(e))

# -------------------------
# Start
# -------------------------
root.mainloop()

```

## Screenshot Kodingan
<img width="2950" height="15340" alt="OTP" src="https://github.com/user-attachments/assets/10b9a6e9-286b-4ec1-b26a-0ddb5a2cf348" />

## Tabel ASCII
![ASCII Conversion Chart](https://github.com/user-attachments/assets/edbd582a-3715-49b2-9b12-3670673c6802)

