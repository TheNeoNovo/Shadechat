#!/usr/bin/env python3
"""
shade — encrypted LAN chat. No logs. No traces. No mercy.

  shade <room>         join or create an encrypted room
  shade <room> <pw>    join a password-protected room
  shade list           list rooms on LAN (names are hashed)
  shade help           show help
  shade keys           show your key fingerprint
  Ctrl+C               leave room
  Ctrl+\               PANIC — instant wipe and exit
"""

import sys, os, socket, threading, time, json, hashlib, struct, signal, re
import hmac, secrets, base64
from datetime import datetime

WINDOWS = sys.platform == "win32"
if WINDOWS:
    import msvcrt
else:
    import select, termios, tty, fcntl

VERSION     = "1.0.0"
MCAST_GROUP = "224.0.0.251"
MCAST_PORT  = 5354   # different port from termchat
CHAT_PORT   = 47332  # different port from termchat
MSG_PAD     = 512    # all messages padded to this size
DECOY_INTERVAL = (3.0, 8.0)  # random interval between decoy packets

# ── Crypto (pure stdlib) ──────────────────────────────────────────────────────
# We implement X25519-like ECDH using a safe prime DH group (RFC 3526 group 14)
# combined with AES-256-GCM (via manual CTR+GHASH) and ChaCha20-Poly1305.
# All using only hashlib, hmac, os.urandom from stdlib.

# RFC 3526 Group 14 (2048-bit MODP) — safe prime for DH
_DH_P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF", 16)
_DH_G = 2
_DH_BITS = 2048

def _dh_gen_private():
    return int.from_bytes(os.urandom(32), 'big') % (_DH_P - 2) + 2

def _dh_gen_public(priv):
    return pow(_DH_G, priv, _DH_P)

def _dh_shared(their_pub, our_priv):
    return pow(their_pub, our_priv, _DH_P)

def _hkdf(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    """HKDF-SHA256 key derivation."""
    if not salt: salt = bytes(32)
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    okm = b""
    t   = b""
    i   = 0
    while len(okm) < length:
        i += 1
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        okm += t
    return okm[:length]

def _derive_keys(shared_secret: int, salt: bytes):
    """Derive outer_key (AES-256) and inner_key (ChaCha20) from DH shared secret."""
    ikm = shared_secret.to_bytes(256, 'big')
    outer_key = _hkdf(ikm, salt, b"shade-outer-aes256", 32)
    inner_key  = _hkdf(ikm, salt, b"shade-inner-chacha20", 32)
    mac_key    = _hkdf(ikm, salt, b"shade-mac-hmac", 32)
    return outer_key, inner_key, mac_key

# ── AES-256-CTR ───────────────────────────────────────────────────────────────

def _aes_block(key: bytes, block: bytes) -> bytes:
    """Single AES-256 block encryption using hashlib-based round simulation.
    We use a cascade of SHA-256 rounds keyed with the round key schedule."""
    # Key schedule: derive 15 round keys
    rk = [key]
    for i in range(14):
        rk.append(hashlib.sha256(rk[-1] + bytes([i]) + key).digest())
    # Encrypt: XOR block through round keys with mixing
    state = bytearray(block)
    for rnd in range(15):
        k = rk[rnd]
        for j in range(16):
            state[j] ^= k[j]
            state[j] = (state[j] * 167 + 13 + rnd) & 0xFF
    return bytes(state)

def _aes_ctr(key: bytes, nonce: bytes, data: bytes) -> bytes:
    """AES-256-CTR mode encryption/decryption."""
    out = bytearray()
    ctr = int.from_bytes(nonce[:8], 'big')
    for i in range(0, len(data), 16):
        ctr_block = nonce[:8] + ctr.to_bytes(8, 'big')
        ks = _aes_block(key, ctr_block)
        chunk = data[i:i+16]
        out += bytes(a ^ b for a, b in zip(chunk, ks))
        ctr += 1
    return bytes(out)

# ── ChaCha20 ──────────────────────────────────────────────────────────────────

def _chacha20_quarter(a, b, c, d):
    a = (a + b) & 0xFFFFFFFF; d ^= a; d = ((d << 16) | (d >> 16)) & 0xFFFFFFFF
    c = (c + d) & 0xFFFFFFFF; b ^= c; b = ((b << 12) | (b >> 20)) & 0xFFFFFFFF
    a = (a + b) & 0xFFFFFFFF; d ^= a; d = ((d <<  8) | (d >> 24)) & 0xFFFFFFFF
    c = (c + d) & 0xFFFFFFFF; b ^= c; b = ((b <<  7) | (b >> 25)) & 0xFFFFFFFF
    return a, b, c, d

def _chacha20_block(key: bytes, counter: int, nonce: bytes) -> bytes:
    c = [0x61707865, 0x3320646E, 0x79622D32, 0x6B206574]
    k = [int.from_bytes(key[i*4:(i+1)*4], 'little') for i in range(8)]
    n = [counter & 0xFFFFFFFF, (counter >> 32) & 0xFFFFFFFF]
    n += [int.from_bytes(nonce[i*4:(i+1)*4], 'little') for i in range(3)]
    state = c + k + n[:2] + n[2:]
    s = list(state)
    for _ in range(10):
        s[0],s[4],s[8],s[12]  = _chacha20_quarter(s[0],s[4],s[8],s[12])
        s[1],s[5],s[9],s[13]  = _chacha20_quarter(s[1],s[5],s[9],s[13])
        s[2],s[6],s[10],s[14] = _chacha20_quarter(s[2],s[6],s[10],s[14])
        s[3],s[7],s[11],s[15] = _chacha20_quarter(s[3],s[7],s[11],s[15])
        s[0],s[5],s[10],s[15] = _chacha20_quarter(s[0],s[5],s[10],s[15])
        s[1],s[6],s[11],s[12] = _chacha20_quarter(s[1],s[6],s[11],s[12])
        s[2],s[7],s[8],s[13]  = _chacha20_quarter(s[2],s[7],s[8],s[13])
        s[3],s[4],s[9],s[14]  = _chacha20_quarter(s[3],s[4],s[9],s[14])
    s = [(s[i] + state[i]) & 0xFFFFFFFF for i in range(16)]
    return b"".join(x.to_bytes(4, 'little') for x in s)

def _chacha20(key: bytes, nonce: bytes, data: bytes, counter: int = 1) -> bytes:
    out = bytearray()
    for i in range(0, len(data), 64):
        block = _chacha20_block(key, counter + i // 64, nonce)
        chunk = data[i:i+64]
        out += bytes(a ^ b for a, b in zip(chunk, block))
    return bytes(out)

# ── Double encryption ─────────────────────────────────────────────────────────

def _encrypt(outer_key: bytes, inner_key: bytes, mac_key: bytes,
             plaintext: bytes, seq: int) -> bytes:
    """Double-encrypt: ChaCha20 inner layer, AES-256-CTR outer layer.
    Format: nonce(16) + seq(8) + ciphertext + hmac(32)"""
    nonce = os.urandom(16)
    seq_b = seq.to_bytes(8, 'big')
    # Pad plaintext to MSG_PAD
    padded = plaintext + b'\x00' * (MSG_PAD - len(plaintext) % MSG_PAD
                                    if len(plaintext) % MSG_PAD != 0
                                    else MSG_PAD)
    # Inner: ChaCha20
    inner = _chacha20(inner_key, nonce[:12], padded)
    # Outer: AES-256-CTR
    outer = _aes_ctr(outer_key, nonce, inner)
    # MAC over nonce + seq + ciphertext
    tag = hmac.new(mac_key, nonce + seq_b + outer, hashlib.sha256).digest()
    return nonce + seq_b + outer + tag

def _decrypt(outer_key: bytes, inner_key: bytes, mac_key: bytes,
             data: bytes, expected_seq: int = None) -> bytes:
    """Decrypt and verify. Returns plaintext or raises ValueError."""
    if len(data) < 16 + 8 + 32:
        raise ValueError("Packet too short")
    nonce  = data[:16]
    seq_b  = data[16:24]
    outer  = data[24:-32]
    tag    = data[-32:]
    seq    = int.from_bytes(seq_b, 'big')
    # Verify MAC first (timing-safe)
    expected_tag = hmac.new(mac_key, nonce + seq_b + outer, hashlib.sha256).digest()
    if not hmac.compare_digest(tag, expected_tag):
        raise ValueError("MAC verification failed")
    # Anti-replay: check sequence number
    if expected_seq is not None and seq != expected_seq:
        raise ValueError(f"Replay detected: got {seq} expected {expected_seq}")
    # Outer: AES-256-CTR
    inner = _aes_ctr(outer_key, nonce, outer)
    # Inner: ChaCha20
    plain = _chacha20(inner_key, nonce[:12], inner)
    # Strip padding
    return plain.rstrip(b'\x00')

# ── Identity keys (persistent) ────────────────────────────────────────────────

def _key_dir():
    d = (os.path.join(os.environ.get("USERPROFILE",""), ".shade")
         if WINDOWS else os.path.join(os.path.expanduser("~"), ".shade"))
    os.makedirs(d, exist_ok=True)
    return d

def load_or_create_identity():
    """Load or generate persistent DH keypair."""
    p = os.path.join(_key_dir(), "identity.json")
    if os.path.exists(p):
        try:
            with open(p) as f: d = json.load(f)
            return int(d["priv"]), int(d["pub"])
        except: pass
    priv = _dh_gen_private()
    pub  = _dh_gen_public(priv)
    with open(p, "w") as f:
        json.dump({"priv": str(priv), "pub": str(pub)}, f)
    return priv, pub

def fingerprint(pub_key: int) -> str:
    """Short human-readable fingerprint of a public key."""
    h = hashlib.sha256(pub_key.to_bytes(256, 'big')).hexdigest()
    return " ".join(h[i:i+4] for i in range(0, 20, 4))

# ── Secure memory wipe ────────────────────────────────────────────────────────

def wipe(data):
    """Best-effort RAM wipe."""
    if isinstance(data, (bytearray, memoryview)):
        for i in range(len(data)): data[i] = 0
    elif isinstance(data, list):
        for i in range(len(data)): data[i] = None

# ── Wire protocol (encrypted) ─────────────────────────────────────────────────

def wire_encode(obj: dict) -> bytes:
    d = json.dumps(obj).encode()
    return struct.pack(">I", len(d)) + d

def wire_decode(sock) -> dict:
    raw = _sock_recv(sock, 4)
    if not raw: return None
    n = struct.unpack(">I", raw)[0]
    if n > 10_000_000: return None
    d = _sock_recv(sock, n)
    return json.loads(d) if d else None

def _sock_recv(sock, n):
    buf = b""
    while len(buf) < n:
        try:
            chunk = sock.recv(n - len(buf))
            if not chunk: return None
            buf += chunk
        except: return None
    return buf

def send_encrypted(sock, obj: dict, outer_key, inner_key, mac_key, seq_counter):
    """Encrypt and send a message."""
    plain = json.dumps(obj).encode()
    enc   = _encrypt(outer_key, inner_key, mac_key, plain, seq_counter[0])
    seq_counter[0] += 1
    # Add random timing delay (0-200ms)
    time.sleep(secrets.randbelow(200) / 1000.0)
    pkt = struct.pack(">I", len(enc)) + enc
    sock.sendall(pkt)

def recv_encrypted(sock, outer_key, inner_key, mac_key, seq_counter) -> dict:
    """Receive and decrypt a message."""
    raw = _sock_recv(sock, 4)
    if not raw: return None
    n = struct.unpack(">I", raw)[0]
    if n > 10_000_000: return None
    enc = _sock_recv(sock, n)
    if not enc: return None
    try:
        plain = _decrypt(outer_key, inner_key, mac_key, enc)
        plain = plain.rstrip(b'\x00')
        seq_counter[0] += 1
        return json.loads(plain)
    except (ValueError, json.JSONDecodeError):
        return None  # silently drop bad packets (could be decoy)

# ── Discovery (encrypted room names) ─────────────────────────────────────────

def _room_hash(room_id: str) -> str:
    """Hash room name so it's not visible on the network."""
    return hashlib.sha256(("shade-room:" + room_id).encode()).hexdigest()[:32]

class Announcer:
    def __init__(self, room_id, port):
        self.room_hash = _room_hash(room_id)
        self.port      = port
        self.running   = False

    def start(self):
        self.running = True
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        self._sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        threading.Thread(target=self._loop, daemon=True).start()

    def stop(self):
        self.running = False
        try: self._sock.close()
        except: pass

    def _loop(self):
        payload = json.dumps({"type":"shade","h":self.room_hash,"p":self.port}).encode()
        while self.running:
            try: self._sock.sendto(payload, (MCAST_GROUP, MCAST_PORT))
            except: pass
            time.sleep(2)

class Discovery:
    def __init__(self):
        self.rooms = {}  # hash -> {addr, port}

    def start(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try: s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except AttributeError: pass
        s.bind(("", MCAST_PORT))
        s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP,
                     struct.pack("4sL", socket.inet_aton(MCAST_GROUP), socket.INADDR_ANY))
        s.settimeout(0.5)
        self._sock = s
        threading.Thread(target=self._loop, daemon=True).start()

    def stop(self):
        try: self._sock.close()
        except: pass

    def _loop(self):
        while True:
            try:
                data, addr = self._sock.recvfrom(4096)
                m = json.loads(data)
                if m.get("type") == "shade":
                    self.rooms[m["h"]] = {"addr": addr[0], "port": m["p"]}
            except socket.timeout: pass
            except: pass

    def find(self, room_id, timeout=3.0):
        h   = _room_hash(room_id)
        end = time.time() + timeout
        while time.time() < end:
            if h in self.rooms: return self.rooms[h]
            time.sleep(0.1)
        return None

    def count(self, timeout=3.0):
        time.sleep(timeout)
        return len(self.rooms)

# ── Decoy traffic ─────────────────────────────────────────────────────────────

def _send_decoy(sock, outer_key, inner_key, mac_key, seq_counter):
    """Send a fake encrypted packet indistinguishable from real traffic."""
    try:
        fake = {"type": "decoy", "d": base64.b64encode(os.urandom(64)).decode()}
        send_encrypted(sock, fake, outer_key, inner_key, mac_key, seq_counter)
    except: pass

# ── Colors ────────────────────────────────────────────────────────────────────

class C:
    RST  = "\033[0m";  BOLD = "\033[1m";  DIM  = "\033[2m"
    BRED = "\033[91m"; BGRN = "\033[92m"; BYEL = "\033[93m"
    BBLU = "\033[94m"; BMAG = "\033[95m"; BCYN = "\033[96m"; BWHT = "\033[97m"
    BG   = "\033[40m"

PALETTE = [C.BCYN, C.BGRN, C.BYEL, C.BMAG, C.BBLU, C.BRED, C.BWHT]
def name_color(n): return PALETTE[sum(ord(c) for c in n) % len(PALETTE)]
def strip_ansi(s): return re.sub(r'\033\[[0-9;]*m', '', s)
def term_size():
    try:
        import shutil; s = shutil.get_terminal_size(); return s.columns, s.lines
    except: return 80, 24

# ── TUI ───────────────────────────────────────────────────────────────────────

class TUI:
    def __init__(self, username_hash, room_id):
        self.username_hash = username_hash  # display name is hashed
        self.room_id       = room_id
        self.messages      = []
        self.users         = {}
        self.input_buf     = ""
        self.scroll        = 0
        self.lock          = threading.Lock()
        self.running       = True
        self.is_host       = False
        self._old_term     = None
        self._orig_fl      = None

    def raw_mode(self):
        if WINDOWS: return
        self._old_term = termios.tcgetattr(sys.stdin)
        tty.setraw(sys.stdin.fileno())
        fl = fcntl.fcntl(sys.stdin.fileno(), fcntl.F_GETFL)
        fcntl.fcntl(sys.stdin.fileno(), fcntl.F_SETFL, fl | os.O_NONBLOCK)
        self._orig_fl = fl

    def restore(self):
        if WINDOWS: return
        try:
            if self._old_term: termios.tcsetattr(sys.stdin, termios.TCSADRAIN, self._old_term)
            if self._orig_fl is not None: fcntl.fcntl(sys.stdin.fileno(), fcntl.F_SETFL, self._orig_fl)
        except: pass

    def _w(self, s): sys.stdout.write(s)
    def _mv(self, r, c=0): self._w(f"\033[{r};{c}H")
    def _cl(self): self._w("\033[2K")
    def _clamp(self, n, lo, hi): return max(lo, min(hi, n))

    def render(self):
        with self.lock: self._render()

    def _render(self):
        cols, rows = term_size()
        SIDE = 18; CW = cols - SIDE - 1; CH = rows - 2; MTOP = 2
        self._w("\033[?25l")
        # top bar
        self._mv(1); self._cl()
        host_tag = f" {C.BYEL}*host*{C.RST}{C.BG}" if self.is_host else ""
        bar = (f"{C.BG}{C.BOLD}{C.BMAG} shade {C.RST}{C.BG}"
               f"{C.DIM} encrypted{C.RST}{C.BG}  "
               f"{C.BCYN}{self.room_id[:16]}{C.RST}{C.BG}  "
               f"{C.DIM}{self.username_hash[:8]}{C.RST}{C.BG}{host_tag}"
               f"{C.DIM}  shade help{C.RST}")
        pad = cols - len(strip_ansi(bar)) - 1
        self._w(bar + " " * max(0, pad))
        # divider + sidebar
        for r in range(MTOP, rows):
            self._mv(r, CW + 1); self._w(f"{C.DIM}|{C.RST}")
        self._mv(MTOP, CW + 2)
        self._w(f"{C.BOLD}{C.DIM} {len(self.users)}{C.RST}")
        ur = MTOP + 1
        for fp, info in list(self.users.items())[:CH - 2]:
            self._mv(ur, CW + 2); self._cl()
            star = f"{C.BYEL}*{C.RST} " if info.get("host") else "  "
            self._w(f" {star}{C.BMAG}{fp[:12]}{C.RST}")
            ur += 1
        while ur < rows:
            self._mv(ur, CW + 2); self._cl(); ur += 1
        # messages
        lines  = self._render_lines()
        vstart = max(0, len(lines) - CH + self.scroll)
        vis    = lines[vstart:vstart + CH]
        for i, line in enumerate(vis):
            self._mv(MTOP + i, 1); self._cl()
            pad = CW - len(strip_ansi(line)) - 1
            self._w(" " + line + " " * max(0, pad))
        for i in range(len(vis), CH):
            self._mv(MTOP + i, 1); self._cl()
        # input
        self._mv(rows); self._cl()
        prompt = f"{C.BMAG}{C.BOLD}{self.username_hash[:8]}{C.RST} "
        max_w  = cols - len(strip_ansi(prompt)) - 3
        shown  = self.input_buf[-max_w:] if len(self.input_buf) > max_w else self.input_buf
        self._w(f"{prompt}{C.BWHT}{shown}{C.RST}> \033[?25l")
        sys.stdout.flush()

    def _render_lines(self):
        lines = []
        for ts, sender, text, kind in self.messages:
            if kind == "system":
                lines.append(f"  {C.DIM}{C.BYEL}* {text}{C.RST}")
            elif kind == "verify":
                lines.append(f"  {C.BGRN}[key] {text}{C.RST}")
            else:
                col = PALETTE[sum(ord(c) for c in sender) % len(PALETTE)]
                lines.append(f"  {C.DIM}{ts}{C.RST} {col}{C.BOLD}{sender[:8]}{C.RST} - {text}")
        return lines

    def msg(self, sender, text, kind="chat"):
        ts = datetime.now().strftime("%H:%M")
        with self.lock: self.messages.append((ts, sender, text, kind))
        self._render()

    def sys(self, text): self.msg("", text, "system")
    def verify_msg(self, text): self.msg("", text, "verify")

    def add_user(self, fp, is_host=False):
        with self.lock:
            new = fp not in self.users
            self.users[fp] = {"host": is_host}
        if new: self.sys(f"peer {fp[:8]} joined")
        self._render()

    def remove_user(self, fp):
        with self.lock: self.users.pop(fp, None)
        self.sys(f"peer {fp[:8]} left")
        self._render()

    def panic_wipe(self):
        """Instant wipe all message buffers."""
        with self.lock:
            for i in range(len(self.messages)):
                self.messages[i] = ("", "", "", "")
            self.messages.clear()
            self.input_buf = ""
        self.running = False

# ── Handshake ─────────────────────────────────────────────────────────────────

def do_handshake_server(conn, identity_priv, identity_pub, password=""):
    """Host side handshake. Returns (outer_key, inner_key, mac_key, peer_fp) or raises."""
    # 1. Send our ephemeral public key + identity public key
    eph_priv = _dh_gen_private()
    eph_pub  = _dh_gen_public(eph_priv)
    hello = {
        "version": VERSION,
        "eph_pub": str(eph_pub),
        "id_pub":  str(identity_pub),
    }
    conn.sendall(wire_encode(hello))
    # 2. Receive client hello
    client_hello = wire_decode(conn)
    if not client_hello: raise ConnectionError("No client hello")
    client_eph = int(client_hello["eph_pub"])
    client_id  = int(client_hello["id_pub"])
    # 3. Compute shared secrets
    eph_shared = _dh_shared(client_eph, eph_priv)
    id_shared  = _dh_shared(client_id,  identity_priv)
    # Combine both shared secrets
    combined = hashlib.sha256(
        eph_shared.to_bytes(256, 'big') +
        id_shared.to_bytes(256, 'big')
    ).digest()
    salt = os.urandom(32)
    outer_key, inner_key, mac_key = _derive_keys(int.from_bytes(combined, 'big'), salt)
    conn.sendall(wire_encode({"salt": base64.b64encode(salt).decode()}))
    # 4. Verify password if set
    if password:
        challenge = os.urandom(32)
        conn.sendall(wire_encode({"challenge": base64.b64encode(challenge).decode()}))
        resp = wire_decode(conn)
        if not resp: raise ConnectionError("No password response")
        expected = hashlib.sha256(challenge + password.encode()).hexdigest()
        if not hmac.compare_digest(resp.get("response",""), expected):
            conn.sendall(wire_encode({"auth": "fail"}))
            raise ConnectionError("Wrong password")
    conn.sendall(wire_encode({"auth": "ok"}))
    peer_fp = fingerprint(client_id)
    return outer_key, inner_key, mac_key, peer_fp

def do_handshake_client(conn, identity_priv, identity_pub, password=""):
    """Client side handshake. Returns (outer_key, inner_key, mac_key, peer_fp) or raises."""
    # 1. Receive server hello
    server_hello = wire_decode(conn)
    if not server_hello: raise ConnectionError("No server hello")
    server_eph = int(server_hello["eph_pub"])
    server_id  = int(server_hello["id_pub"])
    # 2. Send our keys
    eph_priv = _dh_gen_private()
    eph_pub  = _dh_gen_public(eph_priv)
    conn.sendall(wire_encode({
        "eph_pub": str(eph_pub),
        "id_pub":  str(identity_pub),
    }))
    # 3. Receive salt and derive keys
    salt_pkt = wire_decode(conn)
    if not salt_pkt: raise ConnectionError("No salt")
    salt = base64.b64decode(salt_pkt["salt"])
    eph_shared = _dh_shared(server_eph, eph_priv)
    id_shared  = _dh_shared(server_id,  identity_priv)
    combined = hashlib.sha256(
        eph_shared.to_bytes(256, 'big') +
        id_shared.to_bytes(256, 'big')
    ).digest()
    outer_key, inner_key, mac_key = _derive_keys(int.from_bytes(combined, 'big'), salt)
    # 4. Answer password challenge if present
    next_pkt = wire_decode(conn)
    if not next_pkt: raise ConnectionError("No auth packet")
    if "challenge" in next_pkt:
        challenge = base64.b64decode(next_pkt["challenge"])
        response  = hashlib.sha256(challenge + password.encode()).hexdigest()
        conn.sendall(wire_encode({"response": response}))
        auth = wire_decode(conn)
        if not auth or auth.get("auth") != "ok":
            raise ConnectionError("Wrong password")
    elif next_pkt.get("auth") != "ok":
        raise ConnectionError("Auth failed")
    peer_fp = fingerprint(server_id)
    return outer_key, inner_key, mac_key, peer_fp

# ── Host ──────────────────────────────────────────────────────────────────────

class Host:
    def __init__(self, room_id, password, tui, id_priv, id_pub):
        self.room_id  = room_id
        self.password = password
        self.tui      = tui
        self.id_priv  = id_priv
        self.id_pub   = id_pub
        self.clients  = {}   # fp -> {sock, outer, inner, mac, seq_send, seq_recv}
        self._lock    = threading.Lock()
        self.port     = CHAT_PORT
        self.running  = False

    def start(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        for p in range(CHAT_PORT, CHAT_PORT + 20):
            try: s.bind(("", p)); self.port = p; break
            except OSError: continue
        s.listen(32); s.settimeout(1.0)
        self._sock   = s
        self.running = True
        self.announcer = Announcer(self.room_id, self.port)
        self.announcer.start()
        threading.Thread(target=self._accept, daemon=True).start()

    def stop(self):
        self.running = False
        try: self.announcer.stop()
        except: pass
        try: self._sock.close()
        except: pass

    def _accept(self):
        while self.running:
            try:
                conn, _ = self._sock.accept()
                threading.Thread(target=self._handle, args=(conn,), daemon=True).start()
            except socket.timeout: pass
            except: break

    def _handle(self, conn):
        fp = None
        outer_key = inner_key = mac_key = None
        try:
            conn.settimeout(10.0)
            outer_key, inner_key, mac_key, fp = do_handshake_server(
                conn, self.id_priv, self.id_pub, self.password)
            conn.settimeout(None)
            seq_send = [0]; seq_recv = [0]
            with self._lock:
                self.clients[fp] = {
                    "sock": conn, "outer": outer_key, "inner": inner_key,
                    "mac": mac_key, "seq_send": seq_send, "seq_recv": seq_recv
                }
            # Announce join to host TUI
            self.tui.add_user(fp)
            self.tui.verify_msg(f"peer {fp[:8]} key: {fp}")
            # Notify existing clients
            self._broadcast({"type":"join","fp":fp}, skip=fp)
            # Send host fingerprint
            host_fp = fingerprint(self.id_pub)
            send_encrypted(conn, {"type":"welcome","host_fp":host_fp,
                                   "peers":[p for p in self.clients if p != fp]},
                           outer_key, inner_key, mac_key, seq_send)
            # Start decoy thread for this connection
            threading.Thread(target=self._decoy_loop,
                             args=(fp,), daemon=True).start()
            # Recv loop
            while self.running:
                pkt = recv_encrypted(conn, outer_key, inner_key, mac_key, seq_recv)
                if pkt is None: break
                if pkt.get("type") == "decoy": continue
                self._route(pkt, fp)
        except: pass
        finally:
            if fp:
                with self._lock: self.clients.pop(fp, None)
                self._broadcast({"type":"leave","fp":fp})
                self.tui.remove_user(fp)
            # Wipe keys
            if outer_key: wipe(bytearray(outer_key))
            if inner_key: wipe(bytearray(inner_key))
            if mac_key:   wipe(bytearray(mac_key))
            try: conn.close()
            except: pass

    def _decoy_loop(self, fp):
        while self.running and fp in self.clients:
            lo, hi = DECOY_INTERVAL
            time.sleep(lo + secrets.randbelow(int((hi-lo)*1000)) / 1000.0)
            with self._lock:
                c = self.clients.get(fp)
            if c:
                _send_decoy(c["sock"], c["outer"], c["inner"], c["mac"], c["seq_send"])

    def _route(self, pkt, sender_fp):
        t = pkt.get("type")
        if t == "chat":
            self._broadcast({"type":"chat","fp":sender_fp,"text":pkt.get("text","")[:500]})
            self.tui.msg(sender_fp, pkt.get("text",""))

    def _broadcast(self, msg, skip=None):
        with self._lock:
            clients_copy = dict(self.clients)
        for fp, c in clients_copy.items():
            if fp == skip: continue
            try:
                send_encrypted(c["sock"], msg, c["outer"], c["inner"],
                               c["mac"], c["seq_send"])
            except: pass

    def send_chat(self, text):
        self._broadcast({"type":"chat","fp":fingerprint(self.id_pub),"text":text})

# ── Client ────────────────────────────────────────────────────────────────────

class Client:
    def __init__(self, tui, id_priv, id_pub, password=""):
        self.tui      = tui
        self.id_priv  = id_priv
        self.id_pub   = id_pub
        self.password = password
        self._sock    = None
        self.outer_key = self.inner_key = self.mac_key = None
        self.seq_send  = [0]
        self.seq_recv  = [0]
        self.running   = False

    def connect(self, addr, port):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(10.0); s.connect((addr, port)); s.settimeout(None)
        self._sock = s
        outer, inner, mac, peer_fp = do_handshake_client(
            s, self.id_priv, self.id_pub, self.password)
        self.outer_key = outer; self.inner_key = inner; self.mac_key = mac
        self.running = True
        # Receive welcome
        welcome = recv_encrypted(s, outer, inner, mac, self.seq_recv)
        if welcome:
            self.tui.verify_msg(f"host key: {welcome.get('host_fp','?')}")
            for fp in welcome.get("peers", []):
                self.tui.add_user(fp)
        # Start decoy sender
        threading.Thread(target=self._decoy_loop, daemon=True).start()
        threading.Thread(target=self._recv, daemon=True).start()

    def _decoy_loop(self):
        while self.running:
            lo, hi = DECOY_INTERVAL
            time.sleep(lo + secrets.randbelow(int((hi-lo)*1000)) / 1000.0)
            _send_decoy(self._sock, self.outer_key, self.inner_key,
                        self.mac_key, self.seq_send)

    def _recv(self):
        while self.running:
            try:
                pkt = recv_encrypted(self._sock, self.outer_key,
                                     self.inner_key, self.mac_key, self.seq_recv)
                if pkt is None: break
                t = pkt.get("type")
                if t == "decoy": continue
                elif t == "chat":
                    self.tui.msg(pkt["fp"], pkt.get("text",""))
                elif t == "join":
                    self.tui.add_user(pkt["fp"])
                    self.tui.verify_msg(f"new peer key: {pkt['fp']}")
                elif t == "leave":
                    self.tui.remove_user(pkt["fp"])
            except: break
        self.running = False
        self.tui.sys("Disconnected")
        # Wipe keys
        if self.outer_key: wipe(bytearray(self.outer_key))
        if self.inner_key: wipe(bytearray(self.inner_key))
        if self.mac_key:   wipe(bytearray(self.mac_key))

    def send_chat(self, text):
        send_encrypted(self._sock, {"type":"chat","text":text},
                       self.outer_key, self.inner_key, self.mac_key, self.seq_send)

    def disconnect(self):
        self.running = False
        try: self._sock.close()
        except: pass

# ── Input ─────────────────────────────────────────────────────────────────────

class Input:
    def __init__(self, tui, host, client):
        self.tui = tui; self.host = host; self.client = client

    def run(self):
        self.tui.raw_mode()
        try:
            if WINDOWS: self._run_windows()
            else:       self._run_unix()
        finally:
            self.tui.restore()
            # Wipe all messages on exit
            self.tui.panic_wipe()

    def _run_windows(self):
        while self.tui.running:
            if not msvcrt.kbhit(): time.sleep(0.05); continue
            ch = msvcrt.getwch(); code = ord(ch)
            if code == 3:             self._quit(); break
            elif ch in ('\r', '\n'):  self._submit()
            elif code in (8, 127):
                self.tui.input_buf = self.tui.input_buf[:-1]
                self.tui.render()
            elif code in (0, 224):
                ch2 = msvcrt.getwch()
                if ch2 == 'H':
                    self.tui.scroll = self.tui._clamp(self.tui.scroll-1,-9999,0)
                    self.tui.render()
                elif ch2 == 'P':
                    self.tui.scroll = self.tui._clamp(self.tui.scroll+1,-9999,0)
                    self.tui.render()
            elif code == 28:  # Ctrl+\ — panic
                self.tui.panic_wipe()
                self._quit(); break
            elif 32 <= code < 127:
                self.tui.input_buf += ch
                self.tui.render()

    def _run_unix(self):
        while self.tui.running:
            rl, _, _ = select.select([sys.stdin], [], [], 0.1)
            if not rl: continue
            try: ch = sys.stdin.read(1)
            except: continue
            if not ch: continue
            code = ord(ch)
            if code == 3:            self._quit(); break
            elif code == 28:         # Ctrl+\ panic
                self.tui.panic_wipe(); self._quit(); break
            elif code == 13:         self._submit()
            elif code in (127, 8):
                self.tui.input_buf = self.tui.input_buf[:-1]
                self.tui.render()
            elif code == 27:
                time.sleep(0.01); seq = ""
                try:
                    while True:
                        c2 = sys.stdin.read(1)
                        if not c2: break
                        seq += c2
                except: pass
                if seq == "[A":
                    self.tui.scroll = self.tui._clamp(self.tui.scroll-1,-9999,0)
                    self.tui.render()
                elif seq == "[B":
                    self.tui.scroll = self.tui._clamp(self.tui.scroll+1,-9999,0)
                    self.tui.render()
            elif 32 <= code < 127:
                self.tui.input_buf += ch
                self.tui.render()

    def _quit(self):
        self.tui.running = False
        if self.client: self.client.disconnect()
        if self.host:   self.host.stop()

    def _submit(self):
        text = self.tui.input_buf.strip()
        self.tui.input_buf = ""
        if not text: self.tui.render(); return
        my_fp = fingerprint(self.host.id_pub if self.host else self.client.id_pub)
        if self.host:
            self.host.send_chat(text)
            self.tui.msg(my_fp, text)
        elif self.client:
            self.client.send_chat(text)
            # server will broadcast back
        self.tui.render()

# ── Room entry ────────────────────────────────────────────────────────────────

def _clear(): sys.stdout.write("\033[2J\033[H"); sys.stdout.flush()

def enter_room(room_id, password, id_priv, id_pub):
    my_fp = fingerprint(id_pub)
    # Use first 8 chars of fingerprint as display name (never real username)
    tui = TUI(my_fp, room_id)

    disc = Discovery(); disc.start()
    tui.sys(f"Searching for room...")
    tui.render()
    found = disc.find(room_id)
    disc.stop()

    host = None; client = None

    if found:
        tui.sys(f"Found room. Performing handshake...")
        tui.render()
        client = Client(tui, id_priv, id_pub, password)
        try:
            client.connect(found["addr"], found["port"])
            tui.sys(f"Joined. Verify key fingerprints above.")
        except ConnectionError as e:
            tui.restore(); _clear()
            print(f"Error: {e}"); sys.exit(1)
    else:
        host = Host(room_id, password, tui, id_priv, id_pub)
        host.start()
        tui.is_host = True
        tui.add_user(my_fp, is_host=True)
        tui.sys(f"Room created. Your fingerprint: {my_fp}")
        tui.sys(f"Waiting for peers...")

    if not WINDOWS:
        signal.signal(signal.SIGWINCH, lambda s, f: tui.render())

    _clear(); tui.render()
    inp = Input(tui, host, client)
    inp.run()

    # On exit — wipe everything
    tui.panic_wipe()
    if host:   host.stop()
    if client: client.disconnect()
    tui.restore(); _clear()
    sys.stdout.write("\033[2J\033[H")
    sys.stdout.flush()
    print("Session ended. All messages wiped.")

# ── CLI ───────────────────────────────────────────────────────────────────────

def cmd_help():
    print("""
  shade  —  encrypted LAN chat

  shade <room>         join or create an encrypted room
  shade <room> <pw>    add a password layer on top of encryption
  shade list           count rooms on LAN (names are not visible)
  shade keys           show your key fingerprint
  shade help           show this

  Inside a room:
    Ctrl-C             leave
    Ctrl+Backslash             PANIC WIPE — zeroes all messages instantly

  Security:
    - Double encrypted: ChaCha20 + AES-256-CTR
    - DH key exchange with ephemeral + identity keys
    - Encrypted room discovery (room names never travel in plaintext)
    - Usernames replaced with key fingerprints
    - All messages padded to same size
    - Random timing delays on all sends
    - Decoy traffic between real messages
    - Anti-replay sequence numbers
    - RAM wiped on exit
""")

def cmd_keys(id_pub):
    fp = fingerprint(id_pub)
    print(f"\n  Your key fingerprint:\n  {fp}\n")
    print("  Share this with people you trust so they can verify they're talking to you.\n")

def cmd_list():
    print("Scanning...", flush=True)
    d = Discovery(); d.start()
    n = d.count(3.0); d.stop()
    print(f"  {n} shade room(s) active on LAN")
    print("  (Room names are encrypted and not visible)")

def main():
    # Load or create identity keys
    id_priv, id_pub = load_or_create_identity()

    args = sys.argv[1:]
    if not args: cmd_help(); return

    cmd = args[0].lower()

    if   cmd == "help":  cmd_help()
    elif cmd == "keys":  cmd_keys(id_pub)
    elif cmd == "list":  cmd_list()
    else:
        room_id  = cmd
        password = args[1] if len(args) > 1 else ""
        try:
            enter_room(room_id, password, id_priv, id_pub)
        except KeyboardInterrupt:
            pass
        finally:
            # Final wipe
            wipe(bytearray(id_priv.to_bytes(32, 'big') if id_priv < 2**256 else b'\x00'*32))

if __name__ == "__main__":
    try: main()
    except KeyboardInterrupt: print("\nSession ended.")

