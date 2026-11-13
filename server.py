#!/usr/bin/env python3
"""
ZKP Lab — serveur de preuves de Schnorr VOLONTAIREMENT vulnérable.

Usage pédagogique uniquement : la cryptographie est cassée exprès
(groupe trop petit, nonce réutilisé, nonce prévisible). La couche web,
elle, essaie d'être propre.

Aucune dépendance : Python >= 3.8, bibliothèque standard uniquement.

    python3 server.py --host 0.0.0.0 --port 8080
"""
import argparse
import hashlib
import hmac
import json
import os
import re
import secrets
import sys
import threading
import time
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

BASE = Path(__file__).resolve().parent
STATIC = BASE / "static"

STATIC_FILES = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/index.html": ("index.html", "text/html; charset=utf-8"),
    "/style.css": ("style.css", "text/css; charset=utf-8"),
    "/app.js": ("app.js", "application/javascript; charset=utf-8"),
    "/admin": ("admin.html", "text/html; charset=utf-8"),
    "/admin.html": ("admin.html", "text/html; charset=utf-8"),
    "/admin.js": ("admin.js", "application/javascript; charset=utf-8"),
}

MAX_BODY = 16 * 1024
MAX_INT_BITS = 4096
NAME_RE = re.compile(r"[A-Za-z0-9_\-. À-ÖØ-öø-ÿ]{2,24}")
POINTS = {1: 100, 2: 200, 3: 300}
LEVELS = (1, 2, 3)

# Groupe MODP 2048 bits de la RFC 3526 (safe prime, g = 2 d'ordre q = (p-1)/2).
RFC3526_P = int(
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
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF",
    16,
)
RFC3526_Q = (RFC3526_P - 1) // 2
RFC3526_G = 2

# Niveau 3 : constantes du LCG (celles de MMIX, Knuth). Elles sont publiques.
LCG_A = 6364136223846793005
LCG_B = 1442695040888963407


class ApiError(Exception):
    def __init__(self, code, msg):
        super().__init__(msg)
        self.code = code
        self.msg = msg


# --------------------------------------------------------------------------
# Arithmétique
# --------------------------------------------------------------------------

def is_probable_prime(n, rounds=40):
    if n < 2:
        return False
    for sp in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if n % sp == 0:
            return n == sp
    d, s = n - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for _ in range(rounds):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


def gen_safe_prime(bits):
    """Renvoie (p, q) avec p = 2q + 1, p de `bits` bits, p et q premiers."""
    while True:
        q = secrets.randbits(bits - 1) | (1 << (bits - 2)) | 1
        if is_probable_prime(q, 25) and is_probable_prime(2 * q + 1, 25):
            return 2 * q + 1, q


def parse_int(value, field):
    if isinstance(value, bool):
        raise ApiError(400, f"« {field} » doit être un entier.")
    if isinstance(value, int):
        n = value
    elif isinstance(value, str):
        v = value.strip().replace(" ", "").replace("_", "")
        if len(v) > MAX_INT_BITS:  # garde-fou avant int() : 4096 chiffres max
            raise ApiError(400, f"« {field} » est trop long.")
        try:
            neg = v.startswith("-")
            body = v[1:] if neg else v
            n = int(body, 16) if body.lower().startswith("0x") else int(body, 10)
            if neg:
                n = -n
        except ValueError:
            raise ApiError(400, f"« {field} » doit être un entier (décimal ou 0x…).")
    else:
        raise ApiError(400, f"« {field} » doit être un entier.")
    if n.bit_length() > MAX_INT_BITS:
        raise ApiError(400, f"« {field} » dépasse {MAX_INT_BITS} bits.")
    return n


# --------------------------------------------------------------------------
# État persistant
# --------------------------------------------------------------------------

class Store:
    def __init__(self, path, small_bits):
        self.lock = threading.RLock()
        self.path = path
        self.small_bits = small_bits
        self.pending = {}  # (pseudo, niveau) -> nonce en attente de défi
        if path.exists():
            self.data = json.loads(path.read_text(encoding="utf-8"))
        else:
            self.data = self._fresh()
            self.save()

    def _fresh(self):
        p1, q1 = gen_safe_prime(self.small_bits)
        while True:
            g1 = pow(secrets.randbelow(p1 - 3) + 2, 2, p1)  # un carré : ordre q1
            if g1 != 1:
                break
        return {
            "secret": secrets.token_hex(32),
            "small_group": {"p": p1, "q": q1, "g": g1},
            "players": {},
            "tokens": {},
            "created": time.time(),
        }

    def save(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.data), encoding="utf-8")
        os.replace(tmp, self.path)

    def reset(self, everything):
        with self.lock:
            self.pending.clear()
            if everything:
                self.data = self._fresh()
            else:
                self.data["players"] = {}
                self.data["tokens"] = {}
            self.save()


store = None  # initialisé dans main()
ADMIN_TOKEN = ""


def group(level):
    if level == 1:
        sg = store.data["small_group"]
        return sg["p"], sg["q"], sg["g"]
    return RFC3526_P, RFC3526_Q, RFC3526_G


def derive(label, name, mod):
    """Entier pseudo-aléatoire dans [1, mod-1], déterministe par (secret, label, pseudo)."""
    secret = bytes.fromhex(store.data["secret"])
    nbytes = (mod.bit_length() + 64 + 7) // 8
    out, i = b"", 0
    while len(out) < nbytes:
        out += hmac.new(secret, f"{label}|{name}|{i}".encode(), hashlib.sha256).digest()
        i += 1
    return int.from_bytes(out[:nbytes], "big") % (mod - 1) + 1


def private_key(level, name):
    return derive(f"key{level}", name, group(level)[1])


def public_key(level, name):
    p, _, g = group(level)
    return pow(g, private_key(level, name), p)


def fs_challenge(g, y, t, message, q):
    h = hashlib.sha256(f"{g}|{y}|{t}|{message}".encode()).hexdigest()
    return int(h, 16) % q


def parse_level(value, allowed=LEVELS):
    try:
        level = int(value)
    except (TypeError, ValueError):
        raise ApiError(400, "Niveau invalide.")
    if level not in allowed:
        raise ApiError(400, "Niveau invalide.")
    return level


# --------------------------------------------------------------------------
# Routes
# --------------------------------------------------------------------------

def r_register(req):
    body = req.body()
    name = str(body.get("name", "")).strip()
    if not NAME_RE.fullmatch(name):
        raise ApiError(400, "Pseudo invalide : 2 à 24 caractères (lettres, chiffres, espace, - _ .).")
    with store.lock:
        if any(n.lower() == name.lower() for n in store.data["players"]):
            raise ApiError(409, "Ce pseudo est déjà pris.")
        if len(store.data["players"]) >= 500:
            raise ApiError(403, "Trop de joueurs inscrits.")
        token = secrets.token_urlsafe(24)
        store.data["players"][name] = {
            "created": time.time(),
            "solved": {},
            "attempts": {},
            "l3": None,
        }
        store.data["tokens"][token] = name
        store.save()
    return {"token": token, "name": name}


def r_me(req):
    name = req.player()
    with store.lock:
        pl = store.data["players"][name]
        levels = {}
        for lv in LEVELS:
            p, q, g = group(lv)
            levels[str(lv)] = {
                "p": str(p), "q": str(q), "g": str(g),
                "y": str(public_key(lv, name)),
                "points": POINTS[lv],
            }
        levels["3"]["lcg"] = {"A": str(LCG_A), "B": str(LCG_B)}
        return {
            "name": name,
            "solved": pl["solved"],
            "attempts": pl["attempts"],
            "levels": levels,
        }


def r_commit(req):
    name = req.player()
    level = parse_level(req.body().get("level"), (1, 2))
    p, q, g = group(level)
    if level == 1:
        r = secrets.randbelow(q - 1) + 1  # prouveur honnête : nonce frais
    else:
        # « Optimisation » : on calcule le nonce une fois pour toutes par
        # utilisateur, ça évite d'appeler le RNG à chaque preuve…   <-- LA FAILLE
        r = derive("l2nonce", name, q)
    with store.lock:
        store.pending[(name, level)] = r
    return {"level": level, "t": str(pow(g, r, p))}


def r_respond(req):
    name = req.player()
    body = req.body()
    level = parse_level(body.get("level"), (1, 2))
    c = parse_int(body.get("c"), "c")
    if c < 0:
        raise ApiError(400, "Le défi c doit être positif.")
    with store.lock:
        r = store.pending.pop((name, level), None)
    if r is None:
        raise ApiError(409, "Demandez d'abord un engagement (étape 1).")
    _, q, _ = group(level)
    s = (r + c * private_key(level, name)) % q
    return {"level": level, "c": str(c), "s": str(s)}


def r_l3_proofs(req):
    name = req.player()
    p, q, g = group(3)
    x = private_key(3, name)
    y = pow(g, x, p)
    proofs = []
    with store.lock:
        pl = store.data["players"][name]
        st = pl.get("l3") or {"n": 0, "r": derive("l3seed", name, q)}
        if st["n"] >= 1000:
            raise ApiError(429, "Assez de preuves pour aujourd'hui (1000 max).")
        for _ in range(2):
            r, n = st["r"], st["n"]
            t = pow(g, r, p)
            message = f"preuve #{n} pour {name}"
            c = fs_challenge(g, y, t, message, q)
            s = (r + c * x) % q
            proofs.append({"index": n, "message": message,
                           "t": str(t), "c": str(c), "s": str(s)})
            st = {"n": n + 1, "r": (LCG_A * r + LCG_B) % q}
        pl["l3"] = st
        store.save()
    return {"proofs": proofs}


def r_submit(req):
    name = req.player()
    body = req.body()
    level = parse_level(body.get("level"))
    x = parse_int(body.get("x"), "x")
    p, q, g = group(level)
    ok = pow(g, x % q, p) == public_key(level, name)
    key = str(level)
    with store.lock:
        pl = store.data["players"][name]
        pl["attempts"][key] = pl["attempts"].get(key, 0) + 1
        first = False
        if ok and key not in pl["solved"]:
            pl["solved"][key] = time.time()
            first = True
        store.save()
    if not ok:
        return {"ok": False, "message": "Raté : g^x mod p ne donne pas y."}
    msg = f"Bravo ! Niveau {level} résolu (+{POINTS[level]} pts)." if first \
        else "Correct (niveau déjà résolu)."
    return {"ok": True, "message": msg}


def r_scoreboard(req):
    with store.lock:
        players = store.data["players"]
        first_blood = {}
        for lv in LEVELS:
            k = str(lv)
            best = min(((pl["solved"][k], n) for n, pl in players.items() if k in pl["solved"]),
                       default=None)
            if best:
                first_blood[k] = best[1]
        rows = []
        for n, pl in players.items():
            solved = pl["solved"]
            rows.append({
                "name": n,
                "points": sum(POINTS[int(k)] for k in solved),
                "solved": sorted(int(k) for k in solved),
                "last": max(solved.values()) if solved else None,
            })
    rows.sort(key=lambda r: (-r["points"], r["last"] or float("inf"), r["name"].lower()))
    return {"players": rows, "first_blood": first_blood}


def r_admin_state(req):
    req.admin()
    with store.lock:
        sg = store.data["small_group"]
        out = []
        for n, pl in store.data["players"].items():
            out.append({
                "name": n,
                "created": pl["created"],
                "solved": pl["solved"],
                "attempts": pl["attempts"],
                "l3_proofs": (pl.get("l3") or {}).get("n", 0),
                "keys": {str(lv): str(private_key(lv, n)) for lv in LEVELS},
            })
        tokens = {v: k for k, v in store.data["tokens"].items()}
        for row in out:
            row["token"] = tokens.get(row["name"], "")
        return {
            "small_group": {k: str(v) for k, v in sg.items()},
            "small_bits": sg["p"].bit_length(),
            "players": out,
        }


def r_admin_reset(req):
    req.admin()
    what = req.body().get("what")
    if what not in ("players", "all"):
        raise ApiError(400, "what doit valoir « players » ou « all ».")
    store.reset(everything=(what == "all"))
    return {"ok": True}


def r_admin_delete(req):
    req.admin()
    name = str(req.body().get("name", ""))
    with store.lock:
        if name not in store.data["players"]:
            raise ApiError(404, "Joueur inconnu.")
        del store.data["players"][name]
        store.data["tokens"] = {t: n for t, n in store.data["tokens"].items() if n != name}
        for k in [k for k in store.pending if k[0] == name]:
            del store.pending[k]
        store.save()
    return {"ok": True}


ROUTES = {
    ("POST", "/api/register"): r_register,
    ("GET", "/api/me"): r_me,
    ("POST", "/api/commit"): r_commit,
    ("POST", "/api/respond"): r_respond,
    ("POST", "/api/l3/proofs"): r_l3_proofs,
    ("POST", "/api/submit"): r_submit,
    ("GET", "/api/scoreboard"): r_scoreboard,
    ("GET", "/api/admin/state"): r_admin_state,
    ("POST", "/api/admin/reset"): r_admin_reset,
    ("POST", "/api/admin/delete"): r_admin_delete,
}


# --------------------------------------------------------------------------
# HTTP
# --------------------------------------------------------------------------

class Handler(BaseHTTPRequestHandler):
    server_version = "ZKPLab/1.0"
    sys_version = ""
    protocol_version = "HTTP/1.1"

    def _send(self, code, payload, ctype):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self'; style-src 'self'; "
            "img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'",
        )
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(payload)

    def _json(self, code, obj):
        self._send(code, json.dumps(obj, ensure_ascii=False).encode("utf-8"),
                   "application/json; charset=utf-8")

    # --- helpers utilisés par les routes ---
    def body(self):
        if hasattr(self, "_body_cache"):
            return self._body_cache
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            raise ApiError(400, "Content-Length invalide.")
        if length > MAX_BODY:
            raise ApiError(413, "Requête trop volumineuse.")
        raw = self.rfile.read(length) if length else b""
        try:
            data = json.loads(raw.decode("utf-8")) if raw else {}
        except (ValueError, UnicodeDecodeError):
            raise ApiError(400, "JSON invalide.")
        if not isinstance(data, dict):
            raise ApiError(400, "Un objet JSON est attendu.")
        self._body_cache = data
        return data

    def player(self):
        token = self.headers.get("X-Token", "")
        with store.lock:
            name = store.data["tokens"].get(token) if token else None
        if not name:
            raise ApiError(401, "Jeton manquant ou invalide : inscrivez-vous.")
        return name

    def admin(self):
        token = self.headers.get("X-Admin-Token", "")
        if not token or not hmac.compare_digest(token.encode(), ADMIN_TOKEN.encode()):
            raise ApiError(401, "Jeton administrateur invalide.")

    # --- dispatch ---
    def _dispatch(self, method):
        path = urlparse(self.path).path
        if method in ("GET", "HEAD") and path in STATIC_FILES:
            fname, ctype = STATIC_FILES[path]
            try:
                payload = (STATIC / fname).read_bytes()
            except OSError:
                return self._json(404, {"error": "Introuvable."})
            return self._send(200, payload, ctype)
        route = ROUTES.get(("GET" if method == "HEAD" else method, path))
        if route is None:
            if method == "POST":
                self.body()  # vider le corps pour garder la connexion saine
            return self._json(404, {"error": "Introuvable."})
        try:
            self._json(200, route(self))
        except ApiError as e:
            self._json(e.code, {"error": e.msg})
        except Exception:
            traceback.print_exc()
            self._json(500, {"error": "Erreur interne."})

    def do_GET(self):
        self._dispatch("GET")

    def do_HEAD(self):
        self._dispatch("HEAD")

    def do_POST(self):
        try:
            self._dispatch("POST")
        except ApiError as e:
            self._json(e.code, {"error": e.msg})


def main():
    global store, ADMIN_TOKEN
    ap = argparse.ArgumentParser(description="ZKP Lab — serveur volontairement vulnérable")
    ap.add_argument("--host", default=os.environ.get("ZKP_HOST", "0.0.0.0"))
    ap.add_argument("--port", type=int, default=int(os.environ.get("ZKP_PORT", "8080")))
    ap.add_argument("--state", default=os.environ.get("ZKP_STATE", str(BASE / "data" / "state.json")))
    ap.add_argument("--small-bits", type=int, default=int(os.environ.get("ZKP_SMALL_BITS", "22")),
                    help="taille de p au niveau 1 (appliquée seulement à la création de l'état)")
    args = ap.parse_args()

    if not 16 <= args.small_bits <= 64:
        sys.exit("--small-bits doit être entre 16 et 64.")
    assert is_probable_prime(RFC3526_P, 8) and is_probable_prime(RFC3526_Q, 8), "RFC 3526 corrompu"
    assert pow(RFC3526_G, RFC3526_Q, RFC3526_P) == 1

    store = Store(Path(args.state), args.small_bits)
    ADMIN_TOKEN = os.environ.get("ZKP_ADMIN_TOKEN") or secrets.token_urlsafe(18)

    sg = store.data["small_group"]
    print(f"[zkp-lab] niveau 1 : p de {sg['p'].bit_length()} bits", flush=True)
    print(f"[zkp-lab] jeton admin : {ADMIN_TOKEN}", flush=True)
    print(f"[zkp-lab] écoute sur http://{args.host}:{args.port}  (admin : /admin)", flush=True)
    srv = ThreadingHTTPServer((args.host, args.port), Handler)
    srv.daemon_threads = True
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
