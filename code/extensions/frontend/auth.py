"""Portal logins for the web front end: demo accounts, password check and server-side sessions.

This is application-level login for the four portals (patient, doctor, hospital, admin). It is separate from the paper's
cryptographic access control, which system.py reproduces unchanged: a doctor still needs the patient's token and policy to read a
record, whatever portal they are signed in to.

Accounts come from demo_accounts.json. Passwords are hashed with PBKDF2-SHA256 (random salt) when the file is loaded and the
plaintext is dropped; sessions are random 256-bit ids held in memory and sent as an HttpOnly, SameSite=Strict cookie.
"""
import hashlib, hmac, json, os, pathlib, secrets, threading, time

HERE = pathlib.Path(__file__).resolve().parent
SEED = HERE / "demo_accounts.json"
ROLES = ("patient", "doctor", "hospital", "admin")
SESSION_TTL_S = 8 * 3600
ITER = 200_000
MAX_SESSIONS_PER_USER = 5
FAIL_WINDOW_S, FAIL_LIMIT_USER, LOCKOUT_S = 300, 5, 60


class Throttled(PermissionError):
    """Too many failed sign-ins: the caller must wait before trying again."""


def _article(word):
    return ("an " if word[:1] in "aeiou" else "a ") + word
PUBLIC_FIELDS = ("username", "role", "name", "hospital", "staff_role", "specialty", "avatar", "patient_index")


def _hash(password, salt):
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, ITER)


class Accounts:
    def __init__(self, path=SEED):
        data = json.loads(pathlib.Path(path).read_text(encoding="utf-8"))
        self.hospitals = data.get("hospitals", {})
        self.users, self.disabled, self.last_login = {}, set(), {}
        for a in data["accounts"]:
            if a["role"] not in ROLES: raise ValueError(f"bad role for {a['username']}")
            salt = os.urandom(16)
            u = {k: a.get(k) for k in PUBLIC_FIELDS}
            u.update(salt=salt, pw=_hash(a["password"], salt))          # plaintext is not kept
            self.users[a["username"].lower()] = u
        self._dummy = (os.urandom(16), os.urandom(32))
        self.sessions, self.lock = {}, threading.Lock()
        self.fails = {}                                           # key ("u:name" / "c:ip") -> [failure times]
        self.kicked = {}                                          # sid -> why it was ended (told once, then forgotten)

    # ------------------------------------------------------------------ passwords
    def check(self, username, password):
        """The account if the password matches, else None. Unknown users cost the same hash, so timing does not reveal them."""
        u = self.users.get((username or "").strip().lower())
        salt, pw = (u["salt"], u["pw"]) if u else self._dummy
        ok = hmac.compare_digest(_hash(password or "", salt), pw)
        return u if (u and ok) else None

    # ------------------------------------------------------------------ sessions
    def login(self, username, password, role, client="?"):
        """Per-account throttle only: every user of this local demo connects from 127.0.0.1, so a per-address limit let ~20 bad
        sign-ins lock everyone out (stress test). The attempt is reserved under the lock *before* hashing, so parallel guesses cannot
        all slip through while the first ~200 ms PBKDF2 runs."""
        now = time.time(); name = (username or "").strip().lower(); key = f"u:{name}"
        with self.lock:
            recent = [t for t in self.fails.get(key, []) if now - t < FAIL_WINDOW_S]
            if len(recent) >= FAIL_LIMIT_USER and now - recent[-1] < LOCKOUT_S:
                self.fails[key] = recent
                raise Throttled(f"too many failed sign-ins for this account: try again in {int(LOCKOUT_S - (now - recent[-1])) + 1} s")
            recent.append(now); self.fails[key] = recent              # reserved; removed again if the password is right
        u = self.check(username, password)
        if u is None: raise PermissionError("wrong username or password")
        with self.lock:
            lst = self.fails.get(key, [])
            if now in lst: lst.remove(now)
        if u["role"] != role:
            raise PermissionError(f"this is {_article(u['role'])} account: sign in on the {u['role']} portal")
        if u["username"] in self.disabled: raise PermissionError("this account is disabled by the administrator")
        sid = secrets.token_urlsafe(32)
        with self.lock:
            self.fails.pop(f"u:{name}", None)
            for k in [k for k, (_, exp) in self.sessions.items() if exp < now]: self.sessions.pop(k)   # purge expired
            mine = sorted((exp, k) for k, (n, exp) in self.sessions.items() if n == u["username"])
            for _, k in mine[:max(0, len(mine) - MAX_SESSIONS_PER_USER + 1)]: self.sessions.pop(k)    # keep the newest few
            self.sessions[sid] = (u["username"], now + SESSION_TTL_S)
            self.last_login[u["username"]] = now
        return sid, self.public(u)

    def user(self, sid):
        if not sid: return None
        with self.lock:
            s = self.sessions.get(sid)
            if s is None: return None
            name, exp = s
            if exp < time.time() or name in self.disabled:
                self.sessions.pop(sid, None); return None
        return self.users[name]

    def why_out(self, sid):
        with self.lock: return self.kicked.pop(sid, None) if sid else None

    def logout(self, sid):
        with self.lock: self.sessions.pop(sid, None)

    # ------------------------------------------------------------------ admin
    def set_disabled(self, username, disabled):
        u = self.users.get(username.lower())
        if u is None: raise KeyError(f"no account {username}")
        if u["role"] == "admin": raise ValueError("the admin account cannot be disabled")
        with self.lock:
            if disabled:
                self.disabled.add(u["username"])
                for sid in [k for k, (n, _) in self.sessions.items() if n == u["username"]]:
                    self.sessions.pop(sid); self.kicked[sid] = "your account was disabled by the administrator"
            else:
                self.disabled.discard(u["username"])
        return self.listing()

    def listing(self):
        now = time.time()
        with self.lock:
            active = {}
            for n, exp in self.sessions.values():
                if exp > now: active[n] = active.get(n, 0) + 1
        return [dict(self.public(u), disabled=u["username"] in self.disabled, sessions=active.get(u["username"], 0),
                     last_login=self.last_login.get(u["username"])) for u in self.users.values()]

    def public(self, u):
        out = {k: u.get(k) for k in PUBLIC_FIELDS}
        if u.get("hospital"): out["hospital_name"] = self.hospitals.get(u["hospital"], {}).get("name", u["hospital"])
        return out

    def usernames(self, role):
        return [u["username"] for u in self.users.values() if u["role"] == role]

    def staff(self, hospital):
        return [dict(self.public(u), disabled=u["username"] in self.disabled)
                for u in self.users.values() if u["role"] == "doctor" and u.get("hospital") == hospital]
