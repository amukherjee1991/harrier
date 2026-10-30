"""Accounts, sessions and sign-in history.

- Passwords: Argon2id (argon2-cffi defaults), rehashed automatically when parameters change.
- Sessions: a random token in an HttpOnly cookie; only its SHA-256 is stored, so a database leak
  doesn't leak sessions. Every session can be listed and revoked.
- Brute force: an account locks for 15 minutes after 5 wrong passwords, and an address with 20
  failures in 15 minutes is refused outright. Failed sign-ins also become Harrier signals, so
  someone guessing dashboard passwords from outside gets blocked like any other attacker.
- Roles: admin (everything) and viewer (read-only).
"""
import hashlib
import re
import secrets
import time

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

ROLES = ("admin", "viewer")
MAX_FAILS, LOCK_SECONDS = 5, 15 * 60
IP_WINDOW, IP_MAX_FAILS = 15 * 60, 20
SESSION_LONG, SESSION_SHORT = 30 * 86400, 12 * 3600
MIN_PASSWORD = 10
USERNAME = re.compile(r"^[A-Za-z0-9_.@-]{2,40}$")
PALETTES = ("harbor", "ocean", "forest", "graphite")

ph = PasswordHasher()
_DUMMY = ph.hash("equalise timing for unknown usernames")


class AuthError(ValueError):
    pass


def token_hash(token):
    return hashlib.sha256(token.encode()).hexdigest()


def check_password_rules(password, username=""):
    if len(password) < MIN_PASSWORD:
        raise AuthError(f"Use at least {MIN_PASSWORD} characters.")
    if username and password.lower() == username.lower():
        raise AuthError("The password can't be the username.")


def create_user(db, username, password, role="viewer", must_change=False):
    username = username.strip()
    if not USERNAME.match(username):
        raise AuthError("Usernames are 2-40 letters, digits, or . _ - @")
    if role not in ROLES:
        raise AuthError("Unknown role.")
    check_password_rules(password, username)
    if db.execute("select 1 from users where lower(username) = lower(?)", (username,)).fetchone():
        raise AuthError("That username is taken.")
    return db.execute("insert into users (username, password_hash, role, created_at, must_change_password) "
                      "values (?, ?, ?, ?, ?) returning id",
                      (username, ph.hash(password), role, time.time(), 1 if must_change else 0)).fetchone()[0]


def set_password(db, user_id, password, must_change=False):
    u = db.execute("select username from users where id = ?", (user_id,)).fetchone()
    check_password_rules(password, u["username"] if u else "")
    db.execute("update users set password_hash = ?, must_change_password = ?, failed_count = 0, locked_until = 0 "
               "where id = ?", (ph.hash(password), 1 if must_change else 0, user_id))


def temporary_password():
    return secrets.token_urlsafe(12)


def record(db, username, user_id, ip, ua, success, reason=""):
    db.execute("insert into login_events (at, username, user_id, ip, user_agent, success, reason) values (?, ?, ?, ?, ?, ?, ?)",
               (time.time(), (username or "")[:60], user_id, ip, (ua or "")[:300], 1 if success else 0, reason))


def authenticate(db, username, password, ip, ua, on_failure=None):
    """Returns the user row, or raises AuthError with a message safe to show."""
    now = time.time()
    fails = db.execute("select count(*) from login_events where ip = ? and success = 0 and at > ?",
                       (ip, now - IP_WINDOW)).fetchone()[0]
    if fails >= IP_MAX_FAILS:
        record(db, username, None, ip, ua, False, "too many attempts from this address")
        raise AuthError("Too many failed attempts from your address. Try again in 15 minutes.")
    u = db.execute("select * from users where lower(username) = lower(?)", ((username or "").strip(),)).fetchone()

    def fail(reason, uid=None):
        record(db, username, uid, ip, ua, False, reason)
        if on_failure:
            on_failure(username, reason)
        raise AuthError("Wrong username or password." if reason in ("unknown user", "wrong password") else
                        "This account is locked for 15 minutes after too many wrong passwords." if reason == "locked" else
                        "This account is disabled.")

    if not u:
        try:
            ph.verify(_DUMMY, password or "x")
        except VerificationError:
            pass
        fail("unknown user")
    if u["disabled"]:
        fail("disabled", u["id"])
    if u["locked_until"] and u["locked_until"] > now:
        fail("locked", u["id"])
    try:
        ph.verify(u["password_hash"], password or "")
    except (VerifyMismatchError, InvalidHashError, VerificationError):
        n = u["failed_count"] + 1
        db.execute("update users set failed_count = ?, locked_until = ? where id = ?",
                   (0 if n >= MAX_FAILS else n, now + LOCK_SECONDS if n >= MAX_FAILS else u["locked_until"], u["id"]))
        fail("locked" if n >= MAX_FAILS else "wrong password", u["id"])
    if ph.check_needs_rehash(u["password_hash"]):
        db.execute("update users set password_hash = ? where id = ?", (ph.hash(password), u["id"]))
    db.execute("update users set failed_count = 0, locked_until = 0, last_login_at = ? where id = ?", (now, u["id"]))
    record(db, u["username"], u["id"], ip, ua, True)
    return u


def start_session(db, user_id, ip, ua, remember):
    token = secrets.token_urlsafe(32)
    now = time.time()
    expires = now + (SESSION_LONG if remember else SESSION_SHORT)
    db.execute("insert into sessions (token_hash, user_id, created_at, last_seen_at, expires_at, ip, user_agent) "
               "values (?, ?, ?, ?, ?, ?, ?)", (token_hash(token), user_id, now, now, expires, ip, (ua or "")[:300]))
    return token, expires


def session_user(db, token):
    """The signed-in user for a cookie token, or None. Touches last_seen at most once a minute."""
    if not token or len(token) > 100:
        return None, None
    h = token_hash(token)
    r = db.execute("select s.token_hash, s.last_seen_at, s.expires_at, u.* from sessions s join users u on u.id = s.user_id "
                   "where s.token_hash = ? and s.revoked = 0 and s.expires_at > ? and u.disabled = 0", (h, time.time())).fetchone()
    if not r:
        return None, None
    if time.time() - r["last_seen_at"] > 60:
        db.execute("update sessions set last_seen_at = ? where token_hash = ?", (time.time(), h))
    return r, h


def revoke(db, user_id, session_id=None, keep=None):
    """Revoke one session (by its public id prefix) or all of a user's sessions except `keep`."""
    if session_id:
        db.execute("update sessions set revoked = 1 where user_id = ? and token_hash like ?", (user_id, f"{session_id}%"))
    else:
        db.execute("update sessions set revoked = 1 where user_id = ? and token_hash != ?", (user_id, keep or ""))


def ensure_admin(db, username, password):
    """First start: create the admin from the environment if there are no users at all."""
    if db.execute("select count(*) from users").fetchone()[0]:
        return False
    if not username or not password:
        return False
    create_user(db, username, password, "admin")
    return True


def admins_left(db, excluding=None):
    return db.execute("select count(*) from users where role = 'admin' and disabled = 0 and id != ?",
                      (excluding or -1,)).fetchone()[0]
