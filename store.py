"""OMIVIA local storage: accounts (JSON) and per-user upload folders on disk.

Prototype-grade. For production, move this behind a real database and an identity provider.
"""
import hashlib
import hmac
import json
import re
import secrets
import shutil
from datetime import datetime, timezone
from pathlib import Path

DATA = Path(__file__).resolve().parent / "data"
ACCOUNTS = DATA / "accounts.json"
TERMS_VERSION = "2026-10"
MIN_AGE = 18
AI_TRAINING_DEFAULT = True  # many regions require this to be opt-in (False). Change before launch if needed.


def _load():
    try:
        return json.loads(ACCOUNTS.read_text())
    except (FileNotFoundError, ValueError):
        return {}


def _save(db):
    DATA.mkdir(exist_ok=True)
    tmp = ACCOUNTS.with_suffix(".tmp")
    tmp.write_text(json.dumps(db, indent=2))
    tmp.replace(ACCOUNTS)


def _hash(pwd, salt):
    return hashlib.scrypt(pwd.encode(), salt=bytes.fromhex(salt), n=2 ** 14, r=8, p=1).hex()


def _public(email, rec):
    return {"email": email, "uid": rec["uid"], "name": rec["name"], "ai_training": rec["ai_training"]}


def create_account(email, name, pwd, ai_training):
    email, db = email.strip().lower(), _load()
    if email in db:
        raise ValueError("An account with this email already exists.")
    salt = secrets.token_hex(16)
    db[email] = dict(uid=secrets.token_hex(8), name=name, salt=salt, hash=_hash(pwd, salt),
                     created=datetime.now(timezone.utc).isoformat(timespec="seconds"),
                     ai_training=bool(ai_training), terms_version=TERMS_VERSION, age_confirmed=True)
    _save(db)
    return _public(email, db[email])


def authenticate(email, pwd):
    email, rec = email.strip().lower(), _load().get(email.strip().lower())
    if rec and hmac.compare_digest(rec["hash"], _hash(pwd, rec["salt"])):
        return _public(email, rec)
    return None


def update(email, **fields):
    db = _load()
    if email in db:
        db[email].update(fields)
        _save(db)


def user_dir(uid):
    return DATA / "users" / uid / "uploads"


def save_upload(uid, filename, data):
    folder = user_dir(uid)
    folder.mkdir(parents=True, exist_ok=True)
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", Path(filename).name)[:80] or "upload.csv"
    (folder / safe).write_bytes(data)
    return safe


def list_uploads(uid):
    folder = user_dir(uid)
    return sorted(p for p in folder.glob("*") if p.is_file()) if folder.exists() else []


def delete_uploads(uid):
    shutil.rmtree(DATA / "users" / uid, ignore_errors=True)


def delete_account(email, uid):
    """Erase the login record, password hash, preferences and every stored file."""
    delete_uploads(uid)
    db = _load()
    db.pop(email, None)
    _save(db)


def training_files():
    """Only files from accounts that have AI training switched on. Use this as the single source for any training job."""
    return [p for rec in _load().values() if rec.get("ai_training") for p in list_uploads(rec["uid"])]