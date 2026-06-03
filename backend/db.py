"""Stockage local : comptes (JSON + secrets en keyring) + cache messages (SQLite)."""
from __future__ import annotations

import json
import sqlite3
import threading
import uuid
from pathlib import Path
from typing import Any

DATA_DIR = Path(__file__).resolve().parent.parent / "data"
DATA_DIR.mkdir(exist_ok=True)
ACCOUNTS_FILE = DATA_DIR / "accounts.json"
DB_FILE = DATA_DIR / "cache.db"

_lock = threading.Lock()

# Champs sensibles, déplacés vers le coffre-fort du système (jamais dans le JSON).
SECRET_FIELDS = ("password", "access_token", "refresh_token")
KEYRING_SERVICE = "EmailManager"

# keyring = gestionnaire d'identifiants Windows (chiffré). Repli silencieux si absent.
try:
    import keyring
    _KEYRING_OK = True
except Exception:  # noqa: BLE001
    keyring = None  # type: ignore
    _KEYRING_OK = False


# --------------------------------------------------------------------------- #
# Secrets (keyring)
# --------------------------------------------------------------------------- #
def _store_secrets(account_id: str, secrets: dict[str, Any]) -> bool:
    if not _KEYRING_OK or not secrets:
        return False
    try:
        keyring.set_password(KEYRING_SERVICE, account_id, json.dumps(secrets))
        return True
    except Exception:  # noqa: BLE001
        return False


def _load_secrets(account_id: str) -> dict[str, Any]:
    if not _KEYRING_OK:
        return {}
    try:
        raw = keyring.get_password(KEYRING_SERVICE, account_id)
        return json.loads(raw) if raw else {}
    except Exception:  # noqa: BLE001
        return {}


def _delete_secrets(account_id: str) -> None:
    if not _KEYRING_OK:
        return
    try:
        keyring.delete_password(KEYRING_SERVICE, account_id)
    except Exception:  # noqa: BLE001
        pass


# --------------------------------------------------------------------------- #
# Comptes
# --------------------------------------------------------------------------- #
def _read_raw_accounts() -> list[dict[str, Any]]:
    if not ACCOUNTS_FILE.exists():
        return []
    try:
        return json.loads(ACCOUNTS_FILE.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return []


def load_accounts() -> list[dict[str, Any]]:
    """Renvoie les comptes complets (champs publics + secrets fusionnés depuis keyring)."""
    accounts = _read_raw_accounts()
    for a in accounts:
        secrets = _load_secrets(a["id"])
        for k, v in secrets.items():
            a.setdefault(k, v)
    return accounts


def _write_accounts(accounts: list[dict[str, Any]]) -> None:
    """Écrit le JSON public et pousse les secrets vers keyring quand c'est possible."""
    public_list = []
    for a in accounts:
        secrets = {k: a[k] for k in SECRET_FIELDS if a.get(k)}
        stored = _store_secrets(a["id"], secrets) if secrets else False
        if stored:
            public_list.append({k: v for k, v in a.items() if k not in SECRET_FIELDS})
        else:
            # keyring indisponible : on conserve tout dans le JSON (repli)
            public_list.append(dict(a))
    ACCOUNTS_FILE.write_text(
        json.dumps(public_list, ensure_ascii=False, indent=2), encoding="utf-8"
    )


def migrate_secrets() -> None:
    """Déplace les secrets en clair encore présents dans accounts.json vers keyring."""
    if not _KEYRING_OK:
        return
    raw = _read_raw_accounts()
    if any(any(k in a for k in SECRET_FIELDS) for a in raw):
        _write_accounts(load_accounts())  # relit (merge) puis réécrit proprement


def add_account(account: dict[str, Any]) -> dict[str, Any]:
    accounts = load_accounts()
    account["id"] = uuid.uuid4().hex[:12]
    accounts.append(account)
    _write_accounts(accounts)
    return account


def update_account(account_id: str, updates: dict[str, Any]) -> None:
    accounts = load_accounts()
    for a in accounts:
        if a["id"] == account_id:
            a.update(updates)
            break
    _write_accounts(accounts)


def delete_account(account_id: str) -> None:
    accounts = [a for a in load_accounts() if a["id"] != account_id]
    _write_accounts(accounts)
    _delete_secrets(account_id)
    with get_conn() as conn:
        conn.execute("DELETE FROM messages WHERE account_id = ?", (account_id,))
        conn.commit()


def get_account(account_id: str) -> dict[str, Any] | None:
    for a in load_accounts():
        if a["id"] == account_id:
            return a
    return None


# --------------------------------------------------------------------------- #
# Cache des messages (SQLite)
# --------------------------------------------------------------------------- #
def get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn


_COLUMNS = {
    "account_id": "TEXT NOT NULL",
    "folder": "TEXT NOT NULL",
    "uid": "INTEGER NOT NULL",
    "from_email": "TEXT",
    "from_name": "TEXT",
    "subject": "TEXT",
    "date": "TEXT",
    "date_ts": "INTEGER",
    "size": "INTEGER",
    "list_unsubscribe": "TEXT",
    "one_click": "INTEGER DEFAULT 0",
    "is_promo": "INTEGER DEFAULT 0",
    "unread": "INTEGER DEFAULT 0",
    "reply_to": "TEXT",
    "auth_results": "TEXT",
    "phishing_score": "INTEGER DEFAULT 0",
    "phishing_reasons": "TEXT",
}


def init_db() -> None:
    with get_conn() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS messages (
                account_id TEXT NOT NULL, folder TEXT NOT NULL, uid INTEGER NOT NULL,
                from_email TEXT, from_name TEXT, subject TEXT, date TEXT,
                date_ts INTEGER, size INTEGER, list_unsubscribe TEXT,
                one_click INTEGER DEFAULT 0, is_promo INTEGER DEFAULT 0,
                PRIMARY KEY (account_id, folder, uid)
            )
            """
        )
        # Migration : ajoute les colonnes manquantes aux anciennes bases
        existing = {r["name"] for r in conn.execute("PRAGMA table_info(messages)")}
        for col, decl in _COLUMNS.items():
            if col not in existing:
                conn.execute(f"ALTER TABLE messages ADD COLUMN {col} {decl}")
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_sender ON messages(account_id, from_email)"
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS unsubscribed (
                from_email TEXT PRIMARY KEY, ts INTEGER, method TEXT
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS scan_state (
                account_id TEXT NOT NULL, folder TEXT NOT NULL,
                uidvalidity INTEGER, last_uid INTEGER,
                PRIMARY KEY (account_id, folder)
            )
            """
        )
        conn.commit()
    migrate_secrets()


def get_scan_state(account_id: str, folder: str) -> tuple[int, int] | None:
    with get_conn() as conn:
        row = conn.execute(
            "SELECT uidvalidity, last_uid FROM scan_state WHERE account_id=? AND folder=?",
            (account_id, folder),
        ).fetchone()
    return (row["uidvalidity"], row["last_uid"]) if row else None


def set_scan_state(account_id: str, folder: str, uidvalidity: int, last_uid: int) -> None:
    with get_conn() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO scan_state (account_id, folder, uidvalidity, last_uid)"
            " VALUES (?,?,?,?)",
            (account_id, folder, uidvalidity, last_uid),
        )
        conn.commit()


def reset_scan_state(account_id: str) -> None:
    with get_conn() as conn:
        conn.execute("DELETE FROM scan_state WHERE account_id=?", (account_id,))
        conn.commit()


def clear_account_cache(account_id: str) -> None:
    with get_conn() as conn:
        conn.execute("DELETE FROM messages WHERE account_id = ?", (account_id,))
        conn.commit()


def clear_folder_cache(account_id: str, folder: str) -> None:
    with get_conn() as conn:
        conn.execute(
            "DELETE FROM messages WHERE account_id = ? AND folder = ?",
            (account_id, folder),
        )
        conn.commit()


_INSERT_COLS = list(_COLUMNS.keys())


def insert_messages(rows: list[dict[str, Any]]) -> None:
    if not rows:
        return
    cols = ", ".join(_INSERT_COLS)
    placeholders = ", ".join(f":{c}" for c in _INSERT_COLS)
    with _lock, get_conn() as conn:
        conn.executemany(
            f"INSERT OR REPLACE INTO messages ({cols}) VALUES ({placeholders})", rows
        )
        conn.commit()


def _account_where(account_id: str | None, prefix: str = "WHERE") -> tuple[str, list]:
    if account_id and account_id != "all":
        return f"{prefix} account_id = ?", [account_id]
    return "", []


def senders_summary(
    account_id: str | None = None, category: str | None = None
) -> list[dict[str, Any]]:
    where, params = _account_where(account_id)
    with get_conn() as conn:
        rows = conn.execute(
            f"""
            SELECT
                m.from_email,
                MAX(m.from_name)               AS from_name,
                COUNT(*)                       AS count,
                SUM(m.is_promo)                AS promo_count,
                SUM(m.unread)                  AS unread_count,
                MAX(m.one_click)               AS one_click,
                MAX(m.phishing_score)          AS phishing_score,
                MAX(CASE WHEN m.list_unsubscribe IS NOT NULL AND m.list_unsubscribe != ''
                         THEN 1 ELSE 0 END)    AS has_unsub,
                MAX(m.date_ts)                 AS last_ts,
                MIN(m.date_ts)                 AS first_ts,
                SUM(COALESCE(m.size, 0))       AS total_size,
                MAX(m.list_unsubscribe)        AS list_unsubscribe,
                GROUP_CONCAT(DISTINCT m.account_id) AS account_ids,
                (SELECT 1 FROM unsubscribed u WHERE u.from_email = m.from_email) AS unsubscribed
            FROM messages m
            {where}
            GROUP BY m.from_email
            ORDER BY count DESC
            """,
            params,
        ).fetchall()
    return [dict(r) for r in rows]


def suspicious_senders(account_id: str | None = None) -> list[dict[str, Any]]:
    """Expéditeurs avec un score de phishing > 0, avec la raison la plus parlante."""
    where, params = _account_where(account_id, "AND")
    with get_conn() as conn:
        rows = conn.execute(
            f"""
            SELECT from_email, MAX(from_name) AS from_name, COUNT(*) AS count,
                   MAX(phishing_score) AS phishing_score, MAX(date_ts) AS last_ts,
                   GROUP_CONCAT(DISTINCT account_id) AS account_ids
            FROM messages
            WHERE phishing_score > 0 {where}
            GROUP BY from_email
            ORDER BY phishing_score DESC, count DESC
            """,
            params,
        ).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            reason = conn.execute(
                """SELECT phishing_reasons, subject FROM messages
                   WHERE from_email = ? ORDER BY phishing_score DESC LIMIT 1""",
                (d["from_email"],),
            ).fetchone()
            d["reasons"] = reason["phishing_reasons"] if reason else ""
            d["example_subject"] = reason["subject"] if reason else ""
            out.append(d)
    return out


def messages_for_sender(
    from_email: str, account_id: str | None = None
) -> list[dict[str, Any]]:
    where = "WHERE from_email = ?"
    params: list = [from_email]
    if account_id and account_id != "all":
        where += " AND account_id = ?"
        params.append(account_id)
    with get_conn() as conn:
        rows = conn.execute(
            f"""
            SELECT account_id, folder, uid, subject, date, date_ts, size, unread,
                   phishing_score, phishing_reasons, auth_results
            FROM messages {where} ORDER BY date_ts DESC
            """,
            params,
        ).fetchall()
    return [dict(r) for r in rows]


def folder_uids_for_sender(from_email: str, account_id: str) -> dict[str, list[int]]:
    """Regroupe les UID d'un expéditeur par dossier (un UID n'est valable que
    dans son dossier IMAP)."""
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT folder, uid FROM messages WHERE from_email = ? AND account_id = ?",
            (from_email, account_id),
        ).fetchall()
    out: dict[str, list[int]] = {}
    for r in rows:
        out.setdefault(r["folder"], []).append(r["uid"])
    return out


def folder_uids_for_uids(
    account_id: str, uids: list[int]
) -> dict[str, list[int]]:
    if not uids:
        return {}
    placeholders = ",".join("?" * len(uids))
    with get_conn() as conn:
        rows = conn.execute(
            f"SELECT folder, uid FROM messages WHERE account_id = ? "
            f"AND uid IN ({placeholders})", [account_id, *uids],
        ).fetchall()
    out: dict[str, list[int]] = {}
    for r in rows:
        out.setdefault(r["folder"], []).append(r["uid"])
    return out


def delete_cached_sender(account_id: str, from_email: str) -> None:
    with get_conn() as conn:
        conn.execute(
            "DELETE FROM messages WHERE account_id = ? AND from_email = ?",
            (account_id, from_email),
        )
        conn.commit()


def delete_cached_uids(account_id: str, uids: list[int]) -> None:
    if not uids:
        return
    placeholders = ",".join("?" * len(uids))
    with get_conn() as conn:
        conn.execute(
            f"DELETE FROM messages WHERE account_id = ? AND uid IN ({placeholders})",
            [account_id, *uids],
        )
        conn.commit()


def mark_unsubscribed(from_email: str, method: str) -> None:
    import time
    with get_conn() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO unsubscribed (from_email, ts, method) VALUES (?,?,?)",
            (from_email, int(time.time()), method),
        )
        conn.commit()


def global_stats(account_id: str | None = None) -> dict[str, Any]:
    where, params = _account_where(account_id)
    with get_conn() as conn:
        row = conn.execute(
            f"""
            SELECT COUNT(*) AS total, SUM(is_promo) AS promo, SUM(unread) AS unread,
                   SUM(CASE WHEN phishing_score > 0 THEN 1 ELSE 0 END) AS suspicious,
                   COUNT(DISTINCT from_email) AS senders,
                   SUM(COALESCE(size, 0)) AS total_size
            FROM messages {where}
            """,
            params,
        ).fetchone()
    return dict(row) if row else {}


def folders_scanned(account_id: str | None = None) -> list[dict[str, Any]]:
    where, params = _account_where(account_id)
    with get_conn() as conn:
        rows = conn.execute(
            f"SELECT folder, COUNT(*) AS count FROM messages {where} "
            f"GROUP BY folder ORDER BY count DESC", params,
        ).fetchall()
    return [dict(r) for r in rows]


# --------------------------------------------------------------------------- #
# Insights
# --------------------------------------------------------------------------- #
def volume_by_month(account_id: str | None = None) -> list[dict[str, Any]]:
    where, params = _account_where(account_id)
    with get_conn() as conn:
        rows = conn.execute(
            f"""
            SELECT strftime('%Y-%m', date_ts, 'unixepoch') AS month, COUNT(*) AS count
            FROM messages {where} {'AND' if where else 'WHERE'} date_ts > 0
            GROUP BY month ORDER BY month
            """,
            params,
        ).fetchall()
    return [dict(r) for r in rows]


def top_size_senders(account_id: str | None = None, limit: int = 10):
    where, params = _account_where(account_id)
    with get_conn() as conn:
        rows = conn.execute(
            f"""
            SELECT from_email, MAX(from_name) AS from_name,
                   SUM(COALESCE(size,0)) AS total_size, COUNT(*) AS count
            FROM messages {where}
            GROUP BY from_email ORDER BY total_size DESC LIMIT ?
            """,
            [*params, limit],
        ).fetchall()
    return [dict(r) for r in rows]


def dormant_senders(account_id: str | None = None, days: int = 180, limit: int = 20):
    """Expéditeurs volumineux dont tu n'as rien ouvert récemment (candidats au ménage)."""
    import time
    cutoff = int(time.time()) - days * 86400
    where, params = _account_where(account_id)
    with get_conn() as conn:
        rows = conn.execute(
            f"""
            SELECT from_email, MAX(from_name) AS from_name, COUNT(*) AS count,
                   MAX(date_ts) AS last_ts, SUM(unread) AS unread_count
            FROM messages {where}
            GROUP BY from_email
            HAVING last_ts < ? AND count >= 3
            ORDER BY count DESC LIMIT ?
            """,
            [*params, cutoff, limit],
        ).fetchall()
    return [dict(r) for r in rows]
