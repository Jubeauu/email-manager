"""Connexion IMAP : scan des boîtes + actions (supprimer / archiver / déplacer)."""
from __future__ import annotations

import email.header
import email.utils
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from dateutil import parser as dateparser
from imapclient import IMAPClient

# Hôtes IMAP connus, devinés à partir du domaine de l'adresse.
PROVIDER_PRESETS = {
    "gmail.com": ("imap.gmail.com", 993),
    "googlemail.com": ("imap.gmail.com", 993),
    "outlook.com": ("outlook.office365.com", 993),
    "outlook.fr": ("outlook.office365.com", 993),
    "hotmail.com": ("outlook.office365.com", 993),
    "hotmail.fr": ("outlook.office365.com", 993),
    "live.fr": ("outlook.office365.com", 993),
    "live.com": ("outlook.office365.com", 993),
    "yahoo.com": ("imap.mail.yahoo.com", 993),
    "yahoo.fr": ("imap.mail.yahoo.com", 993),
    "icloud.com": ("imap.mail.me.com", 993),
    "me.com": ("imap.mail.me.com", 993),
    "free.fr": ("imap.free.fr", 993),
    "orange.fr": ("imap.orange.fr", 993),
    "wanadoo.fr": ("imap.orange.fr", 993),
    "sfr.fr": ("imap.sfr.fr", 993),
    "laposte.net": ("imap.laposte.net", 993),
    "gmx.com": ("imap.gmx.com", 993),
    "gmx.fr": ("imap.gmx.fr", 993),
}


def guess_imap(email_addr: str) -> tuple[str | None, int]:
    domain = email_addr.split("@")[-1].lower().strip()
    host, port = PROVIDER_PRESETS.get(domain, (None, 993))
    return host, port


def _connect(account: dict[str, Any]) -> IMAPClient:
    host = account["imap_host"]
    port = int(account.get("imap_port", 993))
    client = IMAPClient(host, port=port, ssl=True, timeout=30)
    if account.get("auth_type") == "oauth_ms":
        import oauth_ms
        token = oauth_ms.valid_access_token(account)
        client.oauth2_login(account["username"], token)
    else:
        client.login(account["username"], account["password"])
    return client


def test_connection(account: dict[str, Any]) -> dict[str, Any]:
    """Vérifie les identifiants et renvoie le nombre de messages en INBOX."""
    try:
        client = _connect(account)
        try:
            info = client.select_folder("INBOX", readonly=True)
            return {"ok": True, "inbox_count": info.get(b"EXISTS", 0)}
        finally:
            client.logout()
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": str(exc)}


# --------------------------------------------------------------------------- #
# Détection des dossiers spéciaux (Corbeille / Archive / Spam)
# --------------------------------------------------------------------------- #
SPECIAL_FALLBACKS = {
    "trash": ["Trash", "Deleted", "Deleted Items", "Deleted Messages",
              "Corbeille", "[Gmail]/Corbeille", "[Gmail]/Trash"],
    "archive": ["Archive", "Archives", "[Gmail]/All Mail",
                "[Gmail]/Tous les messages"],
    "junk": ["Junk", "Spam", "Junk Email", "Courrier indésirable",
             "[Gmail]/Spam"],
}


def special_folders(client: IMAPClient) -> dict[str, str]:
    """Repère les dossiers Corbeille / Archive / Spam via les flags SPECIAL-USE."""
    found: dict[str, str] = {}
    names: list[str] = []
    for flags, _delim, name in client.list_folders():
        names.append(name)
        flagset = {f.decode().lower().lstrip("\\") if isinstance(f, bytes)
                   else str(f).lower().lstrip("\\") for f in flags}
        if "trash" in flagset:
            found["trash"] = name
        if "archive" in flagset:
            found["archive"] = name
        if "junk" in flagset:
            found["junk"] = name
    # Fallback par nom si les flags SPECIAL-USE sont absents
    lower = {n.lower(): n for n in names}
    for key, candidates in SPECIAL_FALLBACKS.items():
        if key not in found:
            for cand in candidates:
                if cand.lower() in lower:
                    found[key] = lower[cand.lower()]
                    break
    return found


# --------------------------------------------------------------------------- #
# Scan
# --------------------------------------------------------------------------- #
_HEADER_FIELDS = (b"BODY.PEEK[HEADER.FIELDS (LIST-UNSUBSCRIBE LIST-UNSUBSCRIBE-POST "
                  b"LIST-ID PRECEDENCE AUTHENTICATION-RESULTS)]")
_HEADER_KEY = (b"BODY[HEADER.FIELDS (LIST-UNSUBSCRIBE LIST-UNSUBSCRIBE-POST "
               b"LIST-ID PRECEDENCE AUTHENTICATION-RESULTS)]")

# Dossiers à ignorer lors d'un scan complet (rien à nettoyer côté promo/spam).
_SKIP_FOLDERS = {"sent", "drafts", "outbox", "junk e-mail drafts"}


def interesting_folders(client: IMAPClient, scan_all: bool = False) -> list[str]:
    """Liste des dossiers à scanner : INBOX + Spam (+ tout le reste si scan_all)."""
    specials = special_folders(client)
    folders = ["INBOX"]
    if specials.get("junk"):
        folders.append(specials["junk"])
    if scan_all:
        for flags, _delim, name in client.list_folders():
            flagset = {(f.decode() if isinstance(f, bytes) else str(f)).lower()
                       for f in flags}
            if "\\noselect" in flagset or "noselect" in flagset:
                continue
            if name.lower() in _SKIP_FOLDERS or name in folders:
                continue
            # on saute aussi les dossiers spéciaux Envoyés/Brouillons
            if {"\\sent", "\\drafts", "sent", "drafts"} & flagset:
                continue
            folders.append(name)
    return folders


def _parse_from(envelope) -> tuple[str, str]:
    try:
        addr = envelope.from_[0]
        name = (addr.name or b"").decode("utf-8", "replace") if addr.name else ""
        mailbox = (addr.mailbox or b"").decode("utf-8", "replace")
        host = (addr.host or b"").decode("utf-8", "replace")
        email_addr = f"{mailbox}@{host}".lower() if host else mailbox.lower()
        # décode les noms encodés type =?UTF-8?...?=
        try:
            parts = email.header.decode_header(name)
            name = "".join(
                p.decode(enc or "utf-8", "replace") if isinstance(p, bytes) else p
                for p, enc in parts
            )
        except Exception:  # noqa: BLE001
            pass
        return email_addr, name
    except Exception:  # noqa: BLE001
        return "", ""


def _parse_headers(raw: bytes | None) -> tuple[str, bool, bool, str]:
    """Renvoie (list_unsubscribe, one_click, is_bulk, authentication_results)."""
    if not raw:
        return "", False, False, ""
    text = raw.decode("utf-8", "replace")
    list_unsub = ""
    m = re.search(r"List-Unsubscribe:\s*(.+?)(?:\r?\n[^\s]|\Z)", text,
                  re.IGNORECASE | re.DOTALL)
    if m:
        list_unsub = " ".join(m.group(1).split())
    one_click = "one-click" in text.lower() and "list-unsubscribe-post" in text.lower()
    is_bulk = bool(list_unsub) or "list-id:" in text.lower() \
        or re.search(r"precedence:\s*(bulk|list)", text, re.IGNORECASE) is not None
    auth = ""
    ma = re.search(r"Authentication-Results:\s*(.+?)(?:\r?\n[^\s]|\Z)", text,
                   re.IGNORECASE | re.DOTALL)
    if ma:
        auth = " ".join(ma.group(1).split())
    return list_unsub, one_click, is_bulk, auth


def _decode_mime(value: str) -> str:
    try:
        parts = email.header.decode_header(value)
        return "".join(p.decode(enc or "utf-8", "replace") if isinstance(p, bytes)
                       else p for p, enc in parts)
    except Exception:  # noqa: BLE001
        return value


def _reply_to(envelope) -> str:
    try:
        addr = envelope.reply_to[0]
        host = (addr.host or b"").decode("utf-8", "replace")
        mailbox = (addr.mailbox or b"").decode("utf-8", "replace")
        return f"{mailbox}@{host}".lower() if host else ""
    except Exception:  # noqa: BLE001
        return ""


def _build_row(account_id: str, folder: str, uid, data, phishing) -> dict[str, Any] | None:
    """Construit une ligne à partir d'un message récupéré."""
    env = data.get(b"ENVELOPE")
    if env is None:
        return None
    from_email, from_name = _parse_from(env)
    subject = _decode_mime(env.subject.decode("utf-8", "replace")) if env.subject else ""
    date_ts, date_str = 0, ""
    if env.date:
        date_str = env.date.isoformat()
        try:
            date_ts = int(env.date.timestamp())
        except Exception:  # noqa: BLE001
            date_ts = 0
    raw_headers = data.get(_HEADER_KEY) or data.get(_HEADER_FIELDS)
    list_unsub, one_click, is_bulk, auth_raw = _parse_headers(raw_headers)
    flags = data.get(b"FLAGS", ())
    reply_to = _reply_to(env)
    auth_summary = phishing.parse_auth(auth_raw)
    score, reasons = phishing.analyze(from_email, from_name, subject, reply_to, auth_summary)
    return {
        "account_id": account_id, "folder": folder, "uid": int(uid),
        "from_email": from_email, "from_name": from_name, "subject": subject,
        "date": date_str, "date_ts": date_ts, "size": int(data.get(b"RFC822.SIZE", 0)),
        "list_unsubscribe": list_unsub, "one_click": 1 if one_click else 0,
        "is_promo": 1 if is_bulk else 0, "unread": 0 if b"\\Seen" in flags else 1,
        "reply_to": reply_to, "auth_results": auth_summary,
        "phishing_score": score, "phishing_reasons": reasons,
    }


# Récupération parallèle : plusieurs connexions IMAP simultanées accélèrent le scan.
SCAN_WORKERS = 5
SCAN_CHUNK = 400


def scan_account(
    account: dict[str, Any], folders: list[str] | None = None,
    scan_all: bool = False, incremental: bool = True,
    since_days: int | None = None, progress=None,
) -> list[dict[str, Any]]:
    """Scanne les dossiers en parallèle.

    - incremental : ne lit que les UID nouveaux depuis le dernier scan (rapide).
    - since_days  : en mode complet, ne lit que les mails plus récents que N jours.
    """
    import datetime
    import db
    import phishing

    # 1re passe (connexion de contrôle) : quels UID récupérer dans chaque dossier
    control = _connect(account)  # rafraîchit aussi le jeton OAuth pour les workers
    plan: dict[str, tuple[int, list[int]]] = {}
    grand_total = 0
    try:
        for folder in (folders or interesting_folders(control, scan_all=scan_all)):
            try:
                info = control.select_folder(folder, readonly=True)
            except Exception:  # noqa: BLE001
                continue
            uidvalidity = int(info.get(b"UIDVALIDITY", 0))
            state = db.get_scan_state(account["id"], folder)
            criteria: list = ["ALL"]
            if incremental and state and state[0] == uidvalidity and state[1]:
                criteria = ["UID", f"{state[1] + 1}:*"]
            elif since_days:
                since = datetime.date.today() - datetime.timedelta(days=since_days)
                criteria = ["SINCE", since]
            try:
                uids = control.search(criteria)
            except Exception:  # noqa: BLE001
                uids = []
            if incremental and state and state[1]:
                uids = [u for u in uids if u > state[1]]
            plan[folder] = (uidvalidity, uids)
            grand_total += len(uids)
    finally:
        try:
            control.logout()
        except Exception:  # noqa: BLE001
            pass

    rows: list[dict[str, Any]] = []
    rows_lock = threading.Lock()
    prog_lock = threading.Lock()
    done = [0]
    if progress:
        progress(0, grand_total)

    tasks = [(folder, uids[i : i + SCAN_CHUNK])
             for folder, (_uv, uids) in plan.items()
             for i in range(0, len(uids), SCAN_CHUNK)]

    def worker(task):
        folder, chunk = task
        if not chunk:
            return
        for attempt in range(2):
            local = None
            try:
                local = _connect(account)
                local.select_folder(folder, readonly=True)
                resp = local.fetch(chunk, ["ENVELOPE", "RFC822.SIZE", "FLAGS", _HEADER_FIELDS])
                built = [r for r in (_build_row(account["id"], folder, uid, data, phishing)
                                     for uid, data in resp.items()) if r]
                with rows_lock:
                    rows.extend(built)
                break
            except Exception:  # noqa: BLE001
                if attempt == 0:
                    time.sleep(1.0)
            finally:
                if local:
                    try:
                        local.logout()
                    except Exception:  # noqa: BLE001
                        pass
        with prog_lock:
            done[0] += len(chunk)
            if progress:
                progress(min(done[0], grand_total), grand_total)

    if tasks:
        with ThreadPoolExecutor(max_workers=SCAN_WORKERS) as ex:
            list(ex.map(worker, tasks))

    # mémorise la position de chaque dossier pour le prochain scan incrémental
    for folder, (uidvalidity, uids) in plan.items():
        if uidvalidity and uids:
            prev = (db.get_scan_state(account["id"], folder) or (0, 0))[1] or 0
            db.set_scan_state(account["id"], folder, uidvalidity,
                              max(prev, max(int(u) for u in uids)))
    return rows


# --------------------------------------------------------------------------- #
# Actions
# --------------------------------------------------------------------------- #
def _move_uids(client: IMAPClient, uids: list[int], target: str) -> None:
    if not uids:
        return
    caps = client.capabilities()
    if b"MOVE" in caps:
        client.move(uids, target)
    else:
        client.copy(uids, target)
        client.delete_messages(uids)
        client.expunge()


def _apply_per_folder(
    account: dict[str, Any], folder_uids: dict[str, list[int]], handler
) -> dict[str, Any]:
    """Ouvre chaque dossier source et applique `handler(client, uids, specials)`."""
    client = _connect(account)
    total = 0
    try:
        specials = special_folders(client)
        for folder, uids in folder_uids.items():
            if not uids:
                continue
            try:
                client.select_folder(folder)
            except Exception:  # noqa: BLE001
                continue
            handler(client, uids, specials, folder)
            total += len(uids)
        return {"ok": True, "count": total}
    finally:
        client.logout()


def delete_messages(
    account: dict[str, Any], folder_uids: dict[str, list[int]]
) -> dict[str, Any]:
    """Déplace vers la Corbeille (ou supprime si pas de Corbeille), dossier par dossier."""
    def handler(client, uids, specials, folder):
        trash = specials.get("trash")
        # ne pas re-déplacer ce qui est déjà dans la corbeille
        if trash and folder != trash:
            _move_uids(client, uids, trash)
        else:
            client.delete_messages(uids)
            client.expunge()
    res = _apply_per_folder(account, folder_uids, handler)
    res["action"] = "trashed"
    return res


def archive_messages(
    account: dict[str, Any], folder_uids: dict[str, list[int]]
) -> dict[str, Any]:
    def handler(client, uids, specials, folder):
        archive = specials.get("archive")
        if archive and folder != archive:
            _move_uids(client, uids, archive)
        else:
            client.delete_messages(uids)
            client.expunge()
    res = _apply_per_folder(account, folder_uids, handler)
    res["action"] = "archived"
    return res


def move_messages(
    account: dict[str, Any], folder_uids: dict[str, list[int]], target: str
) -> dict[str, Any]:
    client = _connect(account)
    total = 0
    try:
        if not client.folder_exists(target):
            client.create_folder(target)
        for folder, uids in folder_uids.items():
            if not uids or folder == target:
                continue
            try:
                client.select_folder(folder)
            except Exception:  # noqa: BLE001
                continue
            _move_uids(client, uids, target)
            total += len(uids)
        return {"ok": True, "action": "moved", "count": total, "folder": target}
    finally:
        client.logout()


def list_folders(account: dict[str, Any]) -> list[str]:
    client = _connect(account)
    try:
        return [name for _f, _d, name in client.list_folders()]
    finally:
        client.logout()
