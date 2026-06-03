"""Envoi SMTP minimal pour les désabonnements par e-mail (mailto:).

Gère l'auth OAuth2 (XOAUTH2, comptes Outlook) et par mot de passe (Gmail/IMAP).
"""
from __future__ import annotations

import base64
import smtplib
import urllib.parse
from email.message import EmailMessage
from typing import Any

SMTP_PRESETS = {
    "outlook.office365.com": ("smtp.office365.com", 587),
    "imap.gmail.com": ("smtp.gmail.com", 587),
    "imap.mail.yahoo.com": ("smtp.mail.yahoo.com", 587),
    "imap.mail.me.com": ("smtp.mail.me.com", 587),
    "imap.free.fr": ("smtp.free.fr", 587),
    "imap.orange.fr": ("smtp.orange.fr", 587),
    "imap.laposte.net": ("smtp.laposte.net", 587),
    "imap.gmx.com": ("mail.gmx.com", 587),
    "imap.gmx.fr": ("mail.gmx.fr", 587),
}


def _smtp_for(account: dict[str, Any]) -> tuple[str, int]:
    host = account.get("imap_host", "")
    if host in SMTP_PRESETS:
        return SMTP_PRESETS[host]
    return host.replace("imap", "smtp", 1), 587


def parse_mailto(mailto: str) -> dict[str, str]:
    """Décompose un mailto: en adresse + sujet + corps."""
    raw = mailto[len("mailto:"):] if mailto.lower().startswith("mailto:") else mailto
    addr, _, query = raw.partition("?")
    params = urllib.parse.parse_qs(query)
    return {
        "to": addr.strip(),
        "subject": (params.get("subject", ["unsubscribe"])[0]),
        "body": (params.get("body", ["unsubscribe"])[0]),
    }


def _connect_smtp(account: dict[str, Any]) -> smtplib.SMTP:
    host, port = _smtp_for(account)
    server = smtplib.SMTP(host, port, timeout=30)
    server.ehlo()
    server.starttls()
    server.ehlo()
    if account.get("auth_type") == "oauth_ms":
        import oauth_ms
        token = oauth_ms.valid_access_token(account)
        user = account["username"]
        auth = f"user={user}\x01auth=Bearer {token}\x01\x01"
        code, resp = server.docmd(
            "AUTH", "XOAUTH2 " + base64.b64encode(auth.encode()).decode()
        )
        if code not in (235, 503):
            raise RuntimeError(f"Échec auth SMTP XOAUTH2 : {code} {resp!r}")
    else:
        server.login(account["username"], account["password"])
    return server


def send_unsubscribe(account: dict[str, Any], mailto: str) -> dict[str, Any]:
    info = parse_mailto(mailto)
    if not info["to"]:
        return {"ok": False, "error": "adresse mailto vide"}
    msg = EmailMessage()
    msg["From"] = account["email"]
    msg["To"] = info["to"]
    msg["Subject"] = info["subject"]
    msg.set_content(info["body"])
    try:
        server = _connect_smtp(account)
        try:
            server.send_message(msg)
        finally:
            server.quit()
        return {"ok": True, "method": "mailto", "to": info["to"]}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "method": "mailto", "error": str(exc)}
