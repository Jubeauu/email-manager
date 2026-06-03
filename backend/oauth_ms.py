"""OAuth2 Microsoft (flux device-code) pour l'accès IMAP aux comptes Outlook.com.

Microsoft a désactivé l'authentification IMAP par mot de passe sur les comptes
personnels : on utilise donc OAuth2 + XOAUTH2.
"""
from __future__ import annotations

import base64
import json
import time
from typing import Any

import requests

AUTHORITY = "https://login.microsoftonline.com/common/oauth2/v2.0"
DEVICECODE_URL = f"{AUTHORITY}/devicecode"
TOKEN_URL = f"{AUTHORITY}/token"

# ID d'application public de Mozilla Thunderbird (client public, usage personnel).
# Évite à l'utilisateur de créer sa propre app Azure.
THUNDERBIRD_CLIENT_ID = "9e5f94bc-e8a4-4e73-b8be-63364c29d753"

# Scopes : accès IMAP délégué + jeton de rafraîchissement + identité (pour l'e-mail)
SCOPE = (
    "https://outlook.office.com/IMAP.AccessAsUser.All "
    "https://outlook.office.com/SMTP.Send "
    "offline_access openid email profile"
)


def start_device_flow(client_id: str) -> dict[str, Any]:
    resp = requests.post(
        DEVICECODE_URL,
        data={"client_id": client_id, "scope": SCOPE},
        timeout=20,
    )
    resp.raise_for_status()
    return resp.json()  # device_code, user_code, verification_uri, interval, expires_in


def poll_token(client_id: str, device_code: str) -> dict[str, Any]:
    """Interroge une fois le endpoint. Renvoie {status: pending|ok|error, ...}."""
    resp = requests.post(
        TOKEN_URL,
        data={
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
            "client_id": client_id,
            "device_code": device_code,
        },
        timeout=20,
    )
    data = resp.json()
    if resp.status_code == 200:
        return {"status": "ok", **_with_expiry(data)}
    err = data.get("error", "")
    if err in ("authorization_pending", "slow_down"):
        return {"status": "pending", "error": err}
    return {"status": "error", "error": err,
            "description": data.get("error_description", "")}


def refresh_access_token(client_id: str, refresh_token: str) -> dict[str, Any]:
    resp = requests.post(
        TOKEN_URL,
        data={
            "grant_type": "refresh_token",
            "client_id": client_id,
            "refresh_token": refresh_token,
            "scope": SCOPE,
        },
        timeout=20,
    )
    resp.raise_for_status()
    return _with_expiry(resp.json())


def _with_expiry(token: dict[str, Any]) -> dict[str, Any]:
    token["token_expiry"] = int(time.time()) + int(token.get("expires_in", 3600))
    return token


def email_from_id_token(id_token: str) -> str:
    """Extrait l'adresse e-mail des claims du jeton d'identité (sans vérif. de signature)."""
    try:
        payload = id_token.split(".")[1]
        payload += "=" * (-len(payload) % 4)  # padding base64
        claims = json.loads(base64.urlsafe_b64decode(payload))
        return (claims.get("email") or claims.get("preferred_username") or "").lower()
    except Exception:  # noqa: BLE001
        return ""


def valid_access_token(account: dict[str, Any]) -> str:
    """Renvoie un access token valide, en le rafraîchissant et le persistant si besoin."""
    import db  # import local pour éviter une dépendance circulaire

    if account.get("token_expiry", 0) - 60 > int(time.time()):
        return account["access_token"]
    refreshed = refresh_access_token(account["client_id"], account["refresh_token"])
    updates = {
        "access_token": refreshed["access_token"],
        "token_expiry": refreshed["token_expiry"],
    }
    if refreshed.get("refresh_token"):
        updates["refresh_token"] = refreshed["refresh_token"]
    db.update_account(account["id"], updates)
    account.update(updates)
    return account["access_token"]
