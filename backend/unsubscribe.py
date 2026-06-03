"""Gestion du désabonnement à partir de l'en-tête List-Unsubscribe."""
from __future__ import annotations

import re
from typing import Any

import requests

_URL_RE = re.compile(r"<\s*(https?://[^>]+)\s*>", re.IGNORECASE)
_MAILTO_RE = re.compile(r"<\s*(mailto:[^>]+)\s*>", re.IGNORECASE)


def parse_unsubscribe(header: str) -> dict[str, Any]:
    """Extrait les liens http(s) et mailto d'un en-tête List-Unsubscribe."""
    if not header:
        return {"https": [], "mailto": []}
    return {
        "https": _URL_RE.findall(header),
        "mailto": [m.replace("mailto:", "", 1) for m in _MAILTO_RE.findall(header)],
    }


def one_click_unsubscribe(header: str) -> dict[str, Any]:
    """Effectue un désabonnement RFC 8058 (POST One-Click) si un lien https existe.

    Sinon renvoie les liens disponibles pour que l'utilisateur agisse manuellement.
    """
    links = parse_unsubscribe(header)
    https_links = links["https"]
    if https_links:
        url = https_links[0]
        try:
            resp = requests.post(
                url,
                data={"List-Unsubscribe": "One-Click"},
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                timeout=20,
                allow_redirects=True,
            )
            if 200 <= resp.status_code < 400:
                return {"ok": True, "method": "http-one-click",
                        "status": resp.status_code, "url": url}
            # Certains serveurs n'acceptent que le GET
            resp = requests.get(url, timeout=20, allow_redirects=True)
            return {
                "ok": 200 <= resp.status_code < 400,
                "method": "http-get",
                "status": resp.status_code,
                "url": url,
            }
        except Exception as exc:  # noqa: BLE001
            return {"ok": False, "method": "http", "error": str(exc),
                    "url": url, "links": links}
    return {
        "ok": False,
        "method": "manual",
        "message": "Pas de lien de désabonnement http automatique. "
                   "Utilise les liens ci-dessous.",
        "links": links,
    }


def full_unsubscribe(account: dict[str, Any], header: str) -> dict[str, Any]:
    """Désabonnement complet : tente le one-click HTTP, sinon envoie le mailto en SMTP."""
    res = one_click_unsubscribe(header)
    if res.get("ok"):
        return res
    # repli : désabonnement par e-mail si une adresse mailto est présente
    links = parse_unsubscribe(header)
    if links["mailto"]:
        import smtp_client
        sent = smtp_client.send_unsubscribe(account, "mailto:" + links["mailto"][0])
        if sent.get("ok"):
            return sent
        res = {**res, "mailto_error": sent.get("error")}
    return res
