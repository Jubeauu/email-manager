"""Catégorisation des expéditeurs à partir de signaux agrégés."""
from __future__ import annotations

CATEGORIES = ["Suspect", "Réseaux sociaux", "Finance", "Promo / Newsletter",
              "Notifications", "Contacts"]

_SOCIAL = ("facebook", "instagram", "linkedin", "twitter", "x.com", "tiktok",
           "snapchat", "pinterest", "youtube", "meta.com", "reddit", "discord")
_FINANCE = ("paypal", "stripe", "bank", "banque", "credit-agricole", "bnpparibas",
            "societegenerale", "boursorama", "boursobank", "caisse-epargne",
            "creditmutuel", "labanquepostale", "n26", "revolut", "coinbase",
            "binance", "lydia", "qonto", "shine", "fortuneo")
_NOTIF_LOCALS = ("noreply", "no-reply", "no_reply", "notification", "notify",
                 "donotreply", "do-not-reply", "info", "service", "support",
                 "account", "billing", "facture", "compte", "alerte", "alert",
                 "mailer", "postmaster", "system", "auto")


def categorize(from_email: str, from_name: str, has_unsub: int,
               promo_count: int, phishing_score: int) -> str:
    domain = from_email.split("@")[-1].lower() if "@" in (from_email or "") else ""
    local = from_email.split("@")[0].lower() if "@" in (from_email or "") else ""

    if phishing_score and phishing_score >= 40:
        return "Suspect"
    if any(s in domain for s in _SOCIAL):
        return "Réseaux sociaux"
    if any(f in domain for f in _FINANCE):
        return "Finance"
    if has_unsub or (promo_count and promo_count > 0):
        return "Promo / Newsletter"
    if any(local.startswith(n) or n in local for n in _NOTIF_LOCALS):
        return "Notifications"
    return "Contacts"
