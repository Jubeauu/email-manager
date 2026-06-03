"""Détection de phishing / usurpation de marque — version haute précision.

Principe : on ne déclenche que sur des signaux forts et peu ambigus :
  1. Domaine imitant une marque : le nom de marque apparaît comme un *mot entier*
     combiné à d'autres mots (ex. « paypal-secure.com », « notif-colissimo-x.info »)
     ou en sous-domaine d'un domaine sans rapport (ex. « paypal.evil.com »).
  2. Usurpation du nom affiché : le nom affiché contient une marque connue, ET
     l'envoi vient d'une adresse perso (Gmail…) OU échoue à DMARC.

On évite volontairement :
  - la recherche par sous-chaîne (qui flaggait « sfr » dans « cofidis ») ;
  - le flag sur simple échec d'authentification (fréquent chez les légitimes) ;
  - les marques dont le nom est un mot courant (free, orange, ups…).
"""
from __future__ import annotations

import re

# Marque (token distinctif) -> domaines officiels légitimes.
BRANDS: dict[str, list[str]] = {
    "paypal": ["paypal.com", "paypal.fr", "paypalobjects.com"],
    "amazon": ["amazon.com", "amazon.fr", "amazon.co.uk", "amazon.de",
               "amazonses.com", "amazon.es", "amazon.it"],
    "apple": ["apple.com", "icloud.com", "me.com", "appleid.com", "itunes.com"],
    "microsoft": ["microsoft.com", "outlook.com", "office.com", "live.com",
                  "microsoftonline.com", "microsoft365.com", "azure.com"],
    "google": ["google.com", "gmail.com", "googlemail.com", "google.fr",
               "youtube.com", "googleapis.com"],
    "netflix": ["netflix.com"],
    "disney": ["disneyplus.com", "disney.com", "go.com"],
    "spotify": ["spotify.com"],
    "instagram": ["instagram.com", "mail.instagram.com"],
    "facebook": ["facebook.com", "facebookmail.com", "meta.com"],
    "whatsapp": ["whatsapp.com"],
    "linkedin": ["linkedin.com"],
    "shopify": ["shopify.com", "shopifyemail.com", "myshopify.com"],
    "stripe": ["stripe.com"],
    "coinbase": ["coinbase.com"],
    "binance": ["binance.com"],
    "revolut": ["revolut.com"],
    "n26": ["n26.com"],
    "dhl": ["dhl.com", "dhl.fr", "dhl.de"],
    "fedex": ["fedex.com"],
    "chronopost": ["chronopost.fr"],
    "colissimo": ["colissimo.fr", "laposte.fr"],
    "ameli": ["ameli.fr", "assurance-maladie.fr"],
    "impots": ["dgfip.finances.gouv.fr", "impots.gouv.fr"],
    "boursorama": ["boursorama.com", "boursobank.com"],
    "bnpparibas": ["bnpparibas.com", "bnpparibas.net", "mabanque.bnpparibas"],
    "societegenerale": ["societegenerale.fr", "sg.fr"],
    "labanquepostale": ["labanquepostale.fr"],
    "creditmutuel": ["creditmutuel.fr"],
    "creditagricole": ["credit-agricole.fr", "credit-agricole.com"],
    "fortuneo": ["fortuneo.fr"],
    "lydia": ["lydia-app.com", "sumeria.eu"],
}

FREEMAIL = {
    "gmail.com", "googlemail.com", "outlook.com", "outlook.fr", "hotmail.com",
    "hotmail.fr", "yahoo.com", "yahoo.fr", "live.fr", "live.com", "icloud.com",
    "me.com", "gmx.com", "gmx.fr", "laposte.net", "free.fr", "orange.fr",
    "protonmail.com", "proton.me", "aol.com", "wanadoo.fr", "sfr.fr",
}


def _domain(email: str) -> str:
    return email.split("@")[-1].lower().strip() if "@" in (email or "") else ""


def _tokens(s: str) -> set[str]:
    return {t for t in re.split(r"[^a-z0-9]+", (s or "").lower()) if t}


def _matches_official(domain: str, officials: list[str]) -> bool:
    return any(domain == o or domain.endswith("." + o) for o in officials)


def parse_auth(raw: str) -> str:
    """Résumé compact « spf=.. dkim=.. dmarc=.. » de Authentication-Results."""
    if not raw:
        return ""
    text = raw.lower()
    out = []
    for mech in ("spf", "dkim", "dmarc"):
        m = re.search(rf"{mech}=(\w+)", text)
        if m:
            out.append(f"{mech}={m.group(1)}")
    return " ".join(out)


def analyze(from_email: str, from_name: str, subject: str,
            reply_to: str = "", auth_summary: str = "") -> tuple[int, str]:
    """Renvoie (score 0-100, raison). 0 = non suspect."""
    domain = _domain(from_email)
    if not domain or "." not in domain:
        return 0, ""

    labels = domain.split(".")
    sld_label = labels[-2] if len(labels) >= 2 else labels[0]
    tld = labels[-1]
    sld_parts = sld_label.split("-")
    subdomain_labels = labels[:-2]
    local = from_email.split("@")[0] if "@" in from_email else ""
    name_tokens = _tokens(from_name) | _tokens(local)
    dmarc_fail = "dmarc=fail" in auth_summary
    in_freemail = domain in FREEMAIL

    best, reason = 0, ""
    for kw, officials in BRANDS.items():
        if _matches_official(domain, officials):
            continue  # domaine légitime de la marque

        # 1) marque combinée à d'autres mots dans le nom de domaine (paypal-secure.com)
        if kw in sld_parts and len(sld_parts) > 1:
            if best < 85:
                best, reason = 85, f"Domaine imitant « {kw} » ({domain})"
            continue
        # 2) marque utilisée en sous-domaine d'un domaine sans rapport (paypal.evil.com)
        if kw in subdomain_labels:
            if best < 85:
                best, reason = 85, f"« {kw} » en sous-domaine de {sld_label}.{tld} ({domain})"
            continue
        # 3) usurpation du nom affiché, uniquement si corroborée
        if kw in name_tokens:
            if in_freemail and best < 70:
                best, reason = 70, f"Se fait passer pour « {kw} » depuis une adresse perso ({domain})"
            elif dmarc_fail and best < 60:
                best, reason = 60, f"Se présente comme « {kw} » et échoue l'authentification ({domain})"

    return best, reason
