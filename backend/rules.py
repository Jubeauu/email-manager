"""Règles de tri persistantes + liste d'expéditeurs protégés + nettoyage auto."""
from __future__ import annotations

import json
import uuid
from pathlib import Path
from typing import Any

RULES_FILE = Path(__file__).resolve().parent.parent / "data" / "rules.json"


def _load() -> dict[str, Any]:
    if not RULES_FILE.exists():
        return {"protected": [], "rules": []}
    try:
        data = json.loads(RULES_FILE.read_text(encoding="utf-8"))
        data.setdefault("protected", [])
        data.setdefault("rules", [])
        return data
    except json.JSONDecodeError:
        return {"protected": [], "rules": []}


def _save(data: dict[str, Any]) -> None:
    RULES_FILE.write_text(json.dumps(data, ensure_ascii=False, indent=2),
                          encoding="utf-8")


def get_all() -> dict[str, Any]:
    return _load()


def add_rule(rule: dict[str, Any]) -> dict[str, Any]:
    data = _load()
    rule["id"] = uuid.uuid4().hex[:10]
    data["rules"].append(rule)
    _save(data)
    return rule


def delete_rule(rule_id: str) -> None:
    data = _load()
    data["rules"] = [r for r in data["rules"] if r.get("id") != rule_id]
    _save(data)


def set_protected(protected: list[str]) -> None:
    data = _load()
    data["protected"] = [p.strip().lower() for p in protected if p.strip()]
    _save(data)


def is_protected(from_email: str) -> bool:
    data = _load()
    email = (from_email or "").lower()
    domain = email.split("@")[-1] if "@" in email else ""
    for p in data["protected"]:
        if p == email or (domain and (p == domain or domain.endswith(p))):
            return True
    return False


def _sender_matches(rule: dict[str, Any], sender: dict[str, Any], category: str) -> bool:
    value = (rule.get("value") or "").lower().strip()
    email = (sender.get("from_email") or "").lower()
    domain = email.split("@")[-1] if "@" in email else ""
    mtype = rule.get("match_type")
    if mtype == "sender":
        return value == email or value in email
    if mtype == "domain":
        return bool(domain) and (domain == value or domain.endswith(value))
    if mtype == "category":
        return category.lower() == value
    return False


def apply_rules(account_ids: list[str] | None = None, log=None) -> dict[str, Any]:
    """Applique toutes les règles aux messages en cache (déplace/supprime/archive)."""
    import categorize
    import db
    import imap_client as imap

    data = _load()
    rules = data["rules"]
    if not rules:
        return {"applied": 0, "details": []}

    accounts = {a["id"]: a for a in db.load_accounts()
                if not account_ids or a["id"] in account_ids}
    senders = db.senders_summary("all")
    details = []
    applied = 0

    for sender in senders:
        if is_protected(sender["from_email"]):
            continue
        category = categorize.categorize(
            sender["from_email"], sender.get("from_name", ""),
            sender.get("has_unsub", 0), sender.get("promo_count", 0),
            sender.get("phishing_score", 0),
        )
        for rule in rules:
            if not _sender_matches(rule, sender, category):
                continue
            for acc_id in (sender.get("account_ids") or "").split(","):
                acc = accounts.get(acc_id)
                if not acc:
                    continue
                folder_uids = db.folder_uids_for_sender(sender["from_email"], acc_id)
                if not folder_uids:
                    continue
                try:
                    action = rule.get("action")
                    if action == "delete":
                        imap.delete_messages(acc, folder_uids)
                    elif action == "archive":
                        imap.archive_messages(acc, folder_uids)
                    elif action == "move":
                        imap.move_messages(acc, folder_uids, rule.get("target", "Trié"))
                    db.delete_cached_sender(acc_id, sender["from_email"])
                    applied += 1
                    msg = f"{action} : {sender['from_email']} ({acc['label']})"
                    details.append(msg)
                    if log is not None:
                        log.append("⚙ " + msg)
                except Exception as exc:  # noqa: BLE001
                    if log is not None:
                        log.append(f"✗ règle {sender['from_email']} : {exc}")
            break  # une règle suffit par expéditeur
    return {"applied": applied, "details": details}
