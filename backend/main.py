"""API FastAPI : comptes, scan multi-dossiers, anti-phishing, règles, planning."""
from __future__ import annotations

import csv
import io
import threading
import time
from pathlib import Path
from typing import Any

from fastapi import Body, FastAPI, HTTPException
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

import categorize
import db
import imap_client as imap
import oauth_ms
import rules as rules_mod
import scheduler
import unsubscribe as unsub

app = FastAPI(title="Email Manager")
db.init_db()


@app.middleware("http")
async def no_cache_assets(request, call_next):
    """Empêche le navigateur de garder en cache l'interface (CSS/JS/HTML)."""
    response = await call_next(request)
    path = request.url.path
    if path == "/" or path.endswith((".js", ".css", ".html")):
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"
    return response

FRONTEND = Path(__file__).resolve().parent.parent / "frontend"

_scan_state: dict[str, Any] = {
    "running": False, "done": 0, "total": 0, "current": "", "log": [], "finished_at": 0,
}
_unsub_state: dict[str, Any] = {
    "running": False, "done": 0, "total": 0, "log": [], "finished_at": 0,
}

_SECRET_FIELDS = {"password", "access_token", "refresh_token"}


def _safe_account(a: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in a.items() if k not in _SECRET_FIELDS}


def _with_category(s: dict[str, Any]) -> dict[str, Any]:
    s["category"] = categorize.categorize(
        s.get("from_email", ""), s.get("from_name", ""), s.get("has_unsub", 0),
        s.get("promo_count", 0), s.get("phishing_score", 0),
    )
    s["protected"] = rules_mod.is_protected(s.get("from_email", ""))
    return s


# --------------------------------------------------------------------------- #
# Comptes
# --------------------------------------------------------------------------- #
@app.get("/api/accounts")
def get_accounts():
    return [_safe_account(a) for a in db.load_accounts()]


@app.post("/api/accounts")
def create_account(payload: dict[str, Any] = Body(...)):
    email_addr = (payload.get("email") or "").strip()
    password = payload.get("password") or ""
    if not email_addr or not password:
        raise HTTPException(400, "Email et mot de passe requis")
    host = (payload.get("imap_host") or "").strip()
    port = payload.get("imap_port")
    if not host:
        host, guessed_port = imap.guess_imap(email_addr)
        port = port or guessed_port
        if not host:
            raise HTTPException(400, "Serveur IMAP inconnu : renseigne-le manuellement.")
    account = {
        "label": payload.get("label") or email_addr,
        "email": email_addr,
        "username": payload.get("username") or email_addr,
        "password": password,
        "imap_host": host,
        "imap_port": int(port or 993),
    }
    test = imap.test_connection(account)
    if not test["ok"]:
        raise HTTPException(400, f"Connexion échouée : {test['error']}")
    saved = db.add_account(account)
    return {"account": _safe_account(saved), "inbox_count": test.get("inbox_count")}


@app.post("/api/accounts/test")
def test_account(payload: dict[str, Any] = Body(...)):
    email_addr = (payload.get("email") or "").strip()
    host = (payload.get("imap_host") or "").strip()
    port = payload.get("imap_port")
    if not host:
        host, guessed = imap.guess_imap(email_addr)
        port = port or guessed
    account = {
        "username": payload.get("username") or email_addr,
        "password": payload.get("password") or "",
        "imap_host": host,
        "imap_port": int(port or 993),
    }
    return imap.test_connection(account)


@app.delete("/api/accounts/{account_id}")
def remove_account(account_id: str):
    db.delete_account(account_id)
    return {"ok": True}


@app.get("/api/guess")
def guess(email: str):
    host, port = imap.guess_imap(email)
    return {"imap_host": host, "imap_port": port}


# --------------------------------------------------------------------------- #
# OAuth Microsoft
# --------------------------------------------------------------------------- #
@app.post("/api/oauth/ms/start")
def oauth_ms_start(payload: dict[str, Any] = Body(...)):
    client_id = (payload.get("client_id") or "").strip() or oauth_ms.THUNDERBIRD_CLIENT_ID
    try:
        flow = oauth_ms.start_device_flow(client_id)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(400, f"Échec du démarrage OAuth : {exc}")
    return {
        "device_code": flow["device_code"],
        "user_code": flow["user_code"],
        "verification_uri": flow.get("verification_uri", "https://microsoft.com/devicelogin"),
        "interval": flow.get("interval", 5),
        "expires_in": flow.get("expires_in", 900),
    }


@app.post("/api/oauth/ms/poll")
def oauth_ms_poll(payload: dict[str, Any] = Body(...)):
    client_id = (payload.get("client_id") or "").strip() or oauth_ms.THUNDERBIRD_CLIENT_ID
    device_code = payload.get("device_code") or ""
    res = oauth_ms.poll_token(client_id, device_code)
    if res["status"] != "ok":
        return res
    email_addr = oauth_ms.email_from_id_token(res.get("id_token", "")) \
        or (payload.get("email") or "").strip().lower()
    if not email_addr:
        return {"status": "error", "error": "no_email",
                "description": "Impossible de déterminer l'adresse e-mail."}
    account = {
        "label": payload.get("label") or email_addr,
        "email": email_addr, "username": email_addr,
        "auth_type": "oauth_ms", "client_id": client_id,
        "access_token": res["access_token"],
        "refresh_token": res.get("refresh_token", ""),
        "token_expiry": res["token_expiry"],
        "imap_host": "outlook.office365.com", "imap_port": 993,
    }
    test = imap.test_connection(account)
    if not test["ok"]:
        return {"status": "error", "error": "imap_failed", "description": test["error"]}
    saved = db.add_account(account)
    return {"status": "ok", "account": _safe_account(saved),
            "inbox_count": test.get("inbox_count")}


# --------------------------------------------------------------------------- #
# Scan
# --------------------------------------------------------------------------- #
def _run_scan(account_ids: list[str], scan_all: bool, do_apply_rules: bool,
              incremental: bool = True, since_days: int | None = None):
    _scan_state.update(running=True, done=0, total=0, current="", log=[])
    try:
        accounts = [a for a in db.load_accounts()
                    if not account_ids or a["id"] in account_ids]
        for acc in accounts:
            _scan_state["current"] = acc["label"]
            if not incremental:
                # scan complet/par période : on repart de zéro pour ce compte
                db.clear_account_cache(acc["id"])
                db.reset_scan_state(acc["id"])

            def progress(done, total):
                _scan_state["done"] = done
                _scan_state["total"] = total

            try:
                rows = imap.scan_account(acc, scan_all=scan_all,
                                         incremental=incremental,
                                         since_days=since_days, progress=progress)
                db.insert_messages(rows)
                susp = sum(1 for r in rows if r["phishing_score"] > 0)
                noun = "nouveaux mails" if incremental else "mails"
                _scan_state["log"].append(
                    f"✓ {acc['label']} : {len(rows)} {noun}"
                    + (f", {susp} suspect(s)" if susp else "")
                )
            except Exception as exc:  # noqa: BLE001
                _scan_state["log"].append(f"✗ {acc['label']} : {exc}")
        if do_apply_rules:
            res = rules_mod.apply_rules(account_ids, log=_scan_state["log"])
            if res["applied"]:
                _scan_state["log"].append(f"⚙ {res['applied']} action(s) auto par règles")
    finally:
        _scan_state["running"] = False
        _scan_state["current"] = ""
        _scan_state["finished_at"] = int(time.time())


# Modes de scan -> (incrémental ?, période en jours)
_SCAN_MODES = {
    "new": (True, None),    # uniquement les nouveaux mails (rapide)
    "3m": (False, 90),      # 3 derniers mois
    "1y": (False, 365),     # dernière année
    "all": (False, None),   # tout
}


def _scheduled_scan():
    cfg = scheduler.get_config()
    _run_scan([], cfg.get("scan_all", False), cfg.get("apply_rules", True),
              incremental=True)  # le scan auto est toujours incrémental (rapide)


@app.post("/api/scan")
def start_scan(payload: dict[str, Any] = Body(default={})):
    if _scan_state["running"]:
        raise HTTPException(409, "Un scan est déjà en cours")
    account_ids = payload.get("account_ids") or []
    scan_all = bool(payload.get("scan_all", False))
    do_apply = bool(payload.get("apply_rules", True))
    incremental, since_days = _SCAN_MODES.get(payload.get("mode", "new"), (True, None))
    threading.Thread(
        target=_run_scan,
        args=(account_ids, scan_all, do_apply, incremental, since_days),
        daemon=True,
    ).start()
    return {"ok": True}


@app.get("/api/scan/status")
def scan_status():
    return _scan_state


# --------------------------------------------------------------------------- #
# Statistiques / expéditeurs / suspects
# --------------------------------------------------------------------------- #
@app.get("/api/stats")
def stats(account: str = "all"):
    return db.global_stats(account)


@app.get("/api/senders")
def senders(account: str = "all"):
    return [_with_category(s) for s in db.senders_summary(account)]


@app.get("/api/suspicious")
def suspicious(account: str = "all"):
    return db.suspicious_senders(account)


@app.get("/api/senders/messages")
def sender_messages(email: str, account: str = "all"):
    return db.messages_for_sender(email, account)


@app.get("/api/folders/scanned")
def folders_scanned(account: str = "all"):
    return db.folders_scanned(account)


# --------------------------------------------------------------------------- #
# Actions
# --------------------------------------------------------------------------- #
def _resolve_targets(payload: dict[str, Any]):
    """Renvoie [(compte, {folder: [uids]}, sender_or_None)]."""
    sender = payload.get("sender")
    explicit = payload.get("account_id")
    out = []
    if sender:
        accounts = db.load_accounts()
        if explicit and explicit != "all":
            accounts = [a for a in accounts if a["id"] == explicit]
        for acc in accounts:
            fu = db.folder_uids_for_sender(sender, acc["id"])
            if fu:
                out.append((acc, fu, sender))
    elif payload.get("uids") and explicit:
        acc = db.get_account(explicit)
        if acc:
            fu = db.folder_uids_for_uids(explicit, [int(u) for u in payload["uids"]])
            if fu:
                out.append((acc, fu, None))
    return out


def _purge_cache(acc_id: str, fu: dict[str, list[int]], sender: str | None):
    if sender:
        db.delete_cached_sender(acc_id, sender)
    else:
        for uids in fu.values():
            db.delete_cached_uids(acc_id, uids)


@app.post("/api/actions/delete")
def action_delete(payload: dict[str, Any] = Body(...)):
    results = []
    for acc, fu, sender in _resolve_targets(payload):
        res = imap.delete_messages(acc, fu)
        _purge_cache(acc["id"], fu, sender)
        results.append({"account": acc["label"], **res})
    return {"ok": True, "results": results}


@app.post("/api/actions/archive")
def action_archive(payload: dict[str, Any] = Body(...)):
    results = []
    for acc, fu, sender in _resolve_targets(payload):
        res = imap.archive_messages(acc, fu)
        _purge_cache(acc["id"], fu, sender)
        results.append({"account": acc["label"], **res})
    return {"ok": True, "results": results}


@app.post("/api/actions/move")
def action_move(payload: dict[str, Any] = Body(...)):
    target = payload.get("folder")
    if not target:
        raise HTTPException(400, "Dossier cible requis")
    results = []
    for acc, fu, sender in _resolve_targets(payload):
        res = imap.move_messages(acc, fu, target)
        _purge_cache(acc["id"], fu, sender)
        results.append({"account": acc["label"], **res})
    return {"ok": True, "results": results}


@app.post("/api/actions/unsubscribe")
def action_unsubscribe(payload: dict[str, Any] = Body(...)):
    header = payload.get("list_unsubscribe") or ""
    sender = payload.get("sender") or ""
    if not header:
        raise HTTPException(400, "Aucun en-tête List-Unsubscribe pour cet expéditeur")
    # un compte qui possède ce sender (pour l'éventuel envoi mailto)
    account = None
    for acc in db.load_accounts():
        if db.folder_uids_for_sender(sender, acc["id"]):
            account = acc
            break
    if account is None:
        account = (db.load_accounts() or [None])[0]
    res = unsub.full_unsubscribe(account, header) if account \
        else unsub.one_click_unsubscribe(header)
    if res.get("ok") and sender:
        db.mark_unsubscribed(sender, res.get("method", "?"))
    return res


@app.get("/api/unsubscribe/status")
def unsub_status():
    return _unsub_state


def _run_unsub_all(account_filter: str):
    _unsub_state.update(running=True, done=0, total=0, log=[])
    try:
        senders = [s for s in db.senders_summary(account_filter)
                   if s.get("has_unsub") and not s.get("unsubscribed")
                   and s.get("list_unsubscribe")]
        _unsub_state["total"] = len(senders)
        accounts = {a["id"]: a for a in db.load_accounts()}
        for s in senders:
            acc_id = (s.get("account_ids") or "").split(",")[0]
            acc = accounts.get(acc_id)
            try:
                res = unsub.full_unsubscribe(acc, s["list_unsubscribe"]) if acc \
                    else unsub.one_click_unsubscribe(s["list_unsubscribe"])
                if res.get("ok"):
                    db.mark_unsubscribed(s["from_email"], res.get("method", "?"))
                    _unsub_state["log"].append(f"✓ {s['from_email']}")
                else:
                    _unsub_state["log"].append(f"… {s['from_email']} (manuel)")
            except Exception as exc:  # noqa: BLE001
                _unsub_state["log"].append(f"✗ {s['from_email']} : {exc}")
            _unsub_state["done"] += 1
    finally:
        _unsub_state["running"] = False
        _unsub_state["finished_at"] = int(time.time())


@app.post("/api/actions/unsubscribe_all")
def action_unsubscribe_all(payload: dict[str, Any] = Body(default={})):
    if _unsub_state["running"]:
        raise HTTPException(409, "Désabonnement déjà en cours")
    account_filter = payload.get("account") or "all"
    threading.Thread(target=_run_unsub_all, args=(account_filter,), daemon=True).start()
    return {"ok": True}


# --------------------------------------------------------------------------- #
# Règles + expéditeurs protégés
# --------------------------------------------------------------------------- #
@app.get("/api/rules")
def get_rules():
    return rules_mod.get_all()


@app.post("/api/rules")
def add_rule(payload: dict[str, Any] = Body(...)):
    if not payload.get("match_type") or not payload.get("action"):
        raise HTTPException(400, "match_type et action requis")
    return rules_mod.add_rule(payload)


@app.delete("/api/rules/{rule_id}")
def delete_rule(rule_id: str):
    rules_mod.delete_rule(rule_id)
    return {"ok": True}


@app.put("/api/rules/protected")
def set_protected(payload: dict[str, Any] = Body(...)):
    rules_mod.set_protected(payload.get("protected") or [])
    return {"ok": True}


@app.post("/api/rules/apply")
def apply_rules_now():
    log: list[str] = []
    res = rules_mod.apply_rules(None, log=log)
    return {**res, "log": log}


# --------------------------------------------------------------------------- #
# Planification
# --------------------------------------------------------------------------- #
@app.get("/api/schedule")
def get_schedule():
    return scheduler.get_config()


@app.put("/api/schedule")
def set_schedule(payload: dict[str, Any] = Body(...)):
    return scheduler.set_config(payload)


# --------------------------------------------------------------------------- #
# Insights + export
# --------------------------------------------------------------------------- #
@app.get("/api/insights")
def insights(account: str = "all"):
    return {
        "volume_by_month": db.volume_by_month(account),
        "top_size": db.top_size_senders(account),
        "dormant": db.dormant_senders(account),
    }


@app.get("/api/export")
def export(account: str = "all", format: str = "csv"):
    rows = [_with_category(s) for s in db.senders_summary(account)]
    headers = ["from_email", "from_name", "category", "count", "promo_count",
               "unread_count", "phishing_score", "has_unsub", "total_size", "last_ts"]
    if format == "xlsx":
        try:
            from openpyxl import Workbook
        except Exception:  # noqa: BLE001
            raise HTTPException(400, "openpyxl non installé pour l'export Excel")
        wb = Workbook()
        ws = wb.active
        ws.title = "Expéditeurs"
        ws.append(headers)
        for r in rows:
            ws.append([r.get(h) for h in headers])
        out = Path(db.DATA_DIR) / "export.xlsx"
        wb.save(out)
        return FileResponse(out, filename="email-manager-export.xlsx")
    # CSV par défaut
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=headers, extrasaction="ignore")
    writer.writeheader()
    for r in rows:
        writer.writerow({h: r.get(h) for h in headers})
    return StreamingResponse(
        iter([buf.getvalue()]), media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=email-manager-export.csv"},
    )


@app.get("/api/folders")
def folders(account_id: str):
    acc = db.get_account(account_id)
    if not acc:
        raise HTTPException(404, "Compte introuvable")
    try:
        return imap.list_folders(acc)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(400, str(exc))


# --------------------------------------------------------------------------- #
# Frontend
# --------------------------------------------------------------------------- #
@app.get("/")
def index():
    return FileResponse(FRONTEND / "index.html")


# Démarre le planificateur de fond
scheduler.start(_scheduled_scan)

app.mount("/", StaticFiles(directory=str(FRONTEND)), name="static")
