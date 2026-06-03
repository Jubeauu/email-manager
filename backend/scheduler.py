"""Scan automatique programmé (thread de fond)."""
from __future__ import annotations

import json
import threading
import time
from pathlib import Path
from typing import Any, Callable

SCHEDULE_FILE = Path(__file__).resolve().parent.parent / "data" / "schedule.json"

_DEFAULT = {
    "enabled": False,
    "interval_hours": 24,
    "scan_all": False,
    "apply_rules": True,
    "last_run": 0,
}


def get_config() -> dict[str, Any]:
    if not SCHEDULE_FILE.exists():
        return dict(_DEFAULT)
    try:
        return {**_DEFAULT, **json.loads(SCHEDULE_FILE.read_text(encoding="utf-8"))}
    except json.JSONDecodeError:
        return dict(_DEFAULT)


def set_config(updates: dict[str, Any]) -> dict[str, Any]:
    cfg = {**get_config(), **updates}
    SCHEDULE_FILE.write_text(json.dumps(cfg, ensure_ascii=False, indent=2),
                             encoding="utf-8")
    return cfg


def _mark_run() -> None:
    set_config({"last_run": int(time.time())})


def start(run_scan: Callable[[], None]) -> None:
    """Démarre la boucle de planification. `run_scan` lance un scan complet (bloquant)."""
    def loop():
        while True:
            try:
                cfg = get_config()
                if cfg.get("enabled"):
                    due = cfg.get("last_run", 0) + cfg.get("interval_hours", 24) * 3600
                    if time.time() >= due:
                        run_scan()
                        _mark_run()
            except Exception:  # noqa: BLE001
                pass
            time.sleep(60)  # vérifie chaque minute

    threading.Thread(target=loop, daemon=True).start()
