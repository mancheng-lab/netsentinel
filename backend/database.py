# -*- coding: utf-8 -*-
"""
持久化层 —— SQLite

为什么选 SQLite：零配置、单文件、便于提交演示；对单机测绘平台足够。
若要多人协作/多实例写入，再迁移 Postgres（SQLAlchemy 层不用改表结构逻辑）。

核心设计：
  - scan      一次扫描任务
  - host      主机（按 address 聚合，保留 last_seen）
  - port      端口（记录每次扫描的状态，用于时序 diff）
  - finding   风险项（暴露面 / CVE）

时序 diff 的实现思路：同一 (address, port) 在不同 scan_id 下各留一条记录，
对比两次 scan_id 即可得出"新增端口 / 端口关闭 / 服务版本变更"。
这也是 Zenmap 的 DiffCompare 手工操作的自动化版本。
"""
from __future__ import annotations

import json
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime
from typing import Any

DB_PATH = os.environ.get("NETSENTINEL_DB", "data/netsentinel.db")

SCHEMA = """
CREATE TABLE IF NOT EXISTS scan (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    target      TEXT NOT NULL,
    options     TEXT,
    started_at  TEXT NOT NULL,
    finished_at TEXT,
    duration    REAL,
    hosts_up    INTEGER DEFAULT 0,
    open_ports  INTEGER DEFAULT 0,
    findings    INTEGER DEFAULT 0,
    max_risk    INTEGER DEFAULT 0,
    raw_xml     TEXT
);

CREATE TABLE IF NOT EXISTS host (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id    INTEGER NOT NULL,
    address    TEXT NOT NULL,
    hostname   TEXT,
    mac        TEXT,
    os         TEXT,
    status     TEXT,
    risk_score INTEGER DEFAULT 0,
    risk_level TEXT,
    FOREIGN KEY (scan_id) REFERENCES scan(id)
);

CREATE TABLE IF NOT EXISTS port (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id    INTEGER NOT NULL,
    address    TEXT NOT NULL,
    port       INTEGER NOT NULL,
    protocol   TEXT,
    state      TEXT,
    service    TEXT,
    product    TEXT,
    version    TEXT,
    cpe        TEXT,
    risk_score INTEGER DEFAULT 0,
    risk_level TEXT,
    FOREIGN KEY (scan_id) REFERENCES scan(id)
);

CREATE TABLE IF NOT EXISTS finding (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    address TEXT NOT NULL,
    port    INTEGER,
    type    TEXT,
    level   TEXT,
    title   TEXT,
    advice  TEXT,
    FOREIGN KEY (scan_id) REFERENCES scan(id)
);

CREATE INDEX IF NOT EXISTS idx_host_addr   ON host(address);
CREATE INDEX IF NOT EXISTS idx_port_addr   ON port(address, port);
CREATE INDEX IF NOT EXISTS idx_finding_lvl ON finding(level);
"""


def init_db(db_path: str = DB_PATH) -> None:
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    with sqlite3.connect(db_path) as c:
        c.executescript(SCHEMA)


@contextmanager
def get_conn(db_path: str = DB_PATH):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def save_report(report: dict[str, Any], target: str, options: str,
                duration: float, raw_xml: str = "",
                db_path: str = DB_PATH) -> int:
    """把一份富化后的报告落库，返回 scan_id。"""
    now = datetime.now().isoformat(timespec="seconds")
    summary = report.get("summary", {})

    with get_conn(db_path) as conn:
        cur = conn.execute(
            "INSERT INTO scan (target, options, started_at, finished_at, duration,"
            " hosts_up, open_ports, findings, max_risk, raw_xml)"
            " VALUES (?,?,?,?,?,?,?,?,?,?)",
            (target, options, now, now, duration,
             summary.get("up", 0), summary.get("open_ports", 0),
             summary.get("findings", 0), summary.get("max_risk", 0), raw_xml),
        )
        scan_id = cur.lastrowid

        for h in report.get("hosts", []):
            conn.execute(
                "INSERT INTO host (scan_id, address, hostname, mac, os, status,"
                " risk_score, risk_level) VALUES (?,?,?,?,?,?,?,?)",
                (scan_id, h["address"], h.get("hostname", ""), h.get("mac", ""),
                 h.get("os", ""), h.get("status", ""),
                 h.get("risk_score", 0), h.get("risk_level", "")),
            )
            for p in h.get("ports", []):
                conn.execute(
                    "INSERT INTO port (scan_id, address, port, protocol, state,"
                    " service, product, version, cpe, risk_score, risk_level)"
                    " VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                    (scan_id, h["address"], p["port"], p.get("protocol"),
                     p.get("state"), p.get("service"), p.get("product"),
                     p.get("version"), p.get("cpe"),
                     p.get("risk_score", 0), p.get("risk_level", "")),
                )
                for f in p.get("findings", []):
                    conn.execute(
                        "INSERT INTO finding (scan_id, address, port, type, level,"
                        " title, advice) VALUES (?,?,?,?,?,?,?)",
                        (scan_id, h["address"], p["port"], f["type"],
                         f["level"], f["title"], f["advice"]),
                    )
        return scan_id


def list_scans(limit: int = 50, db_path: str = DB_PATH) -> list[dict]:
    with get_conn(db_path) as conn:
        rows = conn.execute(
            "SELECT id, target, options, started_at, duration, hosts_up,"
            " open_ports, findings, max_risk FROM scan"
            " ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
    return [dict(r) for r in rows]


def get_scan(scan_id: int, db_path: str = DB_PATH) -> dict | None:
    with get_conn(db_path) as conn:
        s = conn.execute("SELECT * FROM scan WHERE id=?", (scan_id,)).fetchone()
        if not s:
            return None
        hosts = conn.execute("SELECT * FROM host WHERE scan_id=?", (scan_id,)).fetchall()
        ports = conn.execute("SELECT * FROM port WHERE scan_id=?", (scan_id,)).fetchall()
        findings = conn.execute(
            "SELECT * FROM finding WHERE scan_id=? ORDER BY level", (scan_id,)).fetchall()
    return {
        "scan": dict(s),
        "hosts": [dict(h) for h in hosts],
        "ports": [dict(p) for p in ports],
        "findings": [dict(f) for f in findings],
    }


def diff_scans(a: int, b: int, db_path: str = DB_PATH) -> dict:
    """
    对比两次扫描（a 为旧，b 为新），返回资产变更。
    这正是 Zenmap DiffCompare 的自动化版本，且能跨任意两次历史扫描。
    """
    def portmap(sid: int) -> dict[tuple, dict]:
        with get_conn(db_path) as conn:
            rows = conn.execute(
                "SELECT address, port, protocol, state, service, product, version"
                " FROM port WHERE scan_id=?", (sid,)).fetchall()
        return {(r["address"], r["port"]): dict(r) for r in rows}

    old, new = portmap(a), portmap(b)
    added = [new[k] for k in new if k not in old]
    removed = [old[k] for k in old if k not in new]
    changed = []
    for k in old:
        if k not in new:
            continue
        o, n = old[k], new[k]
        if (o["state"], o["product"], o["version"]) != (n["state"], n["product"], n["version"]):
            changed.append({"old": o, "new": n})

    return {"added": added, "removed": removed, "changed": changed}
