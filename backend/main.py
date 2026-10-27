# -*- coding: utf-8 -*-
"""
NetSentinel API —— FastAPI 入口

启动（Windows PowerShell）：
    .\\venv\\Scripts\\Activate.ps1
    uvicorn backend.main:app --reload --port 8000
浏览器打开 http://127.0.0.1:8000

安全约束（写进简历里能加分的部分）：
  - 目标白名单：默认只允许扫描私有网段与 localhost，扫公网需显式开关
  - 参数白名单：只允许 PROFILES 里预置的档位，不接受任意 nmap 选项
  - 单并发扫描，避免把本机网卡打满
"""
from __future__ import annotations

import ipaddress
import os
import sys
from typing import Any

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

import database as db
from parser import parse_nmap_xml
from risk import enrich
from scanner import PROFILES, NmapScanner, find_nmap, is_admin, preflight

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "data")
FRONTEND = os.path.join(BASE_DIR, "frontend")

os.makedirs(DATA_DIR, exist_ok=True)
db.DB_PATH = os.path.join(DATA_DIR, "netsentinel.db")
db.init_db(db.DB_PATH)

app = FastAPI(title="NetSentinel", description="资产测绘与漏洞关联平台", version="0.1.0")

# 扫描并发锁：单实例只允许一个扫描任务在跑
_scanning = False


# ---------------------------------------------------------------------------
# 目标合法性校验
# ---------------------------------------------------------------------------
def validate_target(target: str) -> tuple[bool, str]:
    """
    默认策略：只允许私有网段 / 回环 / 单个内网 IP。
    这是本项目最重要的安全边界——Web 化的扫描器最容易变成"别人的扫描代理"。
    """
    allow_public = os.environ.get("ALLOW_PUBLIC_SCAN", "0") == "1"
    target = target.strip()

    # 允许主机名形式（交给 nmap 自己解析，但公网域名在 allow_public 关闭时拒绝）
    try:
        net = ipaddress.ip_network(target, strict=False)
    except ValueError:
        if allow_public:
            return True, ""
        return False, "主机名形式的目标需要设置 ALLOW_PUBLIC_SCAN=1"

    for ip in net.hosts() if net.prefixlen < 32 else [net.network_address]:
        if ip.is_private or ip.is_loopback:
            continue
        if not allow_public:
            return False, f"目标 {ip} 属于公网地址，扫描公网需设置 ALLOW_PUBLIC_SCAN=1"
    return True, ""


# ---------------------------------------------------------------------------
# 请求模型
# ---------------------------------------------------------------------------
class ScanRequest(BaseModel):
    target: str = Field(..., examples=["192.168.1.0/24"])
    profile: str = Field("service", description="扫描档位名")
    timeout: int = Field(600, ge=30, le=3600)


# ---------------------------------------------------------------------------
# 路由
# ---------------------------------------------------------------------------
@app.get("/", response_class=HTMLResponse)
def index():
    return FileResponse(os.path.join(FRONTEND, "index.html"))


app.mount("/static", StaticFiles(directory=FRONTEND), name="static")


@app.get("/api/preflight")
def api_preflight() -> dict[str, Any]:
    """环境自检：nmap 路径、版本、是否管理员、可用档位。"""
    info = preflight()
    info["profiles"] = PROFILES
    info["allow_public"] = os.environ.get("ALLOW_PUBLIC_SCAN", "0") == "1"
    return info


@app.post("/api/scan")
def api_scan(req: ScanRequest) -> dict[str, Any]:
    global _scanning
    if _scanning:
        raise HTTPException(409, "已有扫描任务在执行，请稍后再试")
    if req.profile not in PROFILES:
        raise HTTPException(400, f"未知档位：{req.profile}，可选：{list(PROFILES)}")

    ok, msg = validate_target(req.target)
    if not ok:
        raise HTTPException(403, msg)

    options = PROFILES[req.profile]["options"]
    # OS 指纹需要管理员权限，Windows 下非管理员会静默失败，提前拦
    if "-O" in options and not is_admin():
        raise HTTPException(403, "OS 指纹扫描需要管理员权限，请以管理员身份启动或选择其他档位")

    _scanning = True
    try:
        scanner = NmapScanner(os.environ.get("NMAP_PATH"))
        result = scanner.scan(req.target, options, timeout=req.timeout)
    except Exception as e:
        raise HTTPException(500, f"扫描失败：{e}")
    finally:
        _scanning = False

    if result.returncode != 0 and not result.xml:
        raise HTTPException(500, f"nmap 执行失败（rc={result.returncode}）：{result.stderr[:500]}")

    try:
        report = enrich(parse_nmap_xml(result.xml))
    except Exception as e:
        raise HTTPException(500, f"解析扫描结果失败：{e}")

    scan_id = db.save_report(report, req.target, options, result.duration, result.xml)
    return {"scan_id": scan_id, "report": report, "duration": result.duration,
            "command": result.command, "stderr": result.stderr[-2000:]}


@app.get("/api/scans")
def api_scans(limit: int = 50):
    return db.list_scans(limit, db.DB_PATH)


@app.get("/api/scan/{scan_id}")
def api_scan_detail(scan_id: int):
    data = db.get_scan(scan_id, db.DB_PATH)
    if not data:
        raise HTTPException(404, "扫描记录不存在")
    data["scan"].pop("raw_xml", None)  # 原始 XML 可能很大，列表页不返回
    return data


@app.get("/api/diff")
def api_diff(a: int, b: int):
    """对比两次扫描，输出资产变更。"""
    return db.diff_scans(a, b, db.DB_PATH)


@app.get("/api/stats")
def api_stats():
    """全局统计：累计主机数、端口数、按等级的风险分布。"""
    with db.get_conn(db.DB_PATH) as conn:
        hosts = conn.execute("SELECT COUNT(DISTINCT address) c FROM host").fetchone()["c"]
        ports = conn.execute("SELECT COUNT(*) c FROM port WHERE state='open'").fetchone()["c"]
        rows = conn.execute(
            "SELECT level, COUNT(*) c FROM finding GROUP BY level").fetchall()
    return {"hosts": hosts, "open_ports": ports,
            "findings_by_level": {r["level"]: r["c"] for r in rows}}
