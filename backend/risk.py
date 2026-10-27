# -*- coding: utf-8 -*-
"""
风险评分与 CVE 关联层 —— 本项目的差异化所在

Nmap 只告诉你"跑了 nginx 1.18.0"，不告诉你"这个版本有什么洞"。
这一层把 service/product/version → 风险项 + CVE 编号。

设计成两级：
  1. 本地规则库（离线可用，秒级响应）—— 覆盖常见服务的高危暴露与已知 CVE
  2. NVD API（可选，需联网）—— 用 CPE 精确查询，结果本地缓存

生产化建议：本地规则库只做"兜底 + 快速判断"，真正的 CVE 覆盖应依赖
定期同步 NVD / CNNVD 数据快照到本地 SQLite，避免每次请求打外部 API。
"""
from __future__ import annotations

import re
import sqlite3
from typing import Any

# ---------------------------------------------------------------------------
# 一、暴露面基线：某些服务一旦暴露在外网就是高危，与版本无关
# ---------------------------------------------------------------------------
EXPOSURE_RULES: list[dict[str, Any]] = [
    {"ports": {6379, 6380}, "service": "redis", "level": "CRITICAL",
     "title": "Redis 暴露", "advice": "Redis 默认无认证，暴露即等于服务器沦陷。应绑定内网地址并设置 requirepass。"},
    {"ports": {27017, 27018}, "service": "mongodb", "level": "CRITICAL",
     "title": "MongoDB 暴露", "advice": "MongoDB 默认无认证，历史上被大规模勒索。应开启 auth 并限制来源 IP。"},
    {"ports": {9200, 9300}, "service": "elasticsearch", "level": "CRITICAL",
     "title": "Elasticsearch 暴露", "advice": "ES 未授权可读取/删除全部索引，应启用安全模块。"},
    {"ports": {2375, 2376}, "service": "docker", "level": "CRITICAL",
     "title": "Docker Remote API 暴露", "advice": "2375 端口等于把宿主机 root 交出去，必须关闭或加 TLS 认证。"},
    {"ports": {11211}, "service": "memcached", "level": "HIGH",
     "title": "Memcached 暴露", "advice": "可被用于 DDoS 反射放大，应绑定 127.0.0.1。"},
    {"ports": {3306}, "service": "mysql", "level": "HIGH",
     "title": "MySQL 暴露", "advice": "数据库不应直接暴露，应限制来源并禁用 root 远程登录。"},
    {"ports": {1433}, "service": "ms-sql", "level": "HIGH",
     "title": "MSSQL 暴露", "advice": "常被暴力破解，应改端口 + 强口令 + 限制来源。"},
    {"ports": {3389}, "service": "ms-wbt-server", "level": "HIGH",
     "title": "RDP 暴露", "advice": "RDP 是勒索软件主要入口，应仅通过 VPN 访问并开启 NLA。"},
    {"ports": {445, 139}, "service": "microsoft-ds", "level": "HIGH",
     "title": "SMB 暴露", "advice": "SMB 历来是蠕虫与勒索重灾区（EternalBlue、SMBGhost），应关闭不必要的共享。"},
    {"ports": {23}, "service": "telnet", "level": "HIGH",
     "title": "Telnet 明文传输", "advice": "Telnet 明文传输凭据，应改用 SSH。"},
    {"ports": {21}, "service": "ftp", "level": "MEDIUM",
     "title": "FTP 明文传输", "advice": "FTP 明文传输，应改用 SFTP/FTPS。"},
    {"ports": {5900}, "service": "vnc", "level": "HIGH",
     "title": "VNC 暴露", "advice": "VNC 常弱口令，应设强密码并走 SSH 隧道。"},
    {"ports": {10250, 10255}, "service": "kubelet", "level": "CRITICAL",
     "title": "Kubelet API 暴露", "advice": "Kubelet 未授权可在容器内执行任意命令，进而逃逸到宿主机。"},
    {"ports": {6443}, "service": "kubernetes", "level": "HIGH",
     "title": "Kubernetes API 暴露", "advice": "应启用 RBAC 与鉴权，禁止匿名访问。"},
    {"ports": {8080, 8081, 8888, 9000}, "service": "*", "level": "INFO",
     "title": "常见管理/代理端口", "advice": "确认是否为管理后台或代理，避免未授权访问。"},
]

# ---------------------------------------------------------------------------
# 二、已知 CVE 规则库（离线兜底）
# 格式：服务名 -> [(版本区间判定函数, CVE, 描述, 等级)]
# 版本比较用简单的元组比较，够用且直观
# ---------------------------------------------------------------------------
def _ver(s: str) -> tuple:
    """把 '7.4' / '1.18.0' 转成可比较的元组；解析失败返回 (0,)"""
    nums = re.findall(r"\d+", s or "")
    return tuple(int(n) for n in nums) if nums else (0,)


CVE_RULES: dict[str, list[dict[str, Any]]] = {
    "openssh": [
        {"max": (7, 4), "cve": "CVE-2016-10009", "level": "HIGH",
         "desc": "OpenSSH < 7.4 存在转发信息泄露（roaming）"},
        {"max": (7, 7), "cve": "CVE-2018-15473", "level": "MEDIUM",
         "desc": "OpenSSH < 7.7 用户名枚举"},
    ],
    "nginx": [
        {"max": (1, 20, 0), "cve": "CVE-2021-23017", "level": "HIGH",
         "desc": "nginx resolver off-by-one，可导致 RCE"},
        {"max": (1, 18, 0), "cve": "CVE-2019-20372", "level": "MEDIUM",
         "desc": "nginx < 1.17.7 存在栈读取越界"},
    ],
    "redis": [
        {"max": (6, 0, 0), "cve": "CVE-2022-24736", "level": "HIGH",
         "desc": "Redis Lua 沙箱逃逸，可 RCE"},
        {"max": (7, 0, 0), "cve": "CVE-2023-31656", "level": "MEDIUM",
         "desc": "Redis 整数溢出"},
    ],
    "mysql": [
        {"max": (5, 7, 31), "cve": "CVE-2020-14854", "level": "MEDIUM",
         "desc": "MySQL Server 权限提升"},
    ],
    "lighttpd": [
        {"max": (1, 4, 54), "cve": "CVE-2022-22707", "level": "HIGH",
         "desc": "lighttpd 越界写入，可导致 RCE"},
    ],
    "apache": [
        {"max": (2, 4, 50), "cve": "CVE-2021-41773", "level": "CRITICAL",
         "desc": "Apache HTTP Server 路径穿越 + RCE"},
        {"max": (2, 4, 49), "cve": "CVE-2021-44790", "level": "HIGH",
         "desc": "Apache mod_lua 缓冲区溢出"},
    ],
    "vsftpd": [
        {"max": (2, 3, 5), "cve": "CVE-2011-2523", "level": "CRITICAL",
         "desc": "vsftpd 2.3.4 后门"},
    ],
}

LEVEL_SCORE = {"INFO": 0, "LOW": 2, "MEDIUM": 5, "HIGH": 8, "CRITICAL": 10}


def match_exposure(port: dict[str, Any]) -> dict[str, Any] | None:
    """按端口 + 服务名匹配暴露面基线规则。"""
    pnum, svc = port.get("port", 0), (port.get("service") or "").lower()
    product = (port.get("product") or "").lower()

    for rule in EXPOSURE_RULES:
        if pnum not in rule["ports"]:
            continue
        # service 字段为 "*" 时只看端口
        if rule["service"] == "*":
            return rule
        if rule["service"] in svc or rule["service"] in product:
            return rule
    return None


def match_cves(port: dict[str, Any]) -> list[dict[str, Any]]:
    """按 product + version 匹配已知 CVE（离线规则库）。"""
    product = (port.get("product") or "").lower().replace(" ", "")
    version = port.get("version") or ""
    if not product or not version:
        return []

    hits = []
    for key, rules in CVE_RULES.items():
        if key not in product:
            continue
        v = _ver(version)
        if v == (0,):
            continue
        for r in rules:
            # 只做"低于等于某版本"的判定，够覆盖绝大多数场景
            if v <= r["max"]:
                hits.append({
                    "cve": r["cve"],
                    "level": r["level"],
                    "desc": r["desc"],
                    "source": "local-rule",
                })
    return hits


def score_port(port: dict[str, Any]) -> dict[str, Any]:
    """对单个端口做风险评分，返回带 findings 的结构。"""
    findings: list[dict[str, Any]] = []

    exp = match_exposure(port)
    if exp:
        findings.append({
            "type": "exposure",
            "level": exp["level"],
            "title": exp["title"],
            "advice": exp["advice"],
        })

    for c in match_cves(port):
        findings.append({
            "type": "cve",
            "level": c["level"],
            "title": c["cve"],
            "advice": c["desc"],
        })

    score = max([LEVEL_SCORE[f["level"]] for f in findings], default=0)
    # 开放端口本身给 1 分基线
    if port.get("state") == "open":
        score = max(score, 1)

    level = "INFO"
    for lv, s in sorted(LEVEL_SCORE.items(), key=lambda x: x[1], reverse=True):
        if score >= s and s > 0:
            level = lv
            break

    return {**port, "risk_score": score, "risk_level": level, "findings": findings}


def score_host(host: dict[str, Any]) -> dict[str, Any]:
    """主机级评分：取端口最高分，并按开放端口数量做累加惩罚。"""
    scored_ports = [score_port(p) for p in host.get("ports", []) if p.get("state") == "open"]
    base = max([p["risk_score"] for p in scored_ports], default=0)
    # 攻击面越大风险越高，但不超过 10
    breadth = min(len(scored_ports) // 3, 2)
    score = min(base + breadth, 10)

    level = "INFO"
    for lv, s in sorted(LEVEL_SCORE.items(), key=lambda x: x[1], reverse=True):
        if score >= s and s > 0:
            level = lv
            break

    return {
        **host,
        "ports": scored_ports,
        "risk_score": score,
        "risk_level": level,
        "findings": [f for p in scored_ports for f in p["findings"]],
    }


def enrich(report: dict[str, Any]) -> dict[str, Any]:
    """对整份扫描报告做富化：每台主机 + 每个端口都带上风险与 CVE。"""
    hosts = [score_host(h) for h in report.get("hosts", []) if h.get("status") == "up"]
    total_findings = sum(len(h["findings"]) for h in hosts)
    critical = sum(1 for h in hosts if h["risk_level"] == "CRITICAL")
    return {
        **report,
        "hosts": hosts,
        "summary": {
            **report.get("stats", {}),
            "findings": total_findings,
            "critical_hosts": critical,
            "max_risk": max([h["risk_score"] for h in hosts], default=0),
        },
    }


# ---------------------------------------------------------------------------
# 三、NVD 在线查询（可选）
# ---------------------------------------------------------------------------
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def query_nvd(cpe: str, api_key: str | None = None, timeout: int = 10) -> list[dict]:
    """
    用 CPE 查 NVD。无 api_key 时限流很严（约 5 次/30 秒），
    建议申请免费 key：https://nvd.nist.gov/developers/request-an-api-key
    生产环境应把结果缓存进本地库，避免重复请求。
    """
    import urllib.parse
    import urllib.request

    if not cpe:
        return []
    params = urllib.parse.urlencode({"cpeName": cpe, "resultsPerPage": 20})
    req = urllib.request.Request(f"{NVD_API}?{params}")
    if api_key:
        req.add_header("apiKey", api_key)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            import json
            data = json.load(r)
    except Exception:
        return []

    out = []
    for item in data.get("vulnerabilities", []):
        c = item.get("cve", {})
        cvss = ""
        for m in c.get("metrics", {}).get("cvssMetricV31", []) or []:
            cvss = m.get("cvssData", {}).get("baseScore", "")
        out.append({
            "cve": c.get("id", ""),
            "level": "HIGH" if isinstance(cvss, (int, float)) and cvss >= 7 else "MEDIUM",
            "desc": (c.get("descriptions", [{}])[0].get("value", "")[:200]),
            "cvss": cvss,
            "source": "nvd",
        })
    return out
