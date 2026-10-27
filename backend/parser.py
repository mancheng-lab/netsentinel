# -*- coding: utf-8 -*-
"""
Nmap XML 解析层 —— 零第三方依赖

为什么不直接用 python-nmap / libnmap：
  - 两者在 Windows 上对含空格路径、编码的处理都有历史坑；
  - 自己解析可以让数据模型完全贴合我们自己的表结构；
  - 解析逻辑是本项目真正的技术含量所在，值得自己写。

只用标准库 xml.etree.ElementTree。若解析外部来源（他人提供）的 XML，
建议在 main.py 里改用 defusedxml.ElementTree 以防御 XXE / billion laughs。

Nmap XML 结构（7.9x）：
  <nmaprun>
    <host>
      <status state="up"/>
      <address addr="1.2.3.4" addrtype="ipv4"/>
      <hostnames><hostname name="x" type="PTR"/></hostnames>
      <ports>
        <port protocol="tcp" portid="80">
          <state state="open"/>
          <service name="http" product="nginx" version="1.18.0">
            <cpe>cpe:/a:igor_sysoev:nginx:1.18.0</cpe>
          </service>
        </port>
      </ports>
      <os><osmatch name="Linux 4.x" accuracy="96"/></os>
    </host>
  </nmaprun>
"""
from __future__ import annotations

import xml.etree.ElementTree as ET
from typing import Any


def _text(el: ET.Element | None) -> str:
    return (el.text or "").strip() if el is not None and el.text else ""


def parse_port(pel: ET.Element) -> dict[str, Any]:
    state_el = pel.find("state")
    svc_el = pel.find("service")

    cpe = ""
    if svc_el is not None:
        c = svc_el.find("cpe")
        if c is not None:
            cpe = _text(c)

    return {
        "port": int(pel.get("portid", 0)),
        "protocol": pel.get("protocol", "tcp"),
        "state": state_el.get("state", "unknown") if state_el is not None else "unknown",
        "reason": state_el.get("reason", "") if state_el is not None else "",
        "service": svc_el.get("name", "") if svc_el is not None else "",
        "product": svc_el.get("product", "") if svc_el is not None else "",
        "version": svc_el.get("version", "") if svc_el is not None else "",
        "extrainfo": svc_el.get("extrainfo", "") if svc_el is not None else "",
        "cpe": cpe,
        # 脚本输出（如 --script vuln）会挂在 port/script 下
        "scripts": [
            {"id": s.get("id", ""), "output": _text(s)}
            for s in pel.findall("script")
        ],
    }


def parse_host(hel: ET.Element) -> dict[str, Any]:
    addr = ""
    addrtype = ""
    for a in hel.findall("address"):
        # 优先取 ipv4，其次 ipv6，mac 单独留着
        if a.get("addrtype") == "ipv4":
            addr, addrtype = a.get("addr", ""), "ipv4"
            break
        if a.get("addrtype") == "ipv6" and not addr:
            addr, addrtype = a.get("addr", ""), "ipv6"

    mac = ""
    for a in hel.findall("address"):
        if a.get("addrtype") == "mac":
            mac = a.get("addr", "")

    hostnames = [h.get("name", "") for h in hel.findall("hostnames/hostname")]

    status_el = hel.find("status")
    status = status_el.get("state", "unknown") if status_el is not None else "unknown"

    os_el = hel.find("os/osmatch")
    os_name = os_el.get("name", "") if os_el is not None else ""
    os_accuracy = int(os_el.get("accuracy", 0)) if os_el is not None else 0

    ports = [parse_port(p) for p in hel.findall("ports/port")]

    return {
        "address": addr,
        "addrtype": addrtype,
        "mac": mac,
        "hostname": hostnames[0] if hostnames else "",
        "hostnames": hostnames,
        "status": status,
        "os": os_name,
        "os_accuracy": os_accuracy,
        "ports": ports,
        "open_count": sum(1 for p in ports if p["state"] == "open"),
    }


def parse_nmap_xml(xml: str) -> dict[str, Any]:
    """
    解析完整 XML，返回可 JSON 序列化、可直接入库的 dict。

    返回结构：
    {
      "meta": {"scanner","args","start","version"},
      "hosts": [ {address, hostname, os, ports:[...], ...}, ... ],
      "stats": {"up": n, "down": n, "total": n, "open_ports": n}
    }
    """
    root = ET.fromstring(xml)

    hosts = [parse_host(h) for h in root.findall("host")]

    # runstats 里能拿到 up/down 主机数
    up = down = 0
    hosts_el = root.find("runstats/hosts")
    if hosts_el is not None:
        up = int(hosts_el.get("up", 0))
        down = int(hosts_el.get("down", 0))

    return {
        "meta": {
            "scanner": root.get("scanner", ""),
            "args": root.get("args", ""),
            "version": root.get("version", ""),
            "start": root.get("start", ""),
        },
        "hosts": hosts,
        "stats": {
            "up": up or sum(1 for h in hosts if h["status"] == "up"),
            "down": down,
            "total": len(hosts),
            "open_ports": sum(h["open_count"] for h in hosts),
        },
    }
