# -*- coding: utf-8 -*-
"""
Nmap 进程封装层 —— Windows 优先适配

设计要点：
1. 不依赖 python-nmap / libnmap，直接用 subprocess 调 nmap.exe，避免第三方库在
   Windows 上的路径与编码问题。
2. 自动探测 nmap.exe 位置（Windows 常见安装路径 + PATH）。
3. 始终用 -oX - 把 XML 输出到 stdout，程序只解析结构化数据，不解析人类可读文本。
4. safe_mode 默认开启：禁止 -oN/-oG/-oA/-iL/--script 等会产生副作用或读取外部
   输入的选项，防止上层传入恶意参数。
5. 全程使用 list 形式传参（不用 shell=True），规避 Windows 路径含空格的问题。
"""
from __future__ import annotations

import os
import platform
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, field
from typing import Callable, Optional


IS_WINDOWS = platform.system() == "Windows"

# Windows 下 Nmap 的常见安装路径（官方 installer 默认带 (x86)）
WINDOWS_CANDIDATES = [
    r"C:\Program Files (x86)\Nmap\nmap.exe",
    r"C:\Program Files\Nmap\nmap.exe",
]

# 禁止出现在这套系统里的选项（会写文件 / 读外部输入 / 交互式）
UNSAFE_OPTIONS = {
    "-oN", "-oG", "-oA", "-oS", "-oX", "-iL", "--iflist",
    "--resume", "--stylesheet", "--datadir", "--script", "-iR",
}


def find_nmap(user_path: Optional[str] = None) -> str:
    """定位 nmap 可执行文件，返回绝对路径；找不到则抛 RuntimeError。"""
    if user_path:
        if os.path.isfile(user_path):
            return user_path
        raise RuntimeError(f"指定的 nmap 路径不存在：{user_path}")

    if IS_WINDOWS:
        for cand in WINDOWS_CANDIDATES:
            if os.path.isfile(cand):
                return cand

    found = shutil.which("nmap")
    if found:
        return found

    raise RuntimeError(
        "未找到 nmap。Windows 请从 https://nmap.org/download.html 安装"
        "（务必勾选 Npcap），或在 .env 中指定 NMAP_PATH。"
    )


def is_admin() -> bool:
    """Windows 下 SYN 扫描 / OS 指纹需要管理员权限，提前判断以免静默失败。"""
    if not IS_WINDOWS:
        return os.geteuid() == 0
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def validate_options(options: str) -> None:
    """拦截危险选项。上层若传入 -oX 等会破坏本系统的输出约定。"""
    tokens = set(options.split())
    hit = tokens & UNSAFE_OPTIONS
    if hit:
        raise ValueError(f"禁止使用的 Nmap 选项：{', '.join(sorted(hit))}")


@dataclass
class ScanResult:
    """一次扫描的完整输出：原始 XML + 元信息。"""
    xml: str = ""
    command: str = ""
    returncode: int = -1
    stderr: str = ""
    duration: float = 0.0
    target: str = ""


class NmapScanner:
    """
    同步扫描器。生产环境若要并发，外面套 asyncio.to_thread 或线程池即可。

    用法：
        sc = NmapScanner()
        r = sc.scan("192.168.1.0/24", "-sV -T4")
    """

    def __init__(self, nmap_path: Optional[str] = None, safe_mode: bool = True):
        self.nmap_path = find_nmap(nmap_path)
        self.safe_mode = safe_mode

    def build_command(self, target: str, options: str) -> list[str]:
        validate_options(options)
        cmd = [self.nmap_path] + options.split() + ["-oX", "-", target]
        return cmd

    def scan(
        self,
        target: str,
        options: str = "-sV -T4",
        timeout: int = 600,
        progress_cb: Optional[Callable[[float, str], None]] = None,
    ) -> ScanResult:
        """
        执行扫描。XML 走 stdout，进度信息走 stderr（Nmap 的 --stats-every）。
        """
        cmd = self.build_command(target, options)
        result = ScanResult(target=target, command=" ".join(cmd))
        start = time.time()

        # Windows 下不设置 shell=True；encoding 显式声明避免 GBK 乱码
        try:
            proc = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=timeout,
                shell=False,
                encoding="utf-8",
                errors="replace",
                creationflags=subprocess.CREATE_NO_WINDOW if IS_WINDOWS else 0,
            )
        except subprocess.TimeoutExpired:
            result.stderr = f"扫描超时（{timeout}s）"
            result.returncode = -1
            result.duration = time.time() - start
            return result

        result.xml = proc.stdout or ""
        result.stderr = proc.stderr or ""
        result.returncode = proc.returncode
        result.duration = round(time.time() - start, 2)

        if progress_cb:
            progress_cb(100.0, "完成")

        return result


# 预置的扫描档位，对应不同场景，前端直接下拉选择
PROFILES = {
    "quick": {"label": "快速发现", "options": "-T4 -F", "desc": "Top 100 端口，适合日常巡检"},
    "service": {"label": "服务识别", "options": "-sV -T4", "desc": "版本探测，用于 CVE 关联"},
    "full": {"label": "全端口", "options": "-p- -sV -T4", "desc": "1-65535，慢但完整"},
    "os": {"label": "系统指纹", "options": "-O -sV -T4", "desc": "需管理员权限"},
    "vuln": {"label": "漏洞脚本", "options": "-sV --script vuln -T4", "desc": "NSE 漏洞类脚本"},
}


def preflight() -> dict:
    """启动自检：把环境信息一次性返回给前端展示。"""
    info = {
        "platform": platform.platform(),
        "is_windows": IS_WINDOWS,
        "admin": is_admin(),
    }
    try:
        sc = NmapScanner()
        info["nmap_path"] = sc.nmap_path
        r = subprocess.run(
            [sc.nmap_path, "--version"],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            encoding="utf-8", errors="replace",
            creationflags=subprocess.CREATE_NO_WINDOW if IS_WINDOWS else 0,
        )
        info["nmap_version"] = (r.stdout or "").splitlines()[0] if r.stdout else "unknown"
        info["nmap_ok"] = True
    except Exception as e:
        info["nmap_path"] = None
        info["nmap_version"] = str(e)
        info["nmap_ok"] = False
    return info


if __name__ == "__main__":
    import json
    print(json.dumps(preflight(), ensure_ascii=False, indent=2))
