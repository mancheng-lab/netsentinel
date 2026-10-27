# -*- coding: utf-8 -*-
"""
NetSentinel 桌面 GUI（tkinter）

为什么用 tkinter：
  - Python 标准库自带，Windows 上不用装 PySide6 / PyQt（那两个包体大、易装失败）
  - 双击 .bat 即可启动，不需要先起 Web 服务再开浏览器

启动：
    python backend/gui.py          有控制台，报错可见（排错用）
    pythonw backend/gui.py         无控制台（日常用，配合 NetSentinel.bat）

与 Web 版的关系：
  两者共用 backend 下同一套 scanner / parser / risk / database，
  数据写进同一个 data/netsentinel.db，界面不同、数据互通。
"""
from __future__ import annotations

import os
import queue
import sys
import threading
import traceback
import ipaddress
from datetime import datetime

try:
    import tkinter as tk
    from tkinter import ttk, messagebox, filedialog
except ImportError:
    sys.exit("未安装 tkinter。Windows 安装 Python 时请勾选 'tcl/tk and IDLE'，"
             "或改用 Microsoft Store 以外的官方安装包。")

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import database as db
from parser import parse_nmap_xml
from risk import enrich
from scanner import PROFILES, NmapScanner, is_admin, preflight

DATA_DIR = os.path.join(BASE_DIR, "data")
try:
    os.makedirs(DATA_DIR, exist_ok=True)
except OSError:
    DATA_DIR = os.path.join(os.path.expanduser("~"), ".netsentinel")
    os.makedirs(DATA_DIR, exist_ok=True)

DB_PATH = os.path.join(DATA_DIR, "netsentinel.db")
db.DB_PATH = DB_PATH

# 首次运行必须建表，否则所有查询都会报 "no such table"
DB_OK = True
try:
    db.init_db(DB_PATH)
except Exception:
    DB_OK = False

FONT = ("Microsoft YaHei", 10)
FONT_B = ("Microsoft YaHei", 10, "bold")
MONO = ("Consolas", 9)

LEVEL_COLOR = {
    "CRITICAL": ("#f85149", "#fff0f0"),
    "HIGH": ("#d73a49", "#fff4f0"),
    "MEDIUM": ("#b08800", "#fffbe6"),
    "LOW": ("#2da44e", "#f0fff4"),
    "INFO": ("#57606a", "#f6f8fa"),
}


def validate_target(target: str) -> tuple[bool, str]:
    """与 Web 版一致的安全边界：默认只放行内网与回环。"""
    allow_public = os.environ.get("ALLOW_PUBLIC_SCAN", "0") == "1"
    target = (target or "").strip()
    if not target:
        return False, "请填写目标"
    try:
        net = ipaddress.ip_network(target, strict=False)
    except ValueError:
        return (True, "") if allow_public else (False, "主机名需设置 ALLOW_PUBLIC_SCAN=1")
    for ip in (net.hosts() if net.prefixlen < 32 else [net.network_address]):
        if ip.is_private or ip.is_loopback:
            continue
        if not allow_public:
            return False, f"{ip} 是公网地址，需设置 ALLOW_PUBLIC_SCAN=1"
    return True, ""


class App:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.scanning = False
        self.q: queue.Queue = queue.Queue()
        self.current_report = None
        self.host_refs: dict[str, dict] = {}   # tree iid -> host dict
        self.port_refs: dict[str, dict] = {}   # tree iid -> port dict

        root.title("NetSentinel · 资产测绘与漏洞关联平台")
        root.geometry("1240x800")
        root.minsize(1000, 640)

        self._build_header()
        self._build_control()
        self._build_body()
        self._build_history()
        self._build_status()

        self._check_env_async()
        self._load_history()

    # ---------------------------------------------------------------- 界面
    def _build_header(self):
        hd = ttk.Frame(self.root, padding=(12, 10))
        hd.pack(fill="x")
        ttk.Label(hd, text="NetSentinel", font=("Microsoft YaHei", 16, "bold")).pack(side="left")
        ttk.Label(hd, text="资产测绘 · 服务指纹 · CVE 关联 · 时序变更",
                  font=("Microsoft YaHei", 9), foreground="#57606a").pack(side="left", padx=(10, 0))
        self.env_label = ttk.Label(hd, text="环境检测中…", foreground="#57606a")
        self.env_label.pack(side="right")

    def _build_control(self):
        f = ttk.LabelFrame(self.root, text=" 扫描控制 ", padding=10)
        f.pack(fill="x", padx=12, pady=(0, 8))

        ttk.Label(f, text="目标：").grid(row=0, column=0, sticky="w")
        self.target_var = tk.StringVar(value="127.0.0.1")
        ttk.Entry(f, textvariable=self.target_var, width=32).grid(row=0, column=1, padx=(2, 14))

        ttk.Label(f, text="档位：").grid(row=0, column=2, sticky="w")
        self.profile_var = tk.StringVar(value="service")
        names = list(PROFILES.keys())
        self.profile_cb = ttk.Combobox(
            f, textvariable=self.profile_var, width=34, state="readonly",
            values=[f"{k} — {PROFILES[k]['label']}" for k in names])
        self.profile_cb.grid(row=0, column=3, padx=(2, 14))
        if "service" in names:
            self.profile_cb.current(names.index("service"))
        self.profile_keys = names

        self.scan_btn = ttk.Button(f, text="开始扫描", command=self.start_scan)
        self.scan_btn.grid(row=0, column=4, padx=(0, 6))
        ttk.Button(f, text="导入 XML", command=self.import_xml).grid(row=0, column=5, padx=(0, 6))
        ttk.Button(f, text="刷新历史", command=self._load_history).grid(row=0, column=6)

        self.pb = ttk.Progressbar(f, mode="indeterminate", length=180)
        self.pb.grid(row=0, column=7, padx=(10, 0))

        db_txt = f"数据库：{DB_PATH}" if DB_OK else f"⚠ 数据库不可用（只读目录？）：{DB_PATH}"
        ttk.Label(f, text=db_txt, font=("Consolas", 8),
                  foreground="#57606a" if DB_OK else "#d73a49"
                  ).grid(row=1, column=0, columnspan=8, sticky="w", pady=(6, 0))

    def _build_body(self):
        paned = ttk.PanedWindow(self.root, orient="horizontal")
        paned.pack(fill="both", expand=True, padx=12, pady=(0, 8))

        left = ttk.Frame(paned)
        paned.add(left, weight=3)
        cols = ("对象", "服务", "产品 / 版本", "状态", "风险")
        self.tree = ttk.Treeview(left, columns=cols, show="tree headings", selectmode="browse")
        for c, w in zip(cols, (260, 110, 210, 80, 90)):
            self.tree.heading(c, text=c)
            self.tree.column(c, width=w, anchor="w")
        self.tree.column("#0", width=60, stretch=False)
        vs = ttk.Scrollbar(left, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscroll=vs.set)
        vs.pack(side="right", fill="y")
        self.tree.pack(fill="both", expand=True)
        self.tree.bind("<<TreeviewSelect>>", self._on_select)

        for lv, (fg, bg) in LEVEL_COLOR.items():
            self.tree.tag_configure(lv, foreground=fg, background=bg)

        right = ttk.Frame(paned)
        paned.add(right, weight=2)
        ttk.Label(right, text="详情", font=FONT_B).pack(anchor="w", pady=(0, 4))
        self.detail = tk.Text(right, wrap="word", font=MONO, relief="solid",
                              borderwidth=1, padx=8, pady=8)
        self.detail.pack(fill="both", expand=True)
        self.detail.insert("1.0", "扫描后点击左侧主机或端口，查看风险详情与修复建议。")
        self.detail.configure(state="disabled")

    def _build_history(self):
        f = ttk.LabelFrame(self.root, text=" 历史扫描 ", padding=10)
        f.pack(fill="x", padx=12, pady=(0, 8))

        cols = ("id", "target", "options", "time", "up", "ports", "find", "risk")
        self.hist = ttk.Treeview(f, columns=cols, show="headings", height=6, selectmode="extended")
        for c, w, t in zip(cols, (50, 200, 160, 150, 50, 60, 60, 60),
                           ("ID", "目标", "参数", "时间", "主机", "端口", "风险项", "最高分")):
            self.hist.heading(c, text=t)
            self.hist.column(c, width=w, anchor="w" if c in ("target", "options", "time") else "center")
        self.hist.pack(fill="x", side="left", expand=True)

        bar = ttk.Frame(f)
        bar.pack(side="left", fill="y", padx=(10, 0))
        ttk.Button(bar, text="对比选中", command=self.diff_selected).pack(fill="x", pady=(0, 6))
        ttk.Button(bar, text="查看结果", command=self.view_selected).pack(fill="x")

    def _build_status(self):
        self.status = ttk.Label(self.root, text="就绪", relief="sunken", anchor="w", padding=(8, 3))
        self.status.pack(fill="x", side="bottom")

    # ---------------------------------------------------------------- 环境
    def _check_env_async(self):
        def work():
            try:
                info = preflight()
            except Exception as e:
                info = {"nmap_ok": False, "nmap_version": str(e), "admin": False}
            self.q.put(("env", info))
        threading.Thread(target=work, daemon=True).start()
        self.root.after(150, self._poll)

    def _apply_env(self, info):
        ok = info.get("nmap_ok")
        admin = info.get("admin")
        if ok:
            v = (info.get("nmap_version") or "").splitlines()[0][:40]
            txt = f"Nmap {v} · {'管理员' if admin else '普通权限'}"
            self.env_label.configure(text=txt, foreground="#2da44e")
            self._status(f"环境就绪：{v}")
        else:
            self.env_label.configure(text="未找到 Nmap", foreground="#d73a49")
            self.scan_btn.configure(state="disabled")
            self._status("未找到 Nmap。请在 .env 设置 NMAP_PATH 或将 Nmap 加入 PATH。")

    # ---------------------------------------------------------------- 扫描
    def start_scan(self):
        if self.scanning:
            return
        target = self.target_var.get().strip()
        idx = self.profile_cb.current()
        profile = self.profile_keys[idx] if 0 <= idx < len(self.profile_keys) else "service"

        ok, msg = validate_target(target)
        if not ok:
            messagebox.showwarning("目标被拒绝", msg)
            return
        opts = PROFILES[profile]["options"]
        if "-O" in opts and not is_admin():
            messagebox.showwarning("权限不足",
                                   "OS 指纹扫描（-O）需要管理员权限。\n"
                                   "请以管理员身份运行，或选择其他档位。")
            return

        self.scanning = True
        self.scan_btn.configure(state="disabled", text="扫描中…")
        self.pb.start(12)
        self._status(f"正在扫描 {target}（{PROFILES[profile]['label']}）…")
        self._clear_tree()
        self.detail.configure(state="normal")
        self.detail.delete("1.0", "end")
        self.detail.insert("1.0", f"扫描中：{target}\n参数：{opts}\n请稍候…")
        self.detail.configure(state="disabled")

        threading.Thread(target=self._scan_worker, args=(target, profile), daemon=True).start()
        self.root.after(200, self._poll)

    def _scan_worker(self, target, profile):
        try:
            opts = PROFILES[profile]["options"]
            sc = NmapScanner(os.environ.get("NMAP_PATH"))
            r = sc.scan(target, opts, timeout=900)
            if r.returncode != 0 and not r.xml:
                self.q.put(("error", f"nmap 执行失败 rc={r.returncode}\n{r.stderr[:800]}"))
                return
            report = enrich(parse_nmap_xml(r.xml))
            sid = db.save_report(report, target, opts, r.duration, r.xml)
            self.q.put(("done", {"scan_id": sid, "report": report, "duration": r.duration}))
        except Exception as e:
            self.q.put(("error", f"{e}\n\n{traceback.format_exc()[-800:]}"))

    def _poll(self):
        try:
            kind, data = self.q.get_nowait()
        except queue.Empty:
            if self.scanning:
                self.root.after(200, self._poll)
            return
        if kind == "env":
            self._apply_env(data)
        elif kind == "done":
            self.scanning = False
            self.pb.stop()
            self.scan_btn.configure(state="normal", text="开始扫描")
            self._render(data["report"])
            self._load_history()
            s = data["report"].get("summary", {})
            self._status(f"完成 · 存活 {s.get('up',0)} · 开放端口 {s.get('open_ports',0)}"
                         f" · 风险项 {s.get('findings',0)} · 耗时 {data['duration']}s")
        elif kind == "error":
            self.scanning = False
            self.pb.stop()
            self.scan_btn.configure(state="normal", text="开始扫描")
            messagebox.showerror("扫描失败", str(data)[:1500])
            self._status("扫描失败")
        if self.scanning:
            self.root.after(200, self._poll)

    # ---------------------------------------------------------------- 渲染
    def _clear_tree(self):
        for i in self.tree.get_children():
            self.tree.delete(i)
        self.host_refs.clear()
        self.port_refs.clear()

    def _render(self, report):
        self.current_report = report
        self._clear_tree()
        hosts = report.get("hosts", [])
        if not hosts:
            self.tree.insert("", "end", text="-", values=("未发现存活主机", "", "", "", ""))
            return
        for h in hosts:
            hid = self.tree.insert(
                "", "end", text="主机",
                values=(f"{h['address']}  {h.get('hostname','')}", h.get("os", ""), "",
                        f"{h.get('open_count', len(h.get('ports',[])))} 端口",
                        f"{h.get('risk_level','')} {h.get('risk_score','')}"),
                tags=(h.get("risk_level", "INFO"),))
            self.host_refs[hid] = h
            for p in h.get("ports", []):
                pv = " ".join(x for x in (p.get("product"), p.get("version")) if x)
                pid = self.tree.insert(
                    hid, "end", text="端口",
                    values=(f"{p['port']}/{p.get('protocol','tcp')}", p.get("service", ""),
                            pv, p.get("state", ""),
                            f"{p.get('risk_level','')} {p.get('risk_score','')}"),
                    tags=(p.get("risk_level", "INFO"),))
                self.port_refs[pid] = {"port": p, "host": h}
        for hid in self.host_refs:
            self.tree.item(hid, open=True)

    def _on_select(self, _e=None):
        sel = self.tree.selection()
        if not sel:
            return
        iid = sel[0]
        self.detail.configure(state="normal")
        self.detail.delete("1.0", "end")
        if iid in self.port_refs:
            ref = self.port_refs[iid]
            self._render_port(ref["host"], ref["port"])
        elif iid in self.host_refs:
            self._render_host(self.host_refs[iid])
        self.detail.configure(state="disabled")

    def _render_host(self, h):
        self.detail.insert("end", f"主机 {h['address']}\n", "h1")
        meta = [f"主机名：{h.get('hostname') or '-'}", f"MAC：{h.get('mac') or '-'}",
                f"系统：{h.get('os') or '-'}", f"状态：{h.get('status')}",
                f"风险：{h.get('risk_level')} ({h.get('risk_score')}/10)",
                f"开放端口：{h.get('open_count', 0)}"]
        self.detail.insert("end", "\n".join(meta) + "\n\n")
        self.detail.insert("end", f"本主机共 {len(h.get('findings', []))} 条风险项：\n\n")
        for p in h.get("ports", []):
            for f in p.get("findings", []):
                self.detail.insert("end", f"[{f['level']}] {p['port']} {f['title']}\n", f["level"])
                self.detail.insert("end", f"    {f['advice']}\n\n")

    def _render_port(self, host, p):
        pv = " ".join(x for x in (p.get("product"), p.get("version")) if x)
        self.detail.insert("end", f"{host['address']}:{p['port']}/{p.get('protocol','tcp')}\n", "h1")
        info = [f"服务：{p.get('service') or '-'}", f"产品：{pv or '-'}",
                f"状态：{p.get('state')}", f"CPE：{p.get('cpe') or '-'}",
                f"风险：{p.get('risk_level')} ({p.get('risk_score')}/10)"]
        self.detail.insert("end", "\n".join(info) + "\n\n")
        if not p.get("findings"):
            self.detail.insert("end", "未匹配到已知风险规则。\n")
            return
        self.detail.insert("end", f"发现 {len(p['findings'])} 条风险：\n\n")
        for f in p["findings"]:
            self.detail.insert("end", f"[{f['level']}] {f['title']}\n", f["level"])
            self.detail.insert("end", f"{f['advice']}\n\n")

    # ---------------------------------------------------------------- 历史
    def _load_history(self):
        for i in self.hist.get_children():
            self.hist.delete(i)
        try:
            rows = db.list_scans(100, DB_PATH)
        except Exception as e:
            self._status(f"读取历史失败：{e}")
            return
        for r in rows:
            self.hist.insert("", "end", values=(
                r["id"], r["target"], r["options"], r["started_at"],
                r.get("hosts_up", 0), r.get("open_ports", 0),
                r.get("findings", 0), r.get("max_risk", 0)))

    def _selected_ids(self):
        return [self.hist.item(i)["values"][0] for i in self.hist.selection()]

    def view_selected(self):
        ids = self._selected_ids()
        if len(ids) != 1:
            messagebox.showinfo("提示", "请选中一条记录")
            return
        data = db.get_scan(ids[0], DB_PATH)
        if not data:
            return
        report = {"hosts": [], "summary": {}}
        hosts_map = {}
        for h in data["hosts"]:
            hosts_map[h["address"]] = {**h, "ports": [], "findings": []}
        for p in data["ports"]:
            if p["address"] in hosts_map:
                hosts_map[p["address"]]["ports"].append({**p, "findings": []})
        for f in data["findings"]:
            if f["address"] in hosts_map:
                for pp in hosts_map[f["address"]]["ports"]:
                    if pp["port"] == f["port"]:
                        pp["findings"].append({"type": f["type"], "level": f["level"],
                                               "title": f["title"], "advice": f["advice"]})
        report["hosts"] = list(hosts_map.values())
        report["summary"] = {"up": len(report["hosts"]),
                             "open_ports": len(data["ports"]),
                             "findings": len(data["findings"])}
        self._render(report)
        self._status(f"已载入 Scan #{ids[0]}")

    def diff_selected(self):
        ids = sorted(self._selected_ids())
        if len(ids) != 2:
            messagebox.showinfo("提示", "请按住 Ctrl 选中两条记录进行对比")
            return
        a, b = ids
        d = db.diff_scans(a, b, DB_PATH)
        win = tk.Toplevel(self.root)
        win.title(f"资产变更 · Scan #{a} → #{b}")
        win.geometry("720x520")
        txt = tk.Text(win, wrap="word", font=MONO, padx=10, pady=10)
        txt.pack(fill="both", expand=True)

        def block(title, items, fmt):
            txt.insert("end", f"{title}（{len(items)}）\n", "h1")
            if not items:
                txt.insert("end", "  无\n\n")
                return
            for x in items:
                txt.insert("end", f"  {fmt(x)}\n")
            txt.insert("end", "\n")

        block("新增端口", d["added"], lambda x: f"{x['address']}:{x['port']} {x['service'] or ''} {x['version'] or ''}")
        block("关闭端口", d["removed"], lambda x: f"{x['address']}:{x['port']} {x['service'] or ''}")
        block("服务变更", d["changed"],
              lambda x: f"{x['new']['address']}:{x['new']['port']} "
                        f"{x['old']['product'] or ''}{x['old']['version'] or ''} → "
                        f"{x['new']['product'] or ''}{x['new']['version'] or ''}")
        txt.configure(state="disabled")

    # ---------------------------------------------------------------- 导入
    def import_xml(self):
        path = filedialog.askopenfilename(
            title="选择 Nmap XML 结果",
            filetypes=[("XML 文件", "*.xml"), ("所有文件", "*.*")])
        if not path:
            return
        try:
            raw = open(path, encoding="utf-8", errors="replace").read()
            report = enrich(parse_nmap_xml(raw))
            sid = db.save_report(report, os.path.basename(path),
                                 report.get("meta", {}).get("args", ""), 0.0, raw)
        except Exception as e:
            messagebox.showerror("导入失败", f"{e}")
            return
        self._render(report)
        self._load_history()
        self._status(f"已导入 {os.path.basename(path)} → Scan #{sid}")

    def _status(self, s):
        self.status.configure(text=f"  {datetime.now().strftime('%H:%M:%S')}  {s}")


def main():
    root = tk.Tk()
    try:
        root.call("tk", "scaling", 1.2)
    except Exception:
        pass
    App(root)
    root.mainloop()


if __name__ == "__main__":
    main()
