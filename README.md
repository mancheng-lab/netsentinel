# NetSentinel

**资产测绘与漏洞关联平台** —— 以 Nmap 为扫描引擎，在其之上自建数据层、风险层与可视化层。

Nmap 只告诉你"跑了 nginx 1.18.0"，NetSentinel 告诉你"这个版本有 CVE-2021-23017，风险 HIGH，建议升级"。

---

## 为什么不是二开 Zenmap

| | Zenmap 二开 | NetSentinel |
|---|---|---|
| 技术栈 | Python + GTK 3（桌面开发，栈小众） | FastAPI + SQLite + 原生 JS（全栈，面试可聊） |
| 成果形态 | 单机桌面程序 | Web 平台，可演示、可部署 |
| 能力展示 | 读他人代码 + 加按钮 | 后端架构 / 数据建模 / 安全领域知识 / 前端可视化 |
| 面试时长 | 3 分钟讲完 | 20 分钟可深挖 |

---

## 架构

```
┌─────────────────────────────────────────────────┐
│  frontend/index.html   单文件 SPA（零构建）      │
└────────────────────┬────────────────────────────┘
                     │ REST
┌────────────────────▼────────────────────────────┐
│  backend/main.py      FastAPI 路由 + 安全校验    │
│    ├─ validate_target   目标白名单（防滥用）     │
│    └─ 档位白名单        禁止任意 nmap 参数       │
├─────────────────────────────────────────────────┤
│  backend/scanner.py   Nmap 进程封装（Win 适配）  │
│  backend/parser.py    XML → 结构化数据（零依赖） │
│  backend/risk.py      风险评分 + CVE 关联        │
│  backend/database.py  SQLite 持久化 + 时序 diff  │
└────────────────────┬────────────────────────────┘
                     │ subprocess -oX -
┌────────────────────▼────────────────────────────┐
│  nmap.exe  （引擎，本平台不含扫描能力）          │
└─────────────────────────────────────────────────┘
```

**数据模型**（`backend/database.py`）

- `scan` — 一次扫描任务
- `host` — 主机，按 address 聚合
- `port` — 端口，每次扫描各留一条 → **这是时序 diff 的基础**
- `finding` — 风险项（暴露面规则 / CVE）

---

## Windows 安装

### 1. 安装 Nmap（必须）

从 https://nmap.org/download.html 下载 Windows 安装包，安装时**务必勾选 Npcap**
（SYN 扫描、OS 指纹依赖它，缺失会静默失败）。

装完验证：

```powershell
nmap --version
where.exe nmap
```

若提示找不到命令，把 `C:\Program Files (x86)\Nmap` 加入 PATH，或在 `.env` 里指定 `NMAP_PATH`。

### 2. 启动项目

```powershell
cd D:\github-work\netsentinel

python -m venv venv
.\venv\Scripts\Activate.ps1

pip install -r requirements.txt
uvicorn backend.main:app --reload --port 8000
```

浏览器打开 **http://127.0.0.1:8000**

> 需要 SYN 扫描（`-sS`）、OS 指纹（`-O`）时，**以管理员身份**启动 PowerShell。
> 非管理员会自动降级为 TCP connect 扫描。

### 3. 第一次扫描

在页面输入 `127.0.0.1`，档位选"服务识别"，点开始扫描。
这是最安全的起步——扫自己的机器。

---

---

## 桌面 GUI（Windows 推荐）

除了 Web 界面，还提供一个 **tkinter 桌面窗口**——双击即开，不用先启服务再开浏览器。

### 启动

```
双击 NetSentinel.bat
```

首次使用需先建虚拟环境：

```powershell
cd D:\github-work\netsentinel
python -m venv venv
.\venv\Scripts\pip install -r requirements.txt
```

| 脚本 | 用途 |
|---|---|
| `NetSentinel.bat` | 日常用，`pythonw.exe` 启动，无控制台黑窗 |
| `NetSentinel-调试.bat` | 排错用，保留控制台，报错可见 |

> 两个版本共用 `backend` 下同一套 scanner / parser / risk / database，
> 数据写进同一个 `data/netsentinel.db`，**Web 版与桌面版数据互通**。

### 界面功能

| 区域 | 说明 |
|---|---|
| 顶部状态 | Nmap 版本、管理员权限、数据库路径 |
| 扫描控制 | 目标输入 + 档位下拉（快速/服务/全端口/系统指纹/漏洞脚本） |
| 左侧结果树 | 主机 → 端口 两级，按风险等级着色 |
| 右侧详情 | 点击端口显示 CVE 编号、危害说明、修复建议 |
| 历史扫描 | 勾选两条 →「对比选中」查看资产变更 |
| 导入 XML | 直接导入 Zenmap 导出的扫描结果 |

扫描在**后台线程**执行，界面不会卡死；进度条走 marquee 动画。

### 为什么用 tkinter 而不是 Qt

- Python 标准库自带，Windows 上**不用装** PySide6/PyQt（包体大、易装失败）
- 界面需求不复杂，tkinter 完全够用
- 若 Python 安装时没勾选 tkinter，会提示；改用官方安装包重装即可

---

## 核心能力

### CVE 关联

`product + version` → 已知 CVE。示例输出：

```
192.168.1.50  risk=10 CRITICAL
  6379/tcp  redis  Redis 5.0.7   → CRITICAL
    [CRITICAL] Redis 暴露 — Redis 默认无认证，暴露即等于服务器沦陷
    [HIGH]     CVE-2022-24736 — Redis Lua 沙箱逃逸，可 RCE
    [MEDIUM]   CVE-2023-31656 — Redis 整数溢出
```

分两级：
1. **本地规则库**（离线、秒级）— 内置 15 条暴露面规则 + 7 类服务 CVE 映射
2. **NVD API**（可选，需联网）— 用 CPE 精确查询，建议申请免费 API Key

### 风险评分

```
端口分 = max(暴露面规则分, CVE 分, 开放基线 1 分)
主机分 = min(最高端口分 + 攻击面广度惩罚, 10)
```

等级：INFO / LOW(2) / MEDIUM(5) / HIGH(8) / CRITICAL(10)

### 时序 diff

对比任意两次历史扫描，输出新增端口、关闭端口、服务版本变更。
这是 Zenmap `DiffCompare` 的自动化版本，且支持跨任意两次记录对比。

---

## 安全边界（写进简历能加分）

Web 化的扫描器最容易变成"别人的扫描代理"，本项目做了三层约束：

1. **目标白名单** — 默认只放行私有网段与回环地址，扫公网需显式设置 `ALLOW_PUBLIC_SCAN=1`
2. **参数白名单** — 只接受 `PROFILES` 预置档位，不接受任意 nmap 选项；`scanner.py` 的 `validate_options()` 额外拦截 `-oN/-oG/-iL/--script` 等危险参数
3. **并发限制** — 单实例同时只允许一个扫描任务

---

## 目录结构

```
netsentinel/
├── backend/
│   ├── main.py       FastAPI 入口、路由、安全校验
│   ├── gui.py        tkinter 桌面 GUI
│   ├── scanner.py    Nmap 封装（Windows 路径探测、管理员检测、危险参数拦截）
│   ├── parser.py     Nmap XML 解析（零第三方依赖）
│   ├── risk.py       暴露面规则 + CVE 关联 + 风险评分
│   └── database.py   SQLite 持久化 + 时序 diff
├── NetSentinel.bat       桌面版启动（无控制台）
├── NetSentinel-调试.bat   桌面版启动（保留控制台，排错用）
├── frontend/
│   └── index.html    单文件 SPA，零构建
├── samples/
│   └── demo.xml      示例扫描结果，用于离线调试
├── requirements.txt
└── README.md
```

---

## 简历上怎么写

❌ 别写：`熟悉 Nmap，用过 Burp Suite、sqlmap`

✅ 这样写：

> **NetSentinel · 资产测绘与漏洞关联平台**（Python / FastAPI / SQLite / 原生 JS）
> - 自建 Nmap 调度与解析层：零依赖手写 XML 解析器，将扫描结果结构化为资产模型
> - 设计服务指纹 → CVE 关联引擎，基于 CPE 与本地规则库实现版本到漏洞的自动映射
> - 实现时序资产 diff，追踪端口与服务版本变更，支持任意两次扫描对比
> - 设计三层安全边界：目标白名单、参数白名单、并发限制，防止平台被用作第三方扫描代理
> - 前端单文件 SPA 实现资产列表、风险分布与漏洞详情可视化

---

## 后续可加（提升含金量）

| 方向 | 说明 |
|---|---|
| AI 研判 | 接 LLM 读扫描结果，生成资产画像与修复优先级（已有 Hermes 生态可复用） |
| 任务调度 | APScheduler 定时巡检 + 变更告警 |
| 报告导出 | ReportLab 生成 PDF 审计报告 |
| Nuclei 集成 | 用 CVE 模板做二次验证，降低误报 |
| 认证鉴权 | 多用户 + RBAC，远程部署前的必备 |

---

## 合规声明

**本工具仅限用于你拥有或已获得明确书面授权的网络环境。**
未经授权扫描他人网络可能违反《网络安全法》《刑法》等相关法律法规。
项目默认禁用公网扫描，请勿随意开启 `ALLOW_PUBLIC_SCAN`。

## 许可

MIT
