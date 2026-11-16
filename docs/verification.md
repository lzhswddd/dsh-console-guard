# dsh-console-guard 加固版 · 独立安全复核报告（task-4）

> 复核人：**security-verifier**（独立于实现者与测试装置作者；只读插件源码，只写 `analysis/guard/**`）
> 复核对象：`dsh-console-guard/`（上游 `dsh-console-plugin@0.5.64` 的本地加固分支，包版本 `0.5.65-guard.1`）
> 复核方式：**自己写探针**（`analysis/guard/verify.mjs`，约 1700 行）+ 自己的 stub 宿主 + 自己的请求/断言，不复用 `test/guard/` 的任何断言；仅参考其「startLanServer → attachMp → lan.setMp → start」接线顺序。
> 结论：**通过（不阻断发布）** —— 160 项断言：**159 PASS / 0 FAIL / 1 UNCOVERED（Windows 文件权限平台限制）**；另附 12 条残留风险与 15 条真机测试清单（真机 App 闭源，未在真机验证）。

---

## 0. 结论摘要（给决策者）

| 问题 | 结论 |
|---|---|
| P0：局域网未鉴权取配对码/票据（SEC-01/SEC-16） | ✅ **已修复**。`GET /newcode`、`GET /qr` 对 **loopback 与局域网来源都 403**；原攻击链 `LAN /newcode → /claim → /sessions` 在当前快照上**整链失败**；上游基线同一探针下仍为 200/200（对照成立）。 |
| P0：来源判定可绕过（SEC-02） | ✅ **已移除能力 + 已修复**。加固版完全没有隧道/反代；任何带 `x-forwarded-for`/`x-real-ip` 的请求（含 WS upgrade）一律 403；`remotePair`/`remotePairCode`/`cloud` 恒空；`customServer*` 写操作被拒绝。 |
| DNS rebinding / Host 伪造（SEC-10 的一部分） | ✅ **配对端点已修复**。`/claim`、`/pair/ticket`、`/mp/pair/accept` 对 `Host: evil.example`、`Host: 0.0.0.0`、`Host: 127.0.0.1.attacker.example`、无 Host 全部 403；合法 Host 仍正常进入配对逻辑（不是无差别全拒）。 |
| 未披露高危能力（SEC-03/04/05/06/07/08/09/13/14/15） | ✅ **已移除/不可达**。16 个危险 `/cmd` op 全部 `guard-disabled`；`/file` 与 `readFile/fsList/fsMkdir` 白名单根 + realpath；`/screen/*`、`/gui`、`/cloud/*`、宿主根路径全部 404；云链路/升级引擎/推送/伴生安装/隧道全部未创建（日志 + 运行期零外联 + 零 spawn 证据）。 |
| SEC-18 吊销硬边界 | ✅ **已修复并实测**：`/claim`、`/pair/ticket` 成功不再解黑；**`/mp/pair/accept` 用 6 位码也不再复活被吊销设备（403）**（复核中曾发现该残留，Lead 修复后本次实测通过）。 |
| 限速 | ✅ `/claim` 第 **21** 次错码 429、`/mp/pair/accept` 第 **31** 次 429；429 带 `reason:too-many` + ≈15 分钟 `retryAfterMs`；正确码从另一来源分桶仍可配对（不锁死全系统）。上游基线无任何限速（对照）。 |
| 路由白名单有效性 | ✅ 交叉验证：上游（带 DSH GUI 认证 cookie、stub 桌面 GUI 就绪）15 条测试路径中 **14 条非 404**；加固版 **15/15 全 404**，证明 404 来自白名单闸门而非路径本就 404。 |
| 兼容性（协议级） | ✅ 协议字段/方法名/返回壳/WS 101 均与原版一致：6 位码 `/claim`、扫码 `/pair/ticket`、`/mp/pair/accept`+Cookie、`/mp/api/*`、WS mux 101、`/info /sessions /cmd /attachment /upload /file`。**⚠ 官方鸿蒙 App 闭源，未真机验证**（见 §7）。 |
| 是否必须阻断发布 | **否**。但发布前必须：① 真机验证扫码/6 位码配对 + 会话主流程（唯一无法自动化的兼容性风险）；② README 补 3 条平台/残留声明（Windows 0600、CORS、`guard.enabled=false` 危险）；③ 建议随包保留本探针做回归。 |

---

## 1. 复核对象与冻结快照

Lead 于复核前确认 `lib/**` 冻结；本报告所有实测均针对下表快照（复核结束前再次校验哈希一致；工作区 git HEAD = `c0145075a8b3dc8b2fe94ae6123a7d14f6eee189`，`git status` 仅剩 `test/guard/*.json` 测试产物差异）。

| 文件 | SHA256 前 16 位 | 说明 |
|---|---|---|
| `lib/lan-server.mjs` | `BF87616AAFCAD3B2` | 路由闸门/Host/XFF/限速/文件根/WS |
| `lib/index.js` | `E3E04DD862AEA4CD` | 宿主侧门控 + `/cmd` 策略 + 面板换码 |
| `lib/guard-policy.mjs` | `E90AFB2CC9202447` | 共享策略（白名单/限速/路径） |
| `lib/mp-support.mjs` | `8C21BE43BCB67816` | 设备库/SEC-18 修复/0600 |
| `lib/mp-dispatch.mjs` | `DFD223E8B3B592BA` | `host.listDirectory` 根校验 |
| `lib/mp-routes.mjs` | `4FB766001C39D46F` | mp 分支（Cookie 鉴权） |
| `lib/mp-ws-live.mjs` | `304665ADAEA2E65D` | 与上游一致 |
| `lib/mp-contract.mjs` | `612480027488369B` | 与上游一致 |
| `lib/websocket.js` | `A6E2460FC6CA206A` | 与上游一致 |
| `lib/client.js` | `AF79C356D48EDC11` | 面板 UI；`id: "dsh-console-plugin"` 未变 |
| `package.json` | `F805FD769A4CB0B3` | `0.5.65-guard.1`、无 postinstall、files 完整 |
| `cordis.patch.yml` | `A1C22BF1A47B62D7` | bundle patch |
| `README.md` | `40312C3722162C06` | 加固说明（§6 兼容性/残留声明已就位） |

运行环境：Windows / Node `v24.21.0`（`C:\Users\lzh\.dsh\dsh-runtimes\dsh-primary-runtime\dependencies\node\bin\node.exe`）；局域网 IP `192.168.2.7`（用于模拟「同网段另一台设备」的真实来源地址，非伪造头）。

---

## 2. 复核方法与独立性声明

- **探针**：`analysis/guard/verify.mjs`（单文件，可重复运行）。主进程做静态核查与交叉比对，再依次拉起 3 个**互相隔离的子进程**（各自独立 `USERPROFILE/HOME`、临时收件箱、临时设备/吊销库、空 `PATH`、19600–19700 端口）：
  - `--mode=guard-lan`：真实 `lan-server.mjs` + `mp-support.mjs` + stub 宿主；所有请求由探针自行构造（`node:http` 直连，`localAddress` 绑定 LAN IP 以产生**真实非 loopback 来源**）。
  - `--mode=baseline-lan`：**上游 `dsh-console-plugin/lib` 0.5.64** 同一装置对照（证明 P0 真实存在、路由确实可达）。
  - `--mode=host`：真实 `lib/index.js` 的 `apply(fakeCtx, {guard:{enabled:true}})`（预占端口 → 不真监听、不启 UDP 发现应答器），直接调用注册的 4 条面板路由，验证 `/cmd` 策略/只读桩/fs 边界/面板 state/零外联。
- **断言独立**：不复用 `test/guard/run.mjs` 的任何断言或结论；所有期望状态（403/401/404/429/200/101、错误码、字段）由本报告作者按威胁模型自行给出。
- **外联控制**：子进程启动即 patch `globalThis.fetch` / `http(s).request/get` / `child_process.*`：**外部目标记录并抛错阻断**，本地目标仅记录。`PATH` 指向空目录，任何误触发的 `frpc/ffmpeg/curl` 都会 ENOENT。
- **约束遵守**：未安装到真实 DSH profile、未启动 8899 上的真实插件服务（仅 UDP 8899 发现应答器在测试期间临时绑定，验证完即关）、未下载 frpc/ffmpeg、未联网（探针会阻断并记录外部请求，实测外部目标 = 0）、未修改 `dsh-console-guard/lib/**`、`test/guard/**` 或上游目录、未 git commit/reset/checkout。
- **产物**：`analysis/guard/verify-result.json`（全量 160 项断言 + 快照/事实/外联记录）、`analysis/guard/logs/{host,guard-lan,baseline-lan}.log`（子进程日志）、`analysis/guard/.verify/*.json`（子进程原始结果）。

---

## 3. 总体结果

| 套件 | PASS | FAIL | UNCOVERED | 说明 |
|---|---|---|---|---|
| static（静态核查） | 18 | 0 | 0 | 包/版本/files/无 postinstall/client id/域名/门控/顶层无 fetch-spawn/0600/SEC-18/换码路径 |
| host（真实 `apply()`） | 24 | 0 | 0 | 4 条路由、面板 state、16 危险 op、6 只读桩、fs 边界（含 junction）、日志证据、零外联/零 spawn |
| guard-lan（加固版局域网） | 101 | 0 | 1 | P0/Host/XFF/限速/白名单/鉴权/文件/WS/兼容/吊销/面板/发现/DoS |
| baseline-lan（上游对照） | 13 | 0 | 0 | 原始 P0 复现、Host 不校验、无限速、路由可达性 |
| cross（交叉比对） | 3 | 0 | 0 | 白名单有效性、P0 对照、面板换码链路 |
| **合计** | **159** | **0** | **1** | 本快照上全量套件多次运行均 **0 FAIL**；最终产物 `verify-result.json`（2026-11-05T12:58:51Z，node v24.21.0）——子套件耗时 host≈0.5s、guard-lan≈1.0s、baseline≈0.5s |

> 唯一 UNCOVERED：`PERM-01`。代码层已按 `{mode:0o600}` + `chmodSync(0o600)` 写设备/吊销文件（静态 `S-10` 通过），但 Windows 上 Node 的 POSIX mode 被模拟为 `0666/0444`，实测两文件均为 `0666`（`devicesMode=438`(0o666)）。**平台限制，非回归**；见残留风险 R5。

---

## 4. 逐项证据（对应任务书 1–12 项）

> 完整断言与响应原文见 `analysis/guard/verify-result.json`（每项含 `detail`）。行文中的「检查 id」可在 JSON 中按 id 检索。

### 4.1 ① P0 攻击链（`P0-01..09`、`RL-03/04`、`CR-02`）

| 步骤 | 探针实测（加固版） | 上游对照（baseline） |
|---|---|---|
| 局域网 `GET /newcode` | **403** `{"error":"guard: 配对码/二维码不再通过局域网 HTTP 暴露，请在电脑端面板查看"}` | 200，返回 6 位码（`BL-02`） |
| 局域网 `GET /qr` | **403**（无 `image/png`） | 200 `image/png`（`BL-06`） |
| loopback `GET /newcode` | **403**（面板改走宿主认证路由，本机恶意页面也读不到） | 200 + 码（`BL-01`） |
| loopback `GET /qr` | **403** | 200 |
| 局域网 `POST /claim`（攻击者能猜的码） | **403** `code-mismatch` | 200 + 64 字符 token（`BL-03/04`） |
| 局域网 `GET /sessions`（无 token） | **401** | 200（用窃得 token，`BL-05`） |
| `POST /pair/ticket` 随机 `pt_…` | loopback 403、局域网 403（`P0-07/08`） | — |
| **整链结论** | `{"newcode":403,"claim":403,"sessions":401}` → **整链失败**（`P0-09`） | `{"newcode":200,"claim":200,"tokenLen":64}` → 整链成功（`CR-02` 对照） |

面板侧正常链路仍在（兼容必需）：`lan.newCode()` 返回 6 位码 + `dsh-console://pair?b=…&k=pt_…&i=dsh-console` payload + `data:image/png` 二维码（`COMPAT-01/02/03`）；宿主认证路由 `POST /api/dsh-console/newcode` 返回同样字段（`HS-04`，一次实测样例：`code=851610`、票据 `pt_ebeaf6…`、`qrDataUrl=data:image/png;base64,…`）。

### 4.2 ② Host / DNS rebinding（`HOST-01..09`）

| 请求（loopback 来源） | 结果 |
|---|---|
| `POST /claim` + `Host: evil.example` | **403** `guard: host not allowed` |
| `POST /pair/ticket` + `Host: evil.example` | **403** |
| `POST /mp/pair/accept` + `Host: evil.example` | **403** |
| `POST /claim` + `Host: 0.0.0.0:19600` | **403**（0.0.0.0 未列入白名单） |
| `POST /claim` + `Host: 127.0.0.1.attacker.example` | **403** |
| `POST /claim` HTTP/1.0 **无 Host 头** | **403** |
| 对照：合法 `Host: 127.0.0.1` / `localhost` / LAN IP + 错码 | 403 `code-mismatch`（说明 Host 校验通过、进入配对逻辑） |
| 上游对照：`POST /claim` + `Host: evil.example` | **200**（`BL-07`）；`Host: 0.0.0.0` 也 **200**（`BL-08`） |

### 4.3 ③ XFF / 反代来源（`XFF-01..08`）

带 `x-forwarded-for: 203.0.113.7` 的 `/info`、`/sessions`、`/claim`、`/mp/pair/accept`、`/cmd`、`/newcode`，以及带 `x-real-ip` 的 `/claim`、带 XFF 的 WS 握手：**全部 403**（`guard: 本加固版不支持公网/反向代理来源（无隧道）`），WebSocket upgrade 亦 403。上游 XFF `/newcode` 为 403 `remote-pair-off`（`BL-12`，来源判定依赖 XFF 的旧模型）。

### 4.4 ④ 限速（`RL-01..08`）

| 项 | 实测 |
|---|---|
| LAN `/claim` 连续错码 | 第 1–20 次 403，**第 21 次 429**（`RL-01`；`claimFailMax=20`） |
| 429 体 | `{"reason":"too-many","retryAfterMs":899850}`（≈15 分钟窗口，`RL-02`） |
| 限速后用**另一来源**（loopback）+ 面板新码配对 | **200 + token**（`RL-03`，证明按来源分桶、不锁死全系统） |
| 被限来源（LAN）继续请求 | 429（`RL-04`） |
| LAN `/mp/pair/accept` 连续错码 | 第 1–30 次 403，**第 31 次 429**（`RL-05`；`pairAcceptMax=30`） |
| 429 体 | `{"reason":"too-many","retryAfterMs":899837}`（`RL-07`） |
| 限速后用 loopback + 新码 accept | **200 + `Set-Cookie: mp_device=…`**（`RL-08`） |
| 上游对照 | LAN 连续错码 `/claim` 6 次、`/mp/pair/accept` 31 次**均无 429**（`BL-09/10`） |

> 分桶说明：`clientKeyOf` = 来源 IP（XFF 分支在加固版不可达，因为带 XFF 的请求在闸门处已被 403）。因此一个攻击者 IP 刷满只锁它自己，不误伤其他局域网设备。窗口固定 15 分钟（内存态，重启清零）。

### 4.5 ⑤ 路由白名单（`WL-01..15`、`BL-11`、`CR-01`）

测试条件：请求带 token + `Cookie: dsh-auth-verify=1`；装置内**已启动 stub「DSH 桌面 Web GUI」**并把 `webGuiPort` 指向它 —— 这样上游的 `/gui` 与宿主根路径代理真的可达，排除「路径本来就 404」的假阳性。

| 路径 | 加固版 | 上游 0.5.64（同条件） |
|---|---|---|
| `/gui`、`/gui/` | **404** | 200（代理到 stub GUI） |
| `/screen/prepare`、`/screen/displays` | **404** | 202 / 200 |
| `/cloud/status`、`/cloud/bind`(POST) | **404** | 503 / 503 |
| `/dsh-market`、`/plugins`、`/uf`、`/dsh-memes-api`、`/api/dsh-skills-manager`、`/mcp-connector` | **404** | 200（宿主根路径代理） |
| `/web`、`/pet` | **404** | 403（上游「Web 控制台已关闭」） |
| `/random-verify-path-xyz` | **404** | 404 |
| **汇总** | **15/15 404**（`WL-AGG`） | **14/15 非 404**（`BL-11`），交叉 `CR-01` PASS |

白名单响应不含访问码 token（`WL-LEAK`）。此外 WebSocket 侧：`/gui` 与 `/dsh-market/ws` 的 upgrade 均 **403**（`AUTH-12/13`）。

### 4.6 ⑥ 鉴权边界（`AUTH-01..13`）

`/info`、`/sessions`、`/cmd`(POST)、`/file`、`/attachment` 无 token → **401**；错 token → **401**（`AUTH-01..07`）。`/mp/api/session.list` 无 Cookie → **401**（`AUTH-08`），伪造 Cookie → **403**（`AUTH-09`）。WS `/mp/api/ws/mux` 无 Cookie → **401**（`AUTH-10`），伪造 Cookie → **401**（上游 `mp-ws-live` 对两种都回 401，均不可升级，`AUTH-11`）。WS `/gui` → **403**（`AUTH-12`）。旧通道 `/cmd` 无 token → 401（`COMPAT-16`）。

### 4.7 ⑦ 文件边界（`FILE-01..07`、`FS-01..11`、`MP-01`）

| 测试 | 结果 |
|---|---|
| `/file` 收件箱内文件 / 子目录文件 | **200**，内容正确 |
| `/file?path=C:\Windows\win.ini` | **403** `guard: path not allowed` |
| `/file` 收件箱外临时文件 | **403** |
| `/file` 路径穿越 `收件箱\..\outside\…` | **403** |
| `/file` `file:///C:/Windows/win.ini` URI 形式 | **403** |
| `/file` 经 **junction**（收件箱内 junction → 外部目录）逃逸 | **403**（realpath 校验生效；junction 创建成功，非未覆盖） |
| `/cmd fsDrives` | 只回 `[收件箱]`（`home=收件箱`），不暴露盘符/homedir（`FS-01`） |
| `/cmd fsList` 收件箱内 / `C:\Windows` / 收件箱外临时目录 | 200 / **403-path-not-allowed** / **403** |
| `/cmd readFile` 收件箱内 / `win.ini` / 收件箱外 | 200+b64 / **403** / **403** |
| `/cmd fsMkdir` 收件箱内 / `C:\Windows\verify-guard-evil-dir` | ok:true 且创建 / **拒绝且未创建** |
| `/cmd readFile/fsList` 经 junction 逃逸 | **拒绝**（`FS-10/11`） |
| `/mp/api/host.listDirectory` 收件箱内 / 白名单外 | `result.ok:true` / `result.ok:false, error:{code:"forbidden", message:"guard: path not allowed"}`（`MP-01`） |

### 4.8 ⑧ `/cmd` 危险 op（`CMD-01/02`、`NET-01..03`，host 套件）

真实 `lib/index.js apply()` 注册的 `/api/dsh-console/cmd` 路由上：

- **16 个危险 op 全部**返回 `{ok:false, error:"guard-disabled: <op>"}`：`pluginBundleInstall`、`pluginBundleToggle`、`updateStart/updateCancel/updateRollback`、`remotePairSet/remotePairCodeRefresh`、`customServerSet/customServerPrompt`、`pushRegister/pushTest`、`desktop/desktopWeb`、`permissionSet/selectPreset`、`pvWeather`。
- **6 个只读 op** 返回不联网桩：`updateCheck {ok:false,disabled:true}`、`updateState {disabled:true,version:"0.5.65-guard.1"}`、`remotePairGet {enabled:false,available:false}`、`customServerGet {enabled:false}`、`pushStatus {ready:false,disabled:true}`、`pushTokenList {items:[],tokens:[]}`；调用期间外部网络目标新增 **0**（`NET-03`）。
- 附：DoS 上限（Lead 新增，`DOS-01/02` + 静态 `S-18`）：LAN `POST /cmd` 发 13MB body → 连接被重置（`ECONNRESET`），随后 `/info` 仍 200（服务存活）；`/upload` 单文件 256MB 上限 + 413 `file-too-large`（静态核查；运行期未构造 256MB，见 §6 U3）。

### 4.9 ⑨ 宿主层接线（host 套件，独立于测试 teammate）

- fake ctx 下 `apply()` 成功（端口预占 → 未真监听、未启 UDP 发现应答器）。
- 注册路由恰为 4 条：`/api/dsh-console/{state,newcode,sessions,cmd}`。
- 面板 `state`：`guard.enabled=true`、`version=1`、`features` 11 项**全 false**；`updateState.disabled=true`、`access={lan:true,remote:false}`、`remotePair=false`（`HS-02/03`）。
- `POST /newcode` 走 `lan.newCode()`（不碰局域网 `/newcode` HTTP）；`S-17` 静态确认死回退分支不可达（`lan.newCode()` 调用在 index.js:5024，守卫注释自 5021；死回退 `fetchLocal('/dsh-console/newcode')` 在 5027）。
- **反向能力证据**：日志仅出现 guard 禁用标记 —— `[cloud] 加固模式：云链路已禁用`、`push: 加固模式：推送已完成播报/轮询/华为推送全部禁用`、`companion: 加固模式：伴生插件静默安装已关闭`；**没有** `云链路已就绪`、`[tunnel] 启动快照`、`push: 完成播报器`、`companion: 自检`（`HS-06`）。
- **运行期零外联**：加载 + 面板 state + newcode + sessions + `/cmd`（含 16 危险 + 6 只读）全流程外部网络目标 = **0**（http/https/fetch 全 0）、spawn = **0**（`NET-01/02`）。

### 4.10 ⑩ 静态核查（`S-01..18`，全部 PASS）

| id | 结论 |
|---|---|
| S-01 | `name=dsh-console-plugin`、`version=0.5.65-guard.1`、描述含加固说明 |
| S-02 | 无 `postinstall/preinstall/install/prepare` 等生命周期脚本（仅 `test`/`test:legacy-upstream`） |
| S-03 | files 清单 = `lib/*.js`、`lib/*.mjs`、`cordis.patch.yml`、`README.md`，`lib` 顶层文件全覆盖 |
| S-04 | `main`/`exports` 指向文件全部存在 |
| S-05 | `client.js` 第 3 行 `id: "dsh-console-plugin"` 未变（与上游一致） |
| S-06 | `gaoshou25.cn` 仅出现在 3 个未启动模块常量：`cloud-link.mjs:7`、`ffmpeg-bootstrap.mjs:7`、`frpc-bootstrap.mjs:8`；`index.js` **0 处** |
| S-07 | `index.js` 的 frpc/ffmpeg 字样仅在 1 条注释（无下载/执行路径） |
| S-08 | 危险能力门控：`createCloudLink/createCloudPlugin/createPushWatcher/createTurnAnnouncer/ensureCompanionPlugin/createMemeGallery` 调用点均在 `guardOn` 上下文；`bootTunnel` 首句 `if (guardOn) return…`；`startTunnel` 两个调用点都在 `bootTunnel` 体内；`ensureTunnel` 只调 `bootTunnel` |
| S-09 | 服务端 `lib/*.mjs` + `index.js` 模块顶层**无** `fetch/spawn/exec` 调用 |
| S-10 | `writeDevices/writeRevoked` 均 `{mode:0o600}` + `chmodSync(0o600)`（各 2 处） |
| S-11 | `lan-server` 的 2 处 `.unrevoke(` 都在 `!guardOn()` 分支（line 1906 / 1944，claim 与 pair/ticket） |
| S-12 | `mp-support` 的 `createDeviceStore.exchange()` 在 guard 模式不 `clearRevoked()`（SEC-18） |
| S-13 | `client.js` 无外部域名 URL（仅 2 个本地 URL） |
| S-14 | `cordis.patch.yml` 引用 `./lib/index.js` |
| S-15 | `README.md` 已更新为加固说明并含真机未验证声明（8.4KB） |
| S-16 | 运行依赖仅 `qrcode@^1.5.4` |
| S-17 | 面板换码直调 `lan.newCode()`；HTTP `/newcode` 仅死回退 |
| S-18 | DoS 上限：`/cmd` LAN 12MB（`guardOn() ? 12e6 : Infinity`）、`/upload` 256MB + 413 `file-too-large` |

### 4.11 ⑪ SEC-01..22 逐条对照

> 状态口径：**已修复** = 本次实测证明原攻击/缺陷不可复现；**已移除能力** = 该能力整体不再存在（比修复更强）；**部分修复** = 主要面已收口但仍有可接受残留；**接受残留** = 属协议兼容/上游设计，不改但已文档化；**未验证** = 需真机/超出沙箱。

| 编号 | 原问题（摘要） | 状态 | 证据（本报告检查 id / 文件） |
|---|---|---|---|
| SEC-01 | P0：LAN 免鉴权 `/newcode`、`/qr` 泄露 6 位码+票据 → `/claim` 换 token | **已修复** | P0-01..09、CR-02；上游 200 vs 加固 403；核对 lan-server.mjs:1594-1603（`isLoopbackOnlyPath` 对任何来源无条件 403） |
| SEC-02 | P0（条件）：来源判定仅看 XFF；TCP 隧道把公网当 loopback | **已移除能力（+来源绕过已修复）** | XFF-01..08、S-08、CMD-01、PANEL-02、WL；无隧道/无 cloudLink |
| SEC-03 | P1：手机 `/cmd pluginBundleInstall` 可装任意插件 = RCE | **已移除能力** | CMD-01（`guard-disabled: pluginBundleInstall`）；index.js:3629 前置策略 |
| SEC-04 | P1：`/file`、`readFile/fsList/fsMkdir` 任意绝对路径读写 | **已修复** | FILE-01..07、FS-01..11、MP-01（realpath + 白名单根） |
| SEC-05 | P1：屏幕串流 + 远程鼠标注入（手机可自行开启、持久化） | **已移除能力** | WL-03/04（/screen/* 404）、AUTH-12（WS /gui 403）、CMD-01（desktop*）、PANEL-01 screen=false；ffmpeg 零下载（NET-01/02） |
| SEC-06 | P2：`/gui/*` 桌面 GUI 反代 + `/cmd desktopWeb` | **已移除能力** | WL-01/02、AUTH-12/13、CMD-01、features.desktopProxy=false |
| SEC-07 | P2：frpc/ffmpeg manifest 与 hash 同源 gaoshou25.cn、无签名 | **已移除能力** | S-06/07/08、HS-06（无隧道启动）、NET-01/02（零下载/零 spawn） |
| SEC-08 | P2：加载即静默安装 `dsh-web-mobile@3.2.1` | **已移除能力** | S-08（ensureCompanionPlugin 门控）、HS-06（日志「伴生插件静默安装已关闭」） |
| SEC-09 | P2：默认云注册/30s 心跳/会话标题云推送 (gaoshou25.cn) | **已移除能力** | S-08、HS-06（云链路未创建）、CMD-01（pushRegister/pushTest）、CMD-02/NET-03（只读桩不联网）、NET-01/02（外部目标 0） |
| SEC-10 | P2：响应 `ACAO:*`、从不校验 Host/Origin（DNS rebinding 取码） | **部分修复** | 配对端点 HOST-01..09 已修；**残留**：`Access-Control-Allow-Origin: *` 仍在、token 保护的 API 不校验 Host/Origin（R6） |
| SEC-11 | P2：`/claim` 只对 XFF 限速；`/mp/pair/accept` 无限速/绕过会员闸门 | **已修复** | RL-01..08；上游 BL-09/10 无 429 对照 |
| SEC-12 | P2：全程 HTTP 明文、token 走 query、`mp_device` Cookie 无 Secure | **接受残留**（协议兼容） | 未改协议；README §6 已披露；加固后无公网面（R2） |
| SEC-13 | P2：frpc 配置由云端下发，localPort 可被指向任意本机端口 | **已移除能力** | 无隧道（S-08/HS-06）；customServer get/set 拒绝/桩（CMD-01/02） |
| SEC-14 | P2：`pluginBundleToggle` 可启停任意插件 | **已移除能力** | CMD-01 |
| SEC-15 | P2：手机可触发升级/回滚；4 registry 取最高版、minimumReleaseAge=0 | **已移除能力** | CMD-01（update* 拒绝）、CMD-02（updateCheck/State 离线桩）、S-08（升级引擎未创建）、HS-02 |
| SEC-16 | P2：`/newcode` 可被反复调用作废旧码（配对 DoS） | **已修复** | P0-01/P0-03（任何来源 403）；仅宿主认证路由可换码（HS-04） |
| SEC-17 | P3：token 持久化 0600/重启不变、非常量时间比较、URL 泄露 | **接受残留**（未改上游） | token 仍持久化 + `!==` 比较（lan-server.mjs:1978 比较语义未变）；README §6 已披露；无公网面使风险下降（R3） |
| SEC-18 | P3：`/claim`、`/pair/ticket` 成功按 uid 自动解黑 | **已修复** | S-11、S-12（mp-support.mjs:469-470 的 `guardMode` 门控）+ 运行期 REVOKE-01..04：claim 200 / ticket 200 后吊销状态仍 true；`/mp/pair/accept` 对被吊销设备 **403** |
| SEC-19 | P3：`/info` 向 token 持有者返回设备指纹；`customServerGet` 回 frps authToken | **部分修复** | 仍需 token（AUTH-01/02）；隧道凭证已不存在（CMD-02 customServerGet 桩 `{enabled:false}`）；设备指纹对已授权 token 仍可见（设计使然） |
| SEC-20 | P3：`isLocalPeer`（loopback 且无 XFF）无条件放行 | **已修复** | P0-03/04（loopback 也 403 取码）；配对仍需正确码/票据（P0-05/07） |
| SEC-21 | P3：UDP 8899 发现应答广播 hostname | **已修复** | DISC-01：实测回包 `{"ok":true,"t":"dsh-console","v":1,"port":…,"name":…,"nodeId":…}`，**无 host 字段** |
| SEC-22 | P3：`/cmd` 对非 XFF 来源 `readBody(..., Infinity)` 无上限 DoS | **已修复** | DOS-01/02（13MB → ECONNRESET，服务存活）+ S-18（12e6 上限） |

### 4.12 ⑫ 兼容性复核（协议级）

**已自动化验证通过**（`COMPAT-01..17`、`HS-04/05`、`WS-01`）：

- 扫码票据流：`lan.newCode()` → payload `dsh-console://pair?b=…&k=pt_…&i=dsh-console&…` + 二维码 dataURL → `POST /pair/ticket` 200+token；票据**一次性**（重放 403）。
- 6 位码流：局域网来源 `POST /claim` 正确码 → **200 + token**（token 为 64 hex，与 stub 真 token 一致）；错码 403；限速 429。
- 新版 6 位码：`POST /mp/pair/accept` → 200 + `Set-Cookie: mp_device=…` + `deviceId`；错码 403。
- `/mp/api/*`：`session.list` → `{type:"server-response",rpcId,result:{ok:true,value:{items:[…]}}}`；`host.listDirectory` 白名单内 ok、白名单外 forbidden。
- WS：`/mp/api/ws/mux` 有效 Cookie → **101 Switching Protocols**（`Sec-WebSocket-Accept` 正常）。
- 旧通道：`/info?token` 200（name/host/version/dshOk 字段在）、`/sessions?token` 200、`/attachment?id&token` 200 image/png、`/upload` 200 且文件落收件箱、`/cmd?token` 200、`/file` 收件箱内 200。
- 面板：`state` 含 `guard{enabled,version,features}`；`newcode` 返回 6 位码/payload/qrDataUrl；面板访问 `access.remote=false`、`remotePair=false`、`cloud=""`。

**协议假设仍在（只能真机确认）**：

1. **6 位码仍以「看得到电脑屏幕」为信任根**：限速降低了远程爆破可行性（单 IP 20/15min），但能看到面板的人 15 分钟内可配对。
2. **`/mp/pair/accept` 不消耗 6 位码**（上游行为，实测保持）：App 若先 accept 再 claim 仍可用；码在 15 分钟 TTL 内可被复用（限速 30/15min）。
3. **局域网 HTTP 明文**：二维码 payload 内的 token 走 HTTP、`mp_device` Cookie 无 Secure —— 同网段嗅探者仍可截获已配对凭据（上游设计）。
4. **App 端被关闭功能的表现未知**：加固版会让 App 的「公网/异地配对/屏幕/插件管理/升级/推送/桌面视图」请求得到 404/403/桩，App 如何展示（灰掉、报错、闪退）**未验证**。
5. **`fsDrives` 条目形态变化**：仅返回白名单根（收件箱绝对路径），官方 App 文件选择器是否接受该形态**未验证**（越权仍会被拒）。
6. **WebSocket 实时流帧**：仅验证握手 101 与未配对拒绝；`session/event`/`pong`/审批帧的端到端行为依赖真实会话（测试装置里的 stub 会话不产生真实事件）。
7. **访问码持久化**：`~/.dsh/dsh-console-token.json` 重启不变（上游行为，README 已披露）。

---

## 5. 残留风险（发布前需知晓/文档化）

| 编号 | 风险 | 影响 | 建议 |
|---|---|---|---|
| R1 | **官方鸿蒙 App 闭源、未真机验证** | 协议级通过 ≠ App UI/流程通过；最坏情况是某入口异常但主流程可用 | 发布前按 §7 真机清单验证；README §6 已声明 |
| R2 | 局域网 HTTP 明文；token 可能出现在 URL/日志；`mp_device` Cookie 无 Secure（SEC-12） | 同网段嗅探可截获已配对凭据 | 协议兼容所限；文档建议共享 WiFi 慎用、优先手机热点（README §4 已写） |
| R3 | token 持久化、非常量时间比较、URL 传 token（SEC-17） | token 泄露即长期有效（直到删文件/改配置） | 文档披露（已写）；后续可加 token 轮换 UI（协议外） |
| R4 | **6 位码是「看屏即配对」的信任根** | 能看到面板/共享屏幕者可配对 | 限速已降低盲猜；README 已提示勿在共享场合开面板 |
| R5 | **Windows 上 0600 不生效**：代码写入 `mode 0o600` 但实测文件为 `0666`（PERM-01） | 同机其他用户可能读到设备密钥/吊销名单/token 文件（取决于磁盘 ACL） | README 应写明「Windows 下 POSIX 权限不生效」；如需要可用 `icacls` 收紧 `~/.dsh`（非插件职责） |
| R6 | **CORS `Access-Control-Allow-Origin: *` 未收**；token 保护的 API（`/sessions`、`/cmd`、`/file`、`/mp/api/*`）不校验 Host/Origin（SEC-10 残留） | 拿到 token 的浏览器上下文/本机页面可读响应；未拿 token 时不可用。原 P0 取码链已断，风险由 P1 降为 P3 | 后续可对敏感响应加 Host 白名单；不影响本次发布 |
| R7 | `guard.enabled=false` 会**恢复全部上游高危能力**（云/隧道/屏幕/安装/升级） | 误配置等于回到上游 0.5.64 | README §5 已警告「禁止日常使用」；建议启动日志醒目告警（现有日志会打印 enabled=false，但无大字告警） |
| R8 | 隧道/屏幕/云/推送模块仍被 `lan-server` import（保持 diff 小） | 静态已确认顶层无副作用、运行期不可达、零外联；但未来若有人改闸门顺序可能回归 | 本探针可作回归（`verify.mjs` 可重复运行）；后续可考虑按需动态 import |
| R9 | 限速为**内存态**：重启清零；单 IP 窗口固定 20/30 次 | 攻击者重启插件无效（需重启 DSH），多 IP 仍可拼概率（局域网规模有限） | 接受；如需更强可加持久化/指数退避（本次不要求） |
| R10 | 面板 `/api/dsh-console/*` 依赖 DSH 宿主 `connection.fetch.register` 的浏览器认证层（未在本项目内审计） | 若宿主认证弱于预期，面板数据（含 6 位码）风险升高 | 上游同样假设；建议 DSH 默认权限预设勿设 `danger-full-access`（README §7 已提示） |
| R11 | 服务仍监听 `0.0.0.0:8899` 且 UDP 8899 应答（含 name/nodeId/port，无 hostname/code） | 局域网可探测本机装了该插件（信息面） | 设计所需（6 位码发现）；已去掉 hostname |
| R12 | DoS 上限已加（`/cmd` 12MB、`/upload` 256MB）但**已配对设备**仍可发 12MB 请求/256MB 文件 | 上限内仍可消耗资源 | 接受；上限远超手机正常使用 |

---

## 6. 未覆盖项（明确的盲区）

| 编号 | 未覆盖内容 | 原因 |
|---|---|---|
| U1 | 官方鸿蒙 App 真机全流程（配对/会话/审批/附件/文件选择器/断线重连） | App 闭源、无真机设备；只能协议级验证 |
| U2 | 真实浏览器 DNS rebinding 实弹 | 只做了服务端 Host 断言；浏览器 PNA/rebinding 需真实环境（服务端校验是最终防线） |
| U3 | `/upload` 256MB 上限的运行期触发（构造 256MB 请求成本高） | 仅静态核查代码路径 + 413 分支存在 |
| U4 | Windows ACL 层面对 `~/.dsh` 文件的隔离（R5） | Node POSIX mode 在 Windows 不生效，需 `icacls` 层面单独验证 |
| U5 | DSH 宿主认证层（`connection.fetch.register`）强度 | 超出插件仓库范围（上游同样假设） |
| U6 | `guard.enabled=false` 回归分支 | 故意不测：会恢复云/隧道/屏幕等高危能力，违反「不联网/不下载」约束 |
| U7 | frpc/ffmpeg 下载器、隧道、屏幕串流、云推送的「功能正确性」 | 能力已移除，只需证明不可达（已证）；无需验证其可用性 |
| U8 | 长时间运行/并发压测（限速窗口边界、内存增长、多设备并发） | 沙箱功能验证范畴；建议真机环境观察 |
| U9 | 真实局域网多设备/AP 隔离/UDP 广播发现 | 沙箱只验证了本机回环 UDP 应答（无 hostname）；真实广播与跨设备发现需真机网络 |
| U10 | tgz 打包/安装/卸载/升级流程（task-5） | 属交付打包任务；本报告只验证源码与包元数据（`S-01..04`） |
| U11 | `session/event`、`pong`、审批/提问帧端到端 | 需要真实 DSH 会话事件；沙箱 stub 会话不产生真实事件 |
| U12 | App 对 404/403/离线桩的 UI 表现 | 真机才能观察 |

---

## 7. 真机测试清单建议（发布前/首次安装后执行）

> 目标：验证「官方 App 不改也能用核心流程」+ 确认关闭的能力不影响主流程。建议按顺序做，每步记录现象与 `~/.dsh/dsh-console.log`。

1. **安装/升级**：先卸载上游 `dsh-console-plugin` → 重启 → 从插件页粘贴本包 tgz 绝对路径安装 → 重启 → 面板出现且显示 6 位码/二维码/本机地址。
2. **无外联**（关键）：安装并静置 10 分钟，用抓包/代理/防火墙日志确认**无** `gaoshou25.cn`、`registry.npmjs.org`、华为推送域名的请求；无 frpc/ffmpeg 子进程。
3. **扫码配对**：手机 App 扫电脑面板二维码 → 成功拿到 token 并进入会话列表。
4. **6 位码配对（旧流程）**：清空设备后输入面板 6 位码 → 成功配对；错码应报错；连续错码（另一台机器/脚本）应在 21 次后 429（可用本探针思路在真机网络复测）。
5. **新版 6 位码流程**：如 App 支持 `/mp/pair/accept`，验证同样可配对并保持登录（Cookie）。
6. **会话主流程**：列会话 → 看历史 → 发送 prompt → 流式输出（WS）→ 取消 → 切模型 → 新建/重命名。
7. **审批/提问**：触发一次审批/提问，手机端接收并答复；确认 WS 帧正常。
8. **附件/图片**：查看会话图片、附件；上传文件（应落收件箱）；从收件箱下载文件（应 200）。
9. **文件选择器**：确认 App 的「文件」入口能显示收件箱（`fsDrives` 只回白名单根）；进入子目录；尝试访问系统目录应被拒绝且不影响 App。
10. **关闭能力表现**：App 设置/功能页中的「公网访问、异地配对、屏幕画面、插件管理、升级、推送、桌面完整视图」应不可用/隐藏；确认点击后**不崩溃**、不阻塞主流程。
11. **断网/局域网隔离**：在无外网（仅局域网）环境重复第 3–8 步，确认核心功能全部可用。
12. **吊销硬边界**：面板吊销某设备 → 该 App 立即失效/重连失败；用新 6 位码重新配对**仍应被拒**（SEC-18）；扫码重配同样被拒。
13. **限速不影响正常用户**：正常配对（正确码）不受限；连续输错几次后仍可换码成功。
14. **同机安全**：用 Windows 另一个用户账号尝试读 `%USERPROFILE%\.dsh\dsh-console-*.json`（验证 R5 是否可接受；如不可接受，用 `icacls` 收紧）。
15. **宿主认证层**：未登录 DSH 的浏览器访问 `http://127.0.0.1:<DSH宿主端口>/api/dsh-console/state` 应被 DSH 拒绝（验证 R10 前提）。
16. **回归**：如后续再改 lib，重跑 `analysis/guard/verify.mjs`，要求 FAIL=0（UNCOVERED 允许）后再真机抽查 3/4/6。

---

## 8. 复现方式（可重复运行）

```powershell
$node = 'C:\Users\lzh\.dsh\dsh-runtimes\dsh-primary-runtime\dependencies\node\bin\node.exe'
cd C:\Users\lzh\Documents\deepseek-harness\default-workspace

# 全量（static + host + guard-lan + baseline-lan + cross）：
& $node analysis\guard\verify.mjs
# 只需加固版（跳过上游对照）：
& $node analysis\guard\verify.mjs --skip-baseline
# 单独调试某个套件：
& $node analysis\guard\verify.mjs --mode=guard-lan
& $node analysis\guard\verify.mjs --mode=baseline-lan
& $node analysis\guard\verify.mjs --mode=host
```

- 退出码：`0` = FAIL=0（UNCOVERED 不计失败）；`1` = 有失败项；`2` = 装置异常。
- 输出：控制台 PASS/FAIL 摘要 + `analysis/guard/verify-result.json`（含快照哈希、160 项断言、事实、外联记录）；子进程日志在 `analysis/guard/logs/`。
- 端口：19600–19700（HTTP）；UDP 8899 发现应答器临时绑定（验证后释放）。**不占用真实 8899 TCP、不装 profile、不联网**。

### 探针自身的边界（避免过度解读）

- LAN 层的 `/cmd` 使用 stub `runCommand`（真实宿主策略在 host 套件用真实 `lib/index.js` 验证），两侧证据互补。
- 会话/附件/上传/WS 使用 stub `sessionController` 与 8 字节 PNG 附件；验证的是**协议壳与安全边界**，不是业务正确性。
- 上游 baseline 用同一装置与 stub GUI，唯一变量是被测 `lib` 目录（guard vs upstream）。

---

## 9. 附加发现（非阻断）

1. **文档小误差**：`docs/host-hardening-notes.md` §5.4 称「`hmWeatherTool` 仍注册给宿主 tools（AI 调用时会访问 api.open-meteo.com）」——实际 `hm_weather_card` 工具返回固定演示数据（`lib/index.js:2194-2238`，`execute` 无网络）；真正会访问 open-meteo 的是 `pvWeather` op（已被 `guard-disabled` 拒绝，CMD-01）。加固版宿主 tools **不产生外部请求**，可把该条从残留风险中移除。
2. **`mp-ws-live` 的 401/403 语义**：无 Cookie 与 Cookie 未登记都回 401（与 `/mp` HTTP 的 401/403 区分不同）。不构成安全缺陷（均拒绝升级），仅文档/测试期望需注意。
3. **`PERM-01` 的平台语义**：代码层 0600 正确，但 Windows 下需要文档说明或 `icacls` 兜底（见 R5）。

---

## 10. 给 Lead 的最终结论

- **可以发布**（源码/协议/安全边界层面）：3 个 P0（SEC-01/02/16）与全部 P1（SEC-03/04/05）均已在当前快照上**实测不可复现或能力已移除**；SEC-18 的 `/mp/pair/accept` 残留已在最后一次修复后实测关闭；无外联、无 spawn、限速与 DoS 上限生效。
- **发布前置条件（建议必须）**：
  1. 真机 App 验证扫码 + 6 位码配对 + 会话收发（§7 第 3/4/6 步）——这是唯一无法自动化的兼容性风险；
  2. README 补 3 条：Windows 下 0600 不生效（R5）、CORS `*` 与 token API 无 Host 校验（R6）、`guard.enabled=false` 的危险性已有声明但建议再醒目化（R7）；
  3. 打包后的 tgz 安装冒烟（task-5）与安装后零外联复测。
- **不阻断项**：SEC-12/SEC-17（协议兼容必须保留，已文档化）、P3 残留（R6/R9/R10/R11）。
- **回归建议**：把 `analysis/guard/verify.mjs` 与本报告作为加固分支的固定回归基线（任何 lib 改动后要求 FAIL=0）。
