# DSH控制台面板 · 加固分支（dsh-console-guard）

> **这是第三方插件 [ChenJun25/dsh-console-plugin](https://github.com/ChenJun25/dsh-console-plugin) 的本地加固派生版（上游 0.5.64，MIT 声明）。**
> 目标只有一个：**官方鸿蒙 App「DSH控制台」继续能连、能收发会话**，但把上游已复现的 P0 漏洞与未披露的高危能力关掉。
> 手机 App 完全不用改；电脑端换成这个包即可。

- 版本：`0.5.65-guard.1`（包名沿用 `dsh-console-plugin`，安装前必须先卸载上游版本，见 §3）
- 基线：上游 `0.5.64`（GitHub HEAD `58bffb2`，2026-11-04）
- 仓库：<https://github.com/lzhswddd/dsh-console-guard>
- 许可：上游 package.json 声明 MIT；本分支保留原署名（详见 §10）

---

## 快速部署与使用（TL;DR）

> 最短路径；完整说明见 §3「部署」和 §4「使用」。

### 部署（约 3 分钟）

1. 电脑已安装 **DeepSeek Harness 桌面版**（0.2.x，Windows 10/11）。
2. 从本仓库下载安装包 **[`dist/dsh-console-plugin-0.5.65-guard.1.tgz`](dist/dsh-console-plugin-0.5.65-guard.1.tgz)**（或按 §9 自行构建）。
3. DSH 桌面应用 → **插件** 页 → **卸载/停用上游 `dsh-console-plugin`** → 重启应用（本包沿用上游包名，不能共存）。
4. 插件页 → **添加插件** → 粘贴本机 tgz 的**绝对路径** → 安装并重载。
5. 打开发 **设置 → 导航列表 → DSH控制台**（或侧栏底部入口），面板出现 6 位码与二维码即部署成功。
6. 排障看日志：`~/.dsh/dsh-console.log`；局域网服务端口默认 `8899`。

### 使用（手机 App）

1. 手机安装官方**鸿蒙 App「DSH控制台」**（应用商店，闭源，本仓库不包含安装包）。
2. 手机与电脑连**同一局域网**，在 App 里「扫一扫」扫描电脑面板二维码，或输入面板上的 **6 位配对码**。
3. 配对成功后即可在手机上看会话、发消息、答审批、传附件（详见 §4）。
4. 手机不在同一网络时：本加固版**不提供公网隧道**；请使用 Tailscale/WireGuard 等自有 VPN（见 §4 末），或改用其它手机网页方案。

---

## 1. 与上游的差异总览

| 维度 | 上游 0.5.64 | 本加固版 |
|---|---|---|
| 局域网未授权取配对码/票据（**P0**） | `GET /newcode`、`GET /qr` 免鉴权返回当前 6 位码 + 含票据二维码；同网段任意设备可取码换长期 token | **HTTP 端点彻底关闭**：`/newcode`、`/qr` 对任何来源（含 loopback）403；面板换码改走 DSH 宿主认证路由 → 内部 `lan.newCode()` |
| 来源判定可绕过（**P0**，条件） | 只看 `X-Forwarded-For`；TCP frp 隧道下公网被当成本机 | 加固版**没有任何隧道/反代**；带任何转发头的请求一律 403 |
| DNS rebinding / 跨站取码 | 响应 `ACAO:*`、不校验 Host | 未鉴权配对端点（`/claim`、`/pair/ticket`、`/mp/pair/accept`）校验 Host 白名单；`0.0.0.0`/任意域名拒绝 |
| 6 位码爆破 | 仅对 XFF 来源限速，局域网无限尝试 | `/claim` 错码按来源限速（默认 20 次/15 分钟窗口，超限 429）；`/mp/pair/accept` 默认 30 次/15 分钟 |
| 手机端插件安装/启停（P1） | `/cmd pluginBundleInstall` 可装任意 npm/git/本地路径插件 = RCE | 拒绝（`guard-disabled`），只读插件清单仍保留 |
| 任意路径读文件（P1） | `/cmd readFile/fsList/fsMkdir`、`GET /file` 接受任意绝对路径 | 限制在「收件箱 + 配置白名单目录」内（realpath 校验）；越界 403 |
| 屏幕串流 + 远程鼠标注入（P1，README 未披露） | HLS/FLV + `/screen/input`，手机可自行允许、持久化 | 路由白名单直接 404；ffmpeg 永不下载/启动 |
| 默认云外联（P2） | 加载即向 `gaoshou25.cn` 注册 nodeId、30s 心跳、会话标题外发 | 不创建云链路：零注册、零心跳、零云推送 |
| 公网隧道 / frpc / 自定义服务器（P2） | 自动下载 frpc、公网配对、流量配额 | 全部关闭：不下载、不启动、无异地配对 |
| 华为推送（P2） | 可选推送 | 关闭（手机在后台时不会有推送通知） |
| 静默安装 `dsh-web-mobile@3.2.1`（P2） | 加载后自动装并启用另一个插件 | 关闭 |
| 手机端升级/回滚（P2） | 从 4 个公共 registry 取最高版本、关 minimumReleaseAge | 关闭；只读查询返回“未启用”桩，不联网 |
| 桌面 Web GUI 反代（P2） | `/gui/*` 把完整桌面 GUI 代理给手机 | 关闭（404），手机 App 里“桌面完整视图”类入口不可用 |
| 文件/设备状态落盘权限 | 设备密钥/吊销名单默认 0644 | 0600；吊销是硬边界（重新配对不自动解黑） |
| 核心手机协议 | 扫码票据配对、6 位码、`/mp` RPC、WS 实时流、会话/审批/附件 | **原样保留**（见 §6 兼容性） |

> 一句话：**保留“手机连电脑看会话/发消息/答审批/传附件”这条主线，砍掉“公网、屏幕、装插件、升级、云端、推送”这些 README 没写全的能力。**

---

## 2. 保留 / 关闭的能力清单

### 保留（手机 App 可用）
- 扫码配对：电脑面板显示二维码（一次性票据，5 分钟、用一次即焚），手机 App 扫码直连。
- 6 位码配对：面板显示 6 位码（15 分钟、一次性），手机输入后自动发现同一局域网内的电脑。
- 会话：会话列表、历史、新建/重命名/归档、发送 prompt、取消、切换模型、队列、置顶。
- 审批与提问：手机端接收审批/提问并在手机上答复（`mobile.pending` / `mobile.respond` + WS 下行）。
- 实时流：WS `/mp/api/ws/mux`、`/mp/api/ws/host`（配对 Cookie 鉴权）。
- 附件与文件：会话附件；上传落到收件箱；下载仅限白名单目录。
- 旧版通道：`/info`、`/sessions`、`/cmd`、`/attachment`、`/file`、`/upload`（token/Cookie 鉴权不变）。
- 面板本身：扫码卡、6 位码卡、连接状态、设备列表、局域网地址；升级/公网/异地配对/自定义服务器卡片已隐藏。

### 关闭（手机 App 上对应入口会不可用/报不可用，属预期）
- 公网访问、异地配对、frpc 隧道、自定义服务器。
- 屏幕实时画面、远程鼠标/键盘控制。
- 手机端安装/启停/卸载插件、升级/回滚插件、重启宿主。
- 华为推送通知（后台通知）。
- 桌面完整视图（`/gui` 反代）。
- 表情包图库（`meme-gallery`）、演示天气卡片 op。
- 云端账号、会员/兑换码、云短号、云心跳、会话标题外发。

---

## 3. 部署（详细步骤）

### 3.1 前置条件

| 项 | 要求 |
|---|---|
| 操作系统 | Windows 10/11（本分支在 Windows 上开发与验证；其它平台未测试） |
| DSH | **桌面版 0.2.x**（本分支基于 0.2.2-rc.1 验证）；需要能打开「插件」页 |
| 网络 | 电脑与手机在同一局域网（同一 WiFi/热点） |
| 手机 | 鸿蒙手机 + 官方 App「DSH控制台」（应用商店下载） |
| 依赖 | 插件依赖 `qrcode@^1.5.4`，安装时需要 profile 能访问 npm registry（或用下述离线办法） |

### 3.2 安装步骤

本包**沿用上游包名 `dsh-console-plugin`**（这样上游 `client.js` 的模块 id、cordis 配置 id 都能继续用，减少兼容风险），因此不能与上游共存：

1. DSH 桌面应用 → **插件** 页 → 找到上游 `dsh-console-plugin` → **卸载/停用**，重启应用。
2. 确认 `~/.dsh/profiles/desktop`（或你当前 profile）的 `package.json` 里已没有 `dsh-console-plugin` 依赖；如果旧版本仍加载，8899 端口会被占用，本包起不来。
3. 桌面应用 → **插件 → 添加插件** → 粘贴本包 tgz 的**绝对路径**（DSH 0.2.x 的插件页输入框只认包名或本地绝对路径；粘贴形如
   `C:\Users\<你>\...\dist\dsh-console-plugin-0.5.65-guard.1.tgz`）。
4. 安装完成按提示重启/重载，打开 **设置 → 导航列表 → DSH控制台**（或侧栏底部入口）应能看到面板与 6 位码。

### 3.3 验证部署是否成功

1. 面板能显示 **6 位配对码**、**局域网地址**和**二维码**（二维码默认折叠，点「展开」）；
2. `~/.dsh/dsh-console.log` 里能看到 `[guard] 宿主侧加固 enabled=true`、`扫码连接已就绪`、`配对码：xxxxxx`；
3. 本机可访问 `http://127.0.0.1:8899/`（无 token 时返回 401/403 属正常）；
4. 「设备」列表为空属正常，手机配对后出现一条。

### 3.4 卸载 / 回滚

1. 插件页移除 `dsh-console-plugin` → 重启 DSH；
2. 可选：删除 `~/.dsh/dsh-console-*.json`、`~/.dsh/dsh-console-inbox`、`~/.dsh/dsh-console.log`；
3. 回滚到上游：按上游 README 重新安装 `dsh-console-plugin`（**注意上游存在已复现的 P0 漏洞**，见 §1）。

> - 本地 tgz 安装不经过 registry，不受 pnpm「最小发布龄（minimumReleaseAge）」影响。
> - 已构建好的包：[`dist/dsh-console-plugin-0.5.65-guard.1.tgz`](dist/dsh-console-plugin-0.5.65-guard.1.tgz)（包内 `files` 与上游一致）。
> - 如果插件页报 `qrcode` 依赖装不上：本包依赖 `qrcode@^1.5.4`，需要 profile 能访问 npm registry；离线环境可先手工在该 profile 里 `pnpm add qrcode`（上游同样有此依赖）。

---

## 4. 使用（配对与功能）

### 4.1 手机 App 要求

- 手机端是作者闭源的鸿蒙 App「**DSH控制台**」（应用商店下载；本仓库不提供安装包、不修改它）；
- 手机与电脑需在**同一局域网**（同一 WiFi 或手机热点）；校园网/AP 隔离网络会导致 6 位码发现失败。

### 4.2 同一局域网配对（推荐）
1. 电脑连 WiFi/网线，打开面板，确认“局域网服务正常”且有 IP。
2. 手机 App → 添加电脑，二选一：
   - **扫一扫**：扫面板二维码（内含一次性票据）；
   - **6 位码**：输入面板上的 6 位数字（App 会自己在同一网段找电脑；校园网/AP 隔离网络可能扫不到，见 §9）。
3. 配对成功后手机即可收发会话、看历史、答审批、传附件。

> 安全提示：6 位码与二维码只显示在**这台电脑的屏幕上**（加固版不会通过局域网 HTTP 暴露）。别在共享场合开面板；配对完成后 App 的访问凭据保存在本机，**不要截图/外传**。
> 局域网与电脑之间是 **HTTP 明文**（上游设计如此，本分支未改协议）。在咖啡厅/宿舍等共享 WiFi 使用请自行评估嗅探风险；需要更强隔离时优先用手机热点直连。

### 4.3 手机端常用功能

配对成功后，手机 App 里可以进行：

| 功能 | 说明 |
|---|---|
| 会话列表 / 历史 | 查看这台电脑上的会话；支持「最近访问 / 固定 / 运行中」等入口 |
| 对话 | 发消息、看流式回复与工具执行过程、取消运行、切换模型 |
| 审批 / 提问 | 电脑端弹出的审批和提问会推到手机，手机答复即可（也支持补发遗漏卡片） |
| 附件 / 文件 | 上传图片、文件到会话；下载受限于「收件箱 + `guard.fileRoots`」白名单 |
| 设备管理 | 面板「设备」列表可查看已配对手机；不需要时在面板里撤销 |

> 手机端看不到「公网访问 / 屏幕控制 / 插件安装 / 升级」等入口，这是加固版刻意关闭的（见 §2），属预期行为。

### 4.4 不在同一局域网（Tailscale 等自有 VPN，可选）
加固版不提供任何公网隧道，但可以复用你已有的点对点 VPN：
1. 电脑与手机都加入同一个 Tailscale（或 WireGuard 等）网络，电脑的 VPN IP 形如 `100.x.y.z`。
2. 在 profile 的 `cordis.patch.yml` 里给插件加配置（见 §5）：
   ```yaml
   - id: dsh-console
     config:
       guard:
         extraBaseUrls: ["http://100.x.y.z:8899"]
   ```
3. 重启 DSH 后，面板二维码的 `c=` 候选地址会带上它；手机在 VPN 内扫码/输码即可连接（Host 白名单会自动包含该地址）。**流量只经过你自己的 VPN，不经过任何第三方服务器。**

---

## 5. 配置（`cordis.patch.yml` 的 `- id: dsh-console` 下）

```yaml
- id: dsh-console
  config:
    port: 8899                # 局域网服务端口（6 位码流程手机只探 8899，非必要别改）
    name: "我的电脑"           # 面板显示名
    guard:
      enabled: true           # 默认 true。false 会恢复上游全部高危能力，仅用于回归对照，禁止日常使用
      fileRoots: []           # 允许手机浏览/下载的目录（绝对路径数组）；收件箱始终允许
      extraBaseUrls: []       # 额外基地址（如 Tailscale http://100.x.y.z:8899），进二维码 c= 与 Host 白名单
      claimFailMax: 20        # /claim 错码限速（次/窗口）
      claimFailWindowMs: 900000
      pairAcceptMax: 30       # /mp/pair/accept 限速（次/窗口）
      pairAcceptWindowMs: 900000
```

- 手机“文件”只能看到 **收件箱 + `fileRoots`**；想传某个项目目录，把它加进 `fileRoots`。
- 收件箱位置：`~/.dsh/dsh-console-inbox`（Windows：`C:\Users\<你>\.dsh\dsh-console-inbox`）。
- 端口被占用时本插件默认**报错退出**（上游行为，手机只认 8899）；先关掉占用 8899 的程序。

> ⚠️ **`guard.enabled: false` 会恢复上游 0.5.64 的全部高危能力**（云端注册/心跳、公网隧道、屏幕串流与远程输入、手机端插件安装、手机端升级、推送、伴生插件安装），等于退回有 P0 的版本。
> 该开关**只用于回归对照**，日常使用必须保持 `true`；启动日志会打印 `[guard] 宿主侧加固 enabled=…`，请确认是 `true`。

---

## 6. 与官方 App 的兼容性

加固版**没有改动任何手机端协议字段**：二维码 payload 格式、`/pair/ticket`、`/claim`、`/mp/pair/accept`、`/mp/api/*` RPC 方法名与返回壳、WebSocket 帧类型（`session/event`、`pong`、审批/提问帧）均与上游 0.5.64 一致。仓库内 `test/guard/` 有自动化的“App 行为模拟”测试（对上游基线做 parity 对照 + 对加固版做安全回归）。

**已在沙箱验证（协议级）**：
- 扫码票据流：`lan.newCode()` → `POST /pair/ticket` → token → `/mp-cookie` → Cookie；
- 6 位码流：`POST /claim`（局域网来源，正确码 200；错码限速）；
- `/mp RPC`：`session.list` / `session.history` / `session.prompt` / `host.listDirectory`（白名单）等；
- WebSocket：101 握手、`session/event` 下行、`ping→pong`、未配对拒绝；
- 旧版通道：`/sessions`、`/cmd`、`/attachment`、`/upload`、`/file`（白名单）；
- 面板：`/api/dsh-console/state` 含二维码/6 位码/设备列表/`guard` 降级字段；换码走后端认证路由。

**只能真机确认（App 闭源，本仓库无法自动化）**：
1. 手机 App 扫码/6 位码能否正常配对（最关键的兼容性验证）；
2. 会话列表/历史/发送/取消/模型切换/审批问答/图片与附件；
3. 手机端文件选择器（`fsDrives` 现在只返回白名单根，条目形态可能与 App 预期不同；越权仍被拒绝）；
4. 后台实时流/断线重连；
5. App 里被关闭的功能（公网、屏幕、插件管理、升级、推送、桌面视图）是否只是灰掉/报错、不影响主流程。

> 建议验证顺序：先只测“扫码 + 会话收发 + 审批”，通过即可日常使用；文件选择器、推送等属增强功能。
> 若 App 在配对/收消息处出现异常：把 `~/.dsh/dsh-console.log`（本插件日志）与现象记下来，回退到上游或反馈给加固维护者。

**已知协议残留（未改，属预期）**：
- 6 位码是“看屏即可配对”的信任模型：面板可见者可在 15 分钟内配对；加固版已限制 HTTP 取码与爆破，但无法防“有人看你屏幕”。
- `/mp/pair/accept` 用正确 6 位码换取设备 Cookie 时**不消耗**该码（上游行为）；码本身 15 分钟有效，之后失效。
- 局域网 HTTP 明文；`token` 可能出现在 URL/日志中（上游设计）。
- 访问码持久化在 `~/.dsh/dsh-console-token.json`（0600），重启不变；如需轮换可删除该文件后重启 DSH（会重新生成并让旧 token 失效）。
- **CORS 残留（P3）**：局域网服务仍返回 `Access-Control-Allow-Origin: *`，且 token 保护的 API 不校验 Host/Origin。原 P0 取码链已断（未鉴权配对端点已 Host 白名单 + 关闭取码），该残留降为 P3；**不要把 8899 暴露到公网或反向代理**（本加固版也不支持隧道）。
- **Windows 文件权限**：设备密钥/吊销名单/token 文件代码里按 `0600` 写入，但 Windows 上 Node 的 POSIX mode 不生效（实测为 `0666`，实际隔离取决于 NTFS ACL）。多用户共用电脑时可自行收紧：

  ```powershell
  icacls "$env:USERPROFILE\.dsh" /inheritance:r /grant:r "$env:USERNAME:(OI)(CI)F"
  ```

完整独立复核（159 PASS / 0 FAIL / 1 平台未覆盖，含 SEC-01..22 对照表、12 条残留风险、16 条真机清单）见 [docs/verification.md](docs/verification.md)。

---

## 7. 安全边界（加固版承诺）

- **无 P0 配对取码链**：局域网内任意设备无法通过 HTTP 拿到 6 位码/二维码/票据；`/newcode`、`/qr` 任何来源 403。
- **无公网面**：不下载/不启动 frpc、ffmpeg；无隧道、无异地配对、无云注册/心跳/推送。
- **手机端权限收窄**：无插件安装/启停、无升级/回滚、无重启、无桌面 GUI 代理、无屏幕/输入、文件仅白名单目录、权限/预设不可改。
- **本地文件**：设备密钥与吊销名单 0600；吊销后重新配对不自动解黑。
- **零新增外联**：除你配置的 `extraBaseUrls` 与 DSH 自身流量外，加固版加载/运行不访问作者域名、npm registry、华为推送等外部服务（沙箱测试实测外部目标=0）。

> **独立复核结论**：[`docs/verification.md`](docs/verification.md) —— 160 项断言 **159 PASS / 0 FAIL / 1 UNCOVERED（仅 Windows 文件权限平台限制）**；P0 攻击链在加固版整链失败、上游基线同一探针 200/200（对照成立）；路由白名单、限速、Host 校验、/cmd 危险 op、文件白名单、零外联均有独立证据。

> **它不是“绝对安全”的**：攻击面仍包括「能看到电脑屏幕的人」、局域网明文嗅探、手机 App 自身（闭源，未审计）、DSH 宿主本身的权限模型。强烈建议 DSH 的默认权限预设不要设为 `danger-full-access`（否则拿到 token 的人可让 agent 直接执行命令）。

---

## 8. 故障排查

| 现象 | 排查 |
|---|---|
| 面板打不开/没有 6 位码 | 插件是否已启用；`~/.dsh/dsh-console.log`；8899 是否被旧实例占用；端口配置 |
| 手机扫码连不上 | 手机与电脑是否同一网段；Windows 防火墙是否放行 8899/TCP（以及 UDP 8899 发现）；AP 隔离/校园网会扫不到 → 用手机热点 |
| 手机 6 位码扫不到电脑 | 同上；6 位码流程依赖局域网发现，热点直连最稳 |
| 面板显示“连不上 DSH” | 这台电脑的 DSH 会话服务问题，与手机无关 |
| 二维码不显示 | `qrcode` 依赖是否装进 profile（`pnpm add qrcode`） |
| 提示 Host 不允许 | 你用了非白名单地址访问；把该地址加进 `guard.extraBaseUrls` 并重启 |
| 手机传文件看不到目录 | 只暴露收件箱；把目标目录加入 `guard.fileRoots` |
| 手机端某功能报“不可用” | 该能力在加固版已关闭（见 §2），属预期 |

日志：`~/.dsh/dsh-console.log`（插件自身）；DSH 应用日志见应用内。

---

## 9. 从源码构建与测试

```bash
git clone https://github.com/lzhswddd/dsh-console-guard.git
cd dsh-console-guard

# 加固版验收（App 行为模拟 + 安全回归 + 无外联），fail=0 退出 0
node test/guard/run.mjs
# 上游基线对照（复现漏洞、验证测试装置有效）
GUARD_LIB=<workspace>/dsh-console-plugin/lib node test/guard/run.mjs
```

打包（生成可安装 tgz）：
```bash
mkdir -p dist/package/lib
cp package.json cordis.patch.yml README.md dist/package/
cp lib/*.js lib/*.mjs dist/package/lib/
tar -czf dist/dsh-console-plugin-0.5.65-guard.1.tgz -C dist package
```
包内容：`package.json`、`lib/*.js`、`lib/*.mjs`、`cordis.patch.yml`、`README.md`（`files` 清单与上游一致）。源码构建需要 Node ≥ 20（Windows 可用 `C:\Users\<你>\.dsh\dsh-runtimes\...\node\bin\node.exe`）。

---

## 10. 许可、归属与免责

- 上游项目：[ChenJun25/dsh-console-plugin](https://github.com/ChenJun25/dsh-console-plugin)（package.json 声明 MIT；上游仓库**没有 LICENSE 文件**，本分支按 package.json 的 MIT 声明保留原作者署名与仓库地址信息）。
- 本加固分支：仅对上游源码做条件门控、路由白名单与安全策略增补（见 [`docs/PATCH-PLAN.md`](docs/PATCH-PLAN.md)、[`docs/host-hardening-notes.md`](docs/host-hardening-notes.md)、[`docs/verification.md`](docs/verification.md)），未重新发行到 npm。
- 本仓库是**源 fork + 加固补丁**，不是上游官方版本；上游更新不会自动跟进。
- 手机 App「DSH控制台」为作者闭源应用，本仓库不包含、不修改、不逆向它；兼容性来自对电脑端协议源码的复用与测试。
- 使用本分支造成的一切后果由使用者自行承担；如用于生产环境，请自行做代码审计与真机验证。

---

**上游 README（原始功能说明、配对面板截图等）已不再适用本分支**；如需对照可查看上游仓库。
