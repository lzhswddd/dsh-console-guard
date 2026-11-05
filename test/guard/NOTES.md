# test/guard · 协议兼容 + 安全回归测试装置说明（Owner: protocol-harness）

> 目标：**不依赖真手机**，用 Node 沙箱模拟官方鸿蒙 App「DSH控制台」的完整协议调用，证明
> (A) 加固版对 配对 / 会话 / 审批 / 附件 / 实时流 / 旧版 `/cmd` 的响应形状与上游 `dsh-console-plugin@0.5.64` 一致；
> (B) 加固版把 P0（局域网免鉴权取配对码/票据）与危险能力全部拒掉；
> (C) 运行期无任何外部网络/外联。
>
> 约束：不真实安装、不启动 8899 真实服务、不联网、不改 `lib/`、不改上游基线目录。

## 1. 运行方式

Node：`C:\Users\lzh\.dsh\dsh-runtimes\dsh-primary-runtime\dependencies\node\bin\node.exe`

```powershell
cd <ws>\dsh-console-guard

# 加固版验收（默认被测 <ws>\dsh-console-guard/lib）—— 退出码 0 = fail=0
<node> test/guard/run.mjs

# 上游基线对照（证明装置能复现已知漏洞 + 给出 A 组形状基准）
$env:GUARD_LIB = '<ws>\dsh-console-plugin\lib'
<node> test/guard/run.mjs
```

产物（均在 `test/guard/`）：
- `last-result.json`：最近一次运行的逐用例 PASS/FAIL/XFAIL/SKIP + 证据 + 外联记录 + summary；
- `baseline-upstream.json`：上游 0.5.64 基线（上游模式下自动写；供加固版做 A 组 parity 对照）；
- 退出码：`0` = fail=0（上游模式 XFAIL 不计 fail），`1` = 有失败，`2` = 装置起不来。

端口：19600–19700 动态空闲端口；UDP 8899 发现应答器允许（`startLanServer` 自带，`stop()` 关闭）。
临时目录（`os.tmpdir()/dsh-guard-harness-*`）：伪造 home、收件箱、白名单外文件、devices/revoked 文件；
`USERPROFILE`/`HOME`/`DSH_CONSOLE_*` 在动态 import 被测模块**之前**设置，不会写用户真实 `~/.dsh`。
token 固定 `a1b2c3d4e5f60718` × 4 = 64 hex；PATH 指向空目录（误触发的 ffmpeg/frpc/curl 都会 ENOENT）。

## 2. 装置结构

| 文件 | 作用 |
|---|---|
| `harness/server.mjs` | stub 宿主（`ctx`：`sessionController`/`host`/`quota` + `on()/emit()`；`listSessions`/`getInfo`/`runCommand`/`uploadSink`/`attachmentOf`…）+ **照抄 `lib/index.js` wiring**：`startLanServer({guard,…})` → `attachMp(ctx,{guard,fileRoots,…})` → `lan.setMp({branch,onUpgrade,issueForCode,issueDevice,store})` → `lan.start()`。顺序很重要：`start()` 创建 http server 时捕获 `o.mp.onUpgrade`，`setMp` 必须在其之前，否则 WS upgrade 会被直接 destroy。配对秘密来源见下：加固版走 `lan.newCode()`（面板等价路径）。 |
| `harness/app-sim.mjs` | 官方 App 行为：`node:http` 请求（可自定义 Host 头；连 `127.0.0.1` = loopback 来源、连本机 LAN IP = 局域网来源）；手写 WS 握手/帧（Cookie 连 `/mp/api/ws/mux`，发 ping、收 pong/session/event）；扫码票据流、6 位码流、`/mp` 配对+Cookie、`/mp` RPC、旧版 `/sessions /cmd /attachment /upload /file`。 |
| `run.mjs` | A/B/C 用例集 + 结果汇总 + parity 对照 + 退出码。 |

**配对秘密来源（2026-11-05 收尾变更）**：加固版把 `/newcode`、`/qr` 的 HTTP 端点**对所有来源（含 loopback）关闭（403）**，
面板改走 DSH 宿主认证路由 `POST /api/dsh-console/newcode` → `index.js` 直接调用 `lan.newCode()`；
`newCode()` 重置 6 位码+票据并返回 `panelData(true)`（`{code,payload,qrDataUrl,…}`）。
因此 `run.mjs` 的 `issuePairing()` 在加固版用 `lan.newCode()` 取 `code`/`payload(k=pt_)`/`qrDataUrl`；
上游基线没有 `newCode()`，退化为 loopback `GET /newcode`（上游既有行为，仅作对照）。
这样 A 组验证的是「面板等价路径 + 配对后续协议」，B1 单独断言 HTTP 端点四向（LAN/loopback × newcode/qr）全 403。

被测库路径参数化：`GUARD_LIB=<dir>`（默认 `<ws>/dsh-console-guard/lib`）；
通过 `await import(pathToFileURL(join(libDir,'lan-server.mjs')))` 动态导入。有 `guard-policy.mjs` → 判定 guard 模式，
没有 → 判定 upstream 模式。

### 离线 qrcode
`/qr` 与 `/newcode.qrDataUrl` 需要 `qrcode`。仓库无网络安装条件，装置用 `analysis/security/sandbox/node_modules/qrcode`
的离线 stub（`toDataURL` 返回固定 `data:image/png;base64,…`），复制到 `dsh-console-guard/node_modules/qrcode`
（已 gitignore）；同时用 `module.registerHooks` 把 `qrcode` 解析到该 shim，保证**上游基线**（其 lib 目录下没有
node_modules）也能出图。注意：这只验证「接口返回 dataURL、形状正确」，**不验证二维码内容可被扫描**。

### stub runCommand（重要设计说明）
真实宿主侧 `/cmd` op 策略在 `lib/index.js` 的 `runCommand()` 里，依赖完整 DSH 宿主，**本装置无法加载整个
`index.js`**。因此 harness 的 stub `runCommand` 镜像 `lib/index.js` 的 guard 分支：
- `guard-policy.mjs` 存在时：`cmdOpDenied`（危险 op 拒绝 / 只读 op 返回不联网桩）、`isFsCmd`+`pathWithinRoots`
  （fsList/fsMkdir/readFile 白名单根目录）、`fsDrives` 只回白名单根；
- 上游模式（无 `guard-policy.mjs`）：纯 stub，无任何 op 策略 → B8 的「漏洞复现」= op 直达宿主被执行。

即 **B8 验证的是 `guard-policy` 策略 + `/cmd` 通道 + `/file`/RPC 边界**；`index.js` 里 guard 分支的接线由
host owner 的改动与 verifier 的静态复核覆盖（本装置不重跑 index.js）。

## 3. 用例清单（对应 PATCH-PLAN §五）

A（兼容，加固版与上游**状态码/形状**一致；上游模式 PASS 即 baseline）：
- A1 配对码来源（面板等价路径）：加固版 `lan.newCode()` / 上游 loopback `GET /newcode` → `code` 6 位、
  `payload` 含 `b= k=pt_ i=dsh-console v=`、`qrDataUrl` dataURL（HTTP 端点关闭见 B1）；
- A2 扫码票据流：payload `k=pt_…` → **LAN** `POST /pair/ticket` → 200 `{ok,token=访问码,base,name,c}`；重复票据 403；
- A3 6 位码流（旧）：面板等价取码 → **LAN** `POST /claim` → 200 `{ok,token}`；
- A4 6 位码流（新）：**LAN** `POST /mp/pair/accept{token:code}` → 200 + `Set-Cookie: mp_device`；错码 403；
- A5 票据流续：**LAN** `GET /mp-cookie?token=` → 200 `{ok,cookie}`，Cookie 可用于 `/mp/api/session.list`；
- A6 `/mp` 设备通道：session.list 200（无 Cookie 401）、`/mp/pair/status` 200（匿名 401）、
  session.history/session.prompt 成功、17 个白名单 RPC 壳 `{type:'server-response',result.ok:true}`、未知方法被拒；
- A7 实时流：无/错 Cookie 握手 401；有 Cookie 101；`ping`→`pong`；stub 触发 `session/event` → 收到
  `{type:'session/event',sessionId,event:{type:'assistant/chunk',…}}`；
- A8 旧版通道：`/sessions`、`/cmd{sessions}`、`/cmd{fsList, path=收件箱}`、`/attachment`、`/upload`、`/file`(收件箱) 全 200；
- A9 `/info?token=` → 200 含 name/host/version/dshOk；错 token 401。

B（安全回归；加固版 PASS=拦住，上游模式 XFAIL=已知漏洞被复现）：
- B1 P0-1：`/newcode`、`/qr` 的 HTTP 端点四向（LAN/loopback × newcode/qr）→ 加固版全 403（上游全 200 泄露码/票据）；
- B2 DNS rebinding：loopback + `Host: evil.example` 访问 `/newcode` `/qr` `/claim` `/pair/ticket` `/mp/pair/accept` → 加固版全 403
  （上游全 200；claim/ticket/accept 用有效码/票，可区分「Host 被拒」与「码无效」）；
- B3 LAN 连续错码 `/claim` 21 次 → 加固版第 21 次 429（上游 21×403，无限爆破）；
- B4 LAN 连续错码 `/mp/pair/accept` 35 次 → 加固版出现 429（上游 35×403）；
- B5 带 `x-forwarded-for` 的 `/newcode` `/sessions` `/mp RPC` `/mp/pair/accept` → 加固版全 403
  （上游 `/sessions`、`/mp/api/*`、`/mp/pair/accept` 均 200 = 公网/隧道绕闸）；
- B6 `/gui` `/screen/prepare` `/cloud/status` `/dsh-market` `/web` `/pet` `/plugins` → 加固版 404（上游 401/403/503）；
- B7 `/file?path=<收件箱外文件>` → 加固版 403 `guard: path not allowed`（上游 200 读出内容）；
- B8 `/cmd`：16 个危险 op（安装/启停插件、升级/回滚、隧道/自定义服务器、推送注册、桌面代理、权限/预设、演示工具）
  + 6 个只读 op（必须返回不联网桩）全部被拒/桩化；`fsList`/`readFile` 越界拒绝；`fsDrives` 只回收件箱根；
- B9 设备吊销是硬边界：`mp.store.mint` → `revokeDevice` → 重新 `/claim` 后仍 `isRevoked`（上游 claim 会按 uid 自动解黑）；
- B10 `/mp api host.listDirectory` 白名单外 → `forbidden`（上游任意目录可浏览），白名单内 200；
- B11 `/cmd` 请求体上限（SEC-22）：13MB body → 加固版拒绝（12MB 上限，服务端 destroy/4xx），上游照单全收 200。

C（运行期外联）：
- C1 在 `createHarness` 里包装 `globalThis.fetch` / `http.request|get` / `https.request|get` / `child_process.*`，
  加载 + 启动 + 全套 A 流程后断言：外部目标 0、无 gaoshou25.cn / registry.npmjs.org / huawei、无 frpc/ffmpeg/curl spawn；
  观测到的 host 只允许 127.0.0.1 与本机 LAN IP。
  局限：只观测进程内 JS 网络 API + spawn；不观测 raw socket/DNS/UDP（发现应答器只回探测者，不应答不算外联）。

## 4. 实测结果（当前工作区）

| 模式 | 结果 |
|---|---|
| 上游基线 `dsh-console-plugin/lib` | PASS=10（A 组）/ FAIL=0 / XFAIL=11（B 组已知问题全部复现）/ SKIP=0（共 21 项）→ 退出码 0 |
| 加固版 `dsh-console-guard/lib` | PASS=22 / FAIL=0 / XFAIL=0 / SKIP=0（共 22 项，含 A-parity）→ 退出码 0；A 组 parity 与基线比较 9 项一致 |

测于 2026-11-05 20:45-20:47（+08），两端各跑一次，运行前后 lib 指纹一致（见 §7）。

## 5. 与 PATCH-PLAN 描述不一致的协议细节（以源码为准）

1. **WS 没有 `{type:'ready'}` 帧**。`mp-contract.mjs` 里的 `readyFrame()` 是**死代码**（全仓只有单测引用，
   服务端 `mp-ws-live.mjs`/`websocket.js` 从不下发）。上游 0.5.64 与 npm 包一致。因此 A7 以 **HTTP 101 握手成功**
   为「实时流就绪」，并断言 `ping→pong` 与 `session/event` 帧；若收到 ready 帧只记录不断言（`receivedReady`）。
   与 Lead 确认过：官方 App 不能改，兼容性以现有 0.5.64 行为为准，**不要**为测试新增 ready 帧。
2. **加固版 `/newcode`、`/qr` 的 HTTP 端点对任何来源（含 loopback）一律 403**（2026-11-05 收尾强化）。
   原因：上游「仅 loopback」仍可被本机浏览器里的恶意页面跨站 fetch 读取（SEC-10/SEC-20 残留），所以干脆关闭；
   面板改走 DSH 宿主认证路由 `POST /api/dsh-console/newcode` → `index.js` 直接调用新增的 `lan.newCode()`
   （重置 6 位码+票据并返回 `panelData(true)`）。测试从 `lan.newCode()`（面板等价路径）取配对秘密（见 §2），
   B1 断言 LAN/loopback × newcode/qr 四向全 403。上游基线模式仍走 loopback `GET /newcode` 作 200 对照。
3. **`/pair/ticket` / `/claim` / `/mp/pair/accept` 的官方 App 调用来源是局域网**。加固版里配对秘密只经面板
   `newCode()` 取得，因此用例顺序是：面板取码/票 → LAN 提交配对。B2（Host 伪造）用 loopback 来源 + 伪造 Host
   模拟 DNS rebinding，符合威胁模型。
4. **`/mp-cookie`**（token 换 `mp_device` Cookie）在加固版仍然可达（白名单路由、非 loopback-only），
   A5 用它验证扫码票据流后半段。
5. **`/mp/api/ws/mux` 的 Cookie 校验在 `createLiveUpgrade`**（`lan.setMp.onUpgrade`）里，不在
   `mountMpUpgrade`（后者在本 wiring 下未被使用）；harness 照 `index.js` 传 `onUpgrade`。
6. 上游 `/mp/api/*` 与 `/mp/pair/accept` 分支在 `X-Forwarded-For` 闸门之前 → 带 XFF 仍 200（SEC-11），
   B5 已作为上游对照复现。

## 6. 未覆盖/残留风险

- **没有真实鸿蒙 App、没有真机**：协议形状按源码 + stub 推导，未在真机验证；二维码 stub 不可扫描。
- 加固版 `lib/index.js` 的宿主侧初始化（不启动 cloud/tunnel/push/companion、upgrade 引擎、面板降级）需要
  完整 DSH 宿主，未在本装置加载；本装置覆盖的是 `lan-server`/`mp-*` 协议层 + `guard-policy` 策略 + `/cmd`/`/file` 边界。
  index.js 的加载期零外联由 host owner 的实现 + verifier 静态 grep 复核。
- 审批/提问的 **WS 下行帧**（approval/request → `approval/requested` 帧）未纳入 A 组断言（App 端 UI 行为无法离线验证）；
  stub ctx 的 approval/request 订阅路径已在 harness 中打通（可后续加用例）。
- `fsMkdir` 未做越界用例（避免上游模式真的在磁盘建目录）；其策略与 `fsList`/`readFile` 同一入口校验。
- **`/upload` 的加固版上限（`GUARD_UPLOAD_MAX_BYTES` = 256MB）未自动化**：需要构造 >256MB 上传，代价过高；
  相关逻辑与 `receiveToFile(..., maxBytes)` 同一入口，建议 verifier 静态复核或手工抽测。
  （`/cmd` 的 12MB body 上限已由 B11 覆盖。2026-11-05 收尾新增：guard 版还强制 `remotePairOn/remoteAccessOn=false`、
  panelData 增加 `guard` 字段——A1 已断言 `newCode()` 返回的 panelData 含 `guard.enabled/features`、token/code 形状。）
- 限速用例依赖同一进程内顺序执行（同一来源 IP 分桶）；真实部署按 `claimFailMax`/`pairAcceptMax` 配置窗口生效。
- UDP 发现应答器（8899）只验证「不崩溃/无外联」，未验证手机端发现流程（真机依赖）。

## 7. 本次测试对应的 lib 指纹（SHA256 前 16 位，2026-11-05 20:47 +08）

| 文件 | SHA256-16 |
|---|---|
| `lib/lan-server.mjs` | `BF87616AAFCAD3B2`（本轮收尾变更后） |
| `lib/index.js` | `E3E04DD862AEA4CD`（含 `NEWCODE_PATH` / `lan.newCode()` 面板换码） |
| `lib/guard-policy.mjs` | `E90AFB2CC9202447` |
| `lib/mp-support.mjs` | `8E521B2BBBA6B296` |
| `lib/mp-dispatch.mjs` | `DFD223E8B3B592BA` |
| `lib/mp-routes.mjs` | `4FB766001C39D46F` |
| `lib/client.js` | `AF79C356D48EDC11` |

上游基线 `dsh-console-plugin/lib` 为仓库基线导入版（0.5.64），未改。若 lib 再变，`run.mjs` 结果需重跑。
