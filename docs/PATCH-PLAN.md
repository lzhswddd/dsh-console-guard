# dsh-console-guard 加固分支 · 实施计划（PATCH-PLAN）

> 基线：`dsh-console-plugin@0.5.64`（GitHub HEAD 58bffb2，MIT 声明，已导入本仓库 git 基线）
> 目标：**官方鸿蒙 App「DSH控制台」不用改**，用它连加固版电脑端；同时消除已复现的 P0 与未披露高危能力。
> 本文件是团队共享的契约：改哪、怎么改、测什么、什么算完成。

---

## 一、总体策略（重要）

**不重写插件、不改手机端协议，只做「收口 + 加固」**：

1. **保留**上游的协议实现（`mp-contract/mp-routes/mp-dispatch/mp-support/mp-ws-live/websocket`、`client.js`）——手机 App 的兼容性靠它们，尽量不动。
2. **局域网服务加一个路由白名单闸门**：只放行手机 App 核心协议路由，其余一律 404。
3. **未鉴权配对端点收口**：`/qr`、`/newcode` 仅 loopback；所有配对端点校验 Host；`/claim` 与 `/mp/pair/accept` 限速。
4. **关闭高风险后台能力**：云端注册/心跳/推送、公网隧道、frpc/ffmpeg 下载、屏幕串流与远程输入、伴生插件静默安装、手机端升级、手机端装任意插件、任意路径读写、桌面 Web GUI 代理。
5. **保留手机端核心**：扫码/票据配对、6 位码配对、`/mp` RPC（会话列表/历史/发送/取消/切模型/审批问答/附件）、WebSocket 实时流、文件上传（收件箱）、受限文件下载。
6. 纯本地、零新增外联：**加固版加载后不应产生任何作者域名/registry 请求**。

命名：包名保持 `dsh-console-plugin`（client bundle 的 `id` 必须与包名一致，减少兼容风险），版本 `0.5.65-guard.1`。**安装前先卸载上游版本**（同包名/同 loader id）。

---

## 二、手机 App 协议面（兼容性契约，禁止改）

| 流程 | 客户端动作 | 服务端必须保持 |
|---|---|---|
| 扫码配对 | 读二维码 `dsh-console://pair?b=<base>&k=pt_…&n=&i=&c=&m=&v=` → `POST /pair/ticket {ticket}` → `{ok,token,base,name,c}` | 二维码 payload 字段不变；票据 5 分钟一次性；成功返回长期 token |
| 6 位码配对（旧） | 局域网发现/扫端口 → `POST /claim {code}` → `{ok,token,base,name,c}` | 6 位码 15 分钟、一次性；错码可被限速但正确码必须成功 |
| 6 位码配对（新） | `POST /mp/pair/accept {token: "<6位码>"}` → `Set-Cookie: mp_device=…` + `{ok,deviceId}` | 同上；`isPairCode` 只认当前 6 位码 |
| 设备通道 | Cookie `mp_device` → `POST /mp/api/<method> {rpcId,payload}` → `{type:'server-response',rpcId,result:{ok,value/error}}` | 24 个白名单方法名与返回壳不变 |
| 实时流 | `WS /mp/api/ws/mux` 或 `/mp/api/ws/host`（Cookie 鉴权） | `{type:'ready',clientId}`、`pong`、`session/event`、审批/提问帧不变 |
| 旧版通道 | `GET /sessions?token=`、`POST /cmd {op,payload}`、`GET /attachment`、`GET /file?path=`、`POST /upload`、`GET /info` | 保留；`/cmd` 的危险 op 见 §四 |
| 面板（电脑端） | `GET /api/dsh-console/state`、`POST /api/dsh-console/newcode`（DSH 宿主认证层） | 保留，字段只增不减（新增 `guard`） |

---

## 三、文件与改动（按 owner 划分）

### A. Lead：`lib/guard-policy.mjs`（已完成初版）

共享策略模块：路由白名单、Host 校验、loopback 判定、限速器、`/cmd` op 策略、文件根目录校验、特性开关。**其他人只读、不修改**；需要新策略项先找 Lead。

### B. Lead：`lib/lan-server.mjs`

1. `import` `guard-policy.mjs`；`startLanServer(o)` 内新增
   `const guard = resolveGuardConfig(o.guard)`，`enabled` 默认 true。
2. 在 `const p = …`（约 1531 行，短号校验之后、`/gui` 分支之前）插入**总闸门**：
   - `guard.enabled && !routeAllowed(p)` → `404 {ok:false,error:'guard: route disabled'}`（`/gui*`、`/screen*`、`/cloud/*`、`/web`、`/pet`、`HOST_ROOT_PATHS` 全部被挡）；
   - `guard.enabled && isPairingPath(p)` → `hostAllowed(req.headers.host, {lanAddresses: lanAddresses(), extraBaseUrls: guard.extraBaseUrls})` 不通过 → `403 {ok:false,error:'guard: host not allowed'}`（防 DNS rebinding）；
   - `guard.enabled && isLoopbackOnlyPath(p) && !(isLoopbackPeer(req) && forwardedFor(req)==='')` → `403`（`/qr`、`/newcode` 仅本机）；
   - `guard.enabled && isRemoteLink(req)` → `403 {error:'guard: remote sources are not supported'}`（加固版无隧道/反代；顺带关闭 SEC-02）。
3. `/claim`：错码计数**对所有来源**生效（把 `const remoteClaim = isRemoteLink(req)` 改为恒真语义），用 `guard.claimFailMax/claimFailWindowMs`；正确码路径必须仍然成功；成功重置计数（保持上游逻辑）。
4. `/mp/pair/accept`：分支调用前用 `RateLimiter({max: guard.pairAcceptMax, windowMs: guard.pairAcceptWindowMs})` 按 `clientKeyOf(req)` 限速，超限 `429 {ok:false,error:'too-many'}`。其余 `/mp/*` 不额外限速。
5. `/file`：`resolveFilePath()` 返回值必须再校验 `pathWithinRoots(fp, resolveFileRoots(inboxDir(), guard))`，不在根目录内 → `403 {ok:false,error:'guard: path not allowed'}`。`/attachment`、`/upload` 不变。
6. `/upload`：保留（写入收件箱）；保持上游大小/文件名校验。
7. WebSocket `server.on('upgrade')`：`guard.enabled` 时只允许 `/mp/api/ws/mux`、`/mp/api/ws/host`，其余（`/gui`、宿主根路径代理）直接 403 destroy；然后走 `mpUp`。
8. `panelData()`：新增 `out.guard = { enabled, version: GUARD_VERSION, features: GUARD_FEATURES }`；`cloud` 字段改为 `[...publicUrlsNow(), ...guard.extraBaseUrls].join(',')`（这样把 Tailscale 地址放进二维码 `c=`，手机不在同一 WiFi 也能扫码连，不走任何第三方隧道）；`token`/`code` 字段不动。
9. 发现应答器（UDP 8899）：保留（6 位码流程要靠它），但 `guard.enabled` 时不回 `host` 主机名。
10. 删除 `/claim`、`/pair/ticket` 成功后的「按 uid 解黑」逻辑（SEC-18：吊销后再次拿码不应自动复活）。`lib/mp-support.mjs` 的 `writeDevices/writeRevoked` 补 `{ mode: 0o600 }`。
11. `/cmd` 路由本身不改（额度/大小例外保留），危险 op 由宿主侧拦（见 C）。
12. **不要**删除 screen/cloud/tunnel 等 import（保持 diff 小）；它们因路由闸门与宿主侧不启动而不可达。上线前由 §五 静态检查确认无副作用。

### C. Host teammate：`lib/index.js` + `lib/client.js`

1. `import { resolveGuardConfig, cmdOpDenied, cmdOpReadonlyStub, isFsCmd, fsCmdPathOf, pathWithinRoots, resolveFileRoots, GUARD_FEATURES } from './guard-policy.mjs'`
   （`inboxDir` 已从 `lan-server.mjs` 导入）。
2. `apply()` 开头：`const guard = resolveGuardConfig(config.guard)`。
3. 关闭后台高危能力（默认全关，`config.guard.enabled=false` 仅测试用）：
   - `createCloudLink` 不创建（cloudLink = null）；依赖 cloudLink 的推送/心跳/云状态全部降级；
   - `createCloudPlugin`（升级引擎）不创建；`updateCheck/updateState` 返回桩；
   - `bootTunnel/startTunnel` 不调用；`/cmd remotePair*/customServer*` 返回桩/拒绝；
   - `ensureCompanionPlugin` 不调用（不静默安装 dsh-web-mobile）；
   - `createMemeGallery` 不创建（若影响面小）；
   - `createPushWatcher/createTurnAnnouncer/sendPush` 不启动（不做任何外部推送）；
   - 屏幕串流的初始化本就懒加载，不用改；但确保没有启动时触达 ffmpeg/frpc。
4. `startLanServer({...})` deps 增加 `guard`（传 `guard` 对象）；`attachMp(ctx, {...})` deps 增加 `guard`、`fileRoots`（见 D 的契约）。
5. `runCommand(op, payload, meta)` 开头（约 3578 行）：
   ```js
   if (guard.enabled && cmdOpDenied(op)) {
     if (cmdOpReadonlyStub(op)) return guardStubFor(op, payload)   // 不联网的桩
     return { ok: false, error: 'guard-disabled: ' + op }
   }
   if (guard.enabled && isFsCmd(op)) {
     const p = fsCmdPathOf(op, payload)
     if (p !== '' && !pathWithinRoots(p, roots)) return { ok: false, error: 'guard: path not allowed' }
     // 空 path 的上游行为保留（fsList 列根/默认目录）
   }
   ```
   `guardStubFor` 需查 `client.js` 与手机端的期望字段，返回最小可用形状（例如 `updateState:{disabled:true,version:PLUGIN_VERSION}`、`updateCheck:{ok:false,disabled:true}`、`remotePairGet:{enabled:false,available:false}`、`customServerGet:{enabled:false}`、`pushStatus:{ready:false,disabled:true}`、`pushTokenList:{items:[]}`），保证面板不崩。
6. `fsDrives`：返回允许的根目录作为「驱动器」列表（让手机文件选择器只看到白名单目录），具体形状照抄上游 `fsDrives` 返回结构。
7. 面板数据：`panelData` 的 `guard` 字段由 lan-server 提供；`client.js` 按 `state.guard.features` 隐藏「公网访问 / 异地配对 / 插件升级 / 屏幕」相关卡片，避免点了报错（若改动过大可只隐藏升级卡与公网卡，其余保留禁用态）。**client.js 的 `id: "dsh-console-plugin"` 不能改。**
8. 加载期零外联：不得调用 `fetch`/`https`/`spawn` 指向作者域名或下载器（grep 验收）。

### D. Lead：`lib/mp-support.mjs`、`lib/mp-routes.mjs`、`lib/mp-dispatch.mjs`

- `attachMp(ctx, deps)` 接收 `deps.guard`、`deps.fileRoots`，把 `{ pins, guard, roots }` 传给 `createDispatcher`；
- `host.listDirectory`：路径必须 `pathWithinRoots`，否则 `wrapErr(...,'forbidden','guard: path not allowed')`；
- `mp-routes.accept` 若再加内部限速（可选，lan-server 已拦）；
- `writeDevices/writeRevoked` 文件权限 0600。

### E. Test teammate：`test/guard/**`（只写这里）

见 §五。

### F. Verifier teammate：`analysis/guard/**`（只写这里，只读源码）

见 §六。

---

## 四、配置（`cordis.patch.yml` 里 `config.guard`）

```yaml
- id: dsh-console
  config:
    port: 8899
    name: "我的电脑"
    guard:
      enabled: true            # 默认 true；false 仅用于和上游做回归对比，危险
      fileRoots: []            # 允许手机浏览/下载的目录（收件箱始终允许）
      extraBaseUrls: []        # 例：["http://100.64.0.8:8899"]（Tailscale），会进二维码 c= 和 Host 白名单
      claimFailMax: 20
      claimFailWindowMs: 900000
      pairAcceptMax: 30
      pairAcceptWindowMs: 900000
```

默认行为（不配置时）：局域网 8899、只允许收件箱文件、无远端基地址、全部高危能力关闭。

---

## 五、测试验收（Test teammate）

**装置**：`test/guard/` 下自建 sandbox（不装进真实 profile、不碰 8899 真服务、不联网）：
- `harness/server.mjs`：用 stub `ctx`/`sessionController` 组装 `startLanServer` + `attachMp`（照抄 `index.js` 的 wiring：先起 lan，再 attachMp，再 `lan.setMp(...)`），端口取 19600–19700，token 用固定 64 hex，收件箱临时目录；
- `harness/qrcode-shim`：离线 `qrcode` stub（可复用 `analysis/security/sandbox/node_modules/qrcode`），保证 `/qr` 返回 PNG dataURL；
- 启动入口同时支持 `GUARD_LIB=<dir>`：默认测 `dsh-console-guard/lib`，另可指向 `dsh-console-plugin/lib` 做**上游对照**（parity）。

**必须覆盖的用例（全部要自动化，输出 PASS/FAIL + JSON 摘要）**：

A. 兼容性（加固版与上游 **响应形状一致**）：
1. loopback `GET /newcode` → 200，含 `code`(6位)、`payload` 含 `b=`、`k=pt_`、`i=dsh-console`；
2. `POST /pair/ticket {ticket}` → 200 `{ok:true,token}`；重复票据 → 403；
3. `POST /claim {code}`（从局域网 IP 发起）→ 200 `{ok:true,token}`；正确码仍能配对（关键！）；
4. `POST /mp/pair/accept {token:code}`（局域网）→ 200 + `Set-Cookie: mp_device`；错码 403；
5. 用 `mp_device` Cookie：`POST /mp/api/session.list` → `{type:'server-response',result.ok:true}`；无 Cookie 401；
6. `session.history`/`session.prompt`（成功路径）→ result.ok:true；
7. WS `/mp/api/ws/mux`（带 Cookie）→ 收到 `{type:'ready'}`；stub 触发 `assistant/chunk` 事件 → 收到 `session/event` 帧；
8. 旧通道：`GET /sessions?token=`、`POST /cmd {op:'sessions'}`、`GET /attachment`、`POST /upload`、`GET /file?path=<收件箱内文件>` 全部 200；
9. `/info?token=` 200，字段满足上游形状（name/host/version/dshOk）。

B. 安全回归（加固版必须拒绝，上游应复现 200 作为对照）：
1. 局域网来源 `GET /newcode` / `/qr` → 403（P0-1 核心）；
2. loopback 但 `Host: evil.example` 访问 `/newcode`、`/qr`、`/claim`、`/pair/ticket`、`/mp/pair/accept` → 403（DNS rebinding）；
3. 局域网来源连续错码 `/claim` 21 次 → 出现 429；正确码仍可在新窗口/未超限时配对；
4. `/mp/pair/accept` 连续 31 次 → 至少一次 429；
5. 局域网/loopback 请求带 `x-forwarded-for` → 403（无隧道模式）；
6. `/gui`、`/screen/prepare`、`/cloud/status`、`/dsh-market`、`/web`、`/pet`、`/plugins` → 404（加固版）；上游对应 200/401 作对照；
7. `/file?path=<收件箱外文件>` → 403（例如 C:\Windows\win.ini 或测试临时文件）；
8. `/cmd {op:'pluginBundleInstall'}`、`updateStart`、`permissionSet`、`desktopWeb`、`customServerSet` → 返回失败/disabled；`fsList` 越界 → 拒绝；`fsDrives` 只回白名单根；
9. 吊销设备后重新 claim 不自动解黑（若 harness 支持 device store 直测）。

C. 运行期外联：
- 在 sandbox 里替换全局 `fetch`/`http.request` 记录目标，加载+启动+配对+一次会话流程后断言：无 `gaoshou25.cn`、无 registry.npmjs.org、无 huawei 域名请求；未 spawn frpc/ffmpeg/curl 等（可用 PATH 空目录 + 记录 spawn 参数的方式）。

**运行方式**：`node test/guard/run.mjs`（Node：`C:\Users\lzh\.dsh\dsh-runtimes\dsh-primary-runtime\dependencies\node\bin\node.exe`）。退出码 0 且摘要 `fail=0` 才算通过。把结果写 `test/guard/last-result.json`。

---

## 六、独立复核（Verifier teammate）

在 Test 通过后、**独立**（自己写探针，不复用 Test 断言）执行：
1. 复跑上游 `analysis/lead/probe-lan-auth2.mjs` 的 P0 攻击链到加固版沙箱：`LAN /newcode → /claim → /sessions` 必须整链失败；
2. DNS rebinding / Host / XFF / 429 / 路由白名单 / 文件越界 / 危险 op 抽检；
3. 静态：grep `dsh-console-guard/lib` 内 `gaoshou25.cn`、`frpc`、`ffmpeg`、`cloud`、`screen`、`pluginBundleInstall` 的**可达路径**，确认只在被闸门挡住的分支/未启动的模块里；
4. 检查 `package.json` 无 postinstall、`files` 清单完整、版本号/描述正确；
5. 输出 `analysis/guard/verification.md`：逐条 PASS/FAIL + 证据命令 + 残留风险（明确写清「未在真机 App 上验证」）。
**只写 `analysis/guard/**`，不改插件源码。**

---

## 七、红线与约束

- 不安装到用户真实 profile、不启动 8899 上的真实服务、不下载 frpc/ffmpeg、不联网。
- 不改上游基线目录 `dsh-console-plugin/`；所有改动只在本目录 `dsh-console-guard/`。
- 不删改手机端协议字段/方法名/帧类型；兼容性优先于代码洁癖。
- 改完必须 `node --check` 或 `node -e "import()"` 全部入口，且 `git diff` 自检无意外大段删除。
- 若发现计划有冲突/不可行：先写进 `docs/DECISIONS.md` 并给 Lead 发消息，不要自行改协议。
