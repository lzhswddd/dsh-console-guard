# 宿主侧加固说明（host-hardener / task-2）

> 范围：`lib/index.js`、`lib/client.js`（+ 本文件）。  
> 策略来源：`lib/guard-policy.mjs`（Lead 维护，只读使用）、`docs/PATCH-PLAN.md` §三.C。  
> 结论：**宿主侧高危能力默认全部关闭（最小 diff 门控，可回滚）；`/cmd` 危险 op 全部收口、只读 op 返回不联网桩、文件类 op 限制在白名单根目录；面板按 `state.guard.features` 隐藏升级/公网/异地配对入口。加载期零 `fetch`、零下载器 spawn。**

---

## 1. 改动统计

```
 lib/client.js | 21 +++++++++++++-------   (24 行变更)
 lib/index.js  | 158 +++++++++++++++++++++++++++++++++++++++++++---------------   (134 增 / 45 删)
```

- 只改上述两个源文件；`id: "dsh-console-plugin"`（client.js 第 3 行）**未改动**。
- `git diff` 自检：无大段删除；所有上游逻辑都保留，只是在入口处加 `guardOn` 门控（`config.guard.enabled=false` 可回到原行为，仅供回归对照，日常禁用）。
- 未改：`lan-server.mjs`、`mp-*.mjs`、`guard-policy.mjs`、`package.json`、`cordis.patch.yml`、`test/**`、`analysis/**`、上游 `dsh-console-plugin/`。

## 2. index.js 改动清单（对应 PATCH-PLAN §三.C）

### 2.1 入口与策略

| 位置 | 改动 |
|---|---|
| import（约 L28） | `import { resolveGuardConfig, cmdOpDenied, cmdOpReadonlyStub, isFsCmd, fsCmdPathOf, pathWithinRoots, resolveFileRoots, GUARD_FEATURES } from './guard-policy.mjs'` |
| `apply()` 开头（L197） | `const guard = resolveGuardConfig(config.guard)`；`guardOn = guard.enabled === true`；`guardRoots = resolveFileRoots(inboxDir(), guard)`（收件箱 + `fileRoots`）；加载日志打印 `enabled / fileRoots / features` |
| `runCommand()` 顶部（L3625） | `guardOn && cmdOpDenied(op)`：只读 op → `guardStubFor(op)` 桩；其余 → `{ ok:false, error:'guard-disabled: ' + op }`。`guardOn && isFsCmd(op)`：`fsCmdPathOf` 取 path，非空且 `!pathWithinRoots(path, guardRoots)` → `{ ok:false, error:'guard: path not allowed' }`；空 path 保留上游行为 |

### 2.2 关闭后台高危能力（全部 `guardOn` 门控）

| 能力 | 改动 | 行号 |
|---|---|---|
| 云链路 cloudLink | guard 模式不调用 `createCloudLink`（`cloudLink` 恒 null），只打日志；`cloudPushReady/reportTokenToCloud/backfillTokensToCloud/sendPushCloudFirst` 沿上游 null 分支降级 | L2976 |
| 升级引擎 cloudPlugin | `guardOn ? null : createCloudPlugin(...)`；`getUpdateState` 返回桩；`getInfo` 里 `refreshLatestVersion()`（联网查 npm registry）被 guard 关掉；`installKind/installDev` 本就 null-safe | L3046 / L3096 |
| 隧道 frpc / 自定义服务器 | `bootTunnel()` 开头 `if (guardOn) return {phase:'disabled',...}`；启动处 `if (!guardOn) bootTunnel()`；`lan.setTunnel()` 在 guard 模式给「恒 disabled」快照；`customServerSet` 等 op 已被 `/cmd` 策略拒绝 | L2893 / L3140 |
| 华为推送 | guard 模式不创建 `createTurnAnnouncer` / `createPushWatcher`（不 `start()`）、不 `backfillTokensToCloud`；`sendPush` 因而不可达 | L5131-5154 |
| 伴生插件静默安装 | guard 模式不调用 `ensureCompanionPlugin`（不装 dsh-web-mobile） | L5184 |
| meme-gallery | `guardOn ? null : createMemeGallery(...)`；`localImagesOf` 对 `memes` 做空值保护（meme 标签不再展开，普通本地图片路径逻辑不变） | L480 / L529 |
| 异地配对码 | `getRemotePair: () => (guardOn ? false : remotePairOn())`：guard 模式恒关，lan-server 不会生成/上报异地配对码（`/claim` 只认本机 6 位码） | L3071 |

### 2.3 Lead 约定接口（已按契约实现）

| 调用点 | 传入 |
|---|---|
| `startLanServer({...})` | `guard: guard`（lan-server 内部再 `resolveGuardConfig(o.guard)`） |
| `attachMp(ctx, {...})` | `guard: guard`、`fileRoots: guardRoots`（mp-support→dispatcher 用于 `host.listDirectory` 越界拒绝） |
| 面板 `state.guard` | 由 Lead 在 lan-server `panelData()` 提供：`{ enabled, version: GUARD_VERSION, features: GUARD_FEATURES }`（已确认在 `lib/lan-server.mjs` L1517 就绪，client.js 依赖该形状） |

### 2.4 `/cmd` 只读桩形状（`guardStubFor`）

```js
updateCheck:    { ok:false, disabled:true }
updateState:    { disabled:true, version: PLUGIN_VERSION }
remotePairGet:  { enabled:false, available:false }
customServerGet:{ enabled:false }
pushStatus:     { ready:false, disabled:true }
pushTokenList:  { items: [], tokens: [] }   // 同时给 items/tokens，降低手机端字段假设不一致的风险
```

### 2.5 fsDrives（手机文件选择器）

guard 模式只返回白名单根目录条目（上游形状 `{ ok, drives[], home }`）：

- 根目录本身是盘符根（`C:\`）→ 条目 `"C:"`（与上游盘符条目形状一致）；
- 其它根目录（默认只有收件箱）→ 条目为绝对路径（`fsList` 可直接使用；手机端若在条目后补 `\` 也仍落在根内）；
- `home` = 第一个白名单根（默认收件箱），不再暴露 `os.homedir()`。

## 3. client.js 改动清单

1. `Panel` 内新增（L1877）：从面板数据取 `state.guard`，`guardOff(key)` 判断 `guard.enabled !== false && features[key] === false`；**没有 `state.guard` 时自动退回上游完整面板**（向后兼容/降级安全）。
2. 隐藏已关闭入口：
   - `UpdateCard`（插件升级）→ `guardOff("mobileUpdate")`；
   - `RemotePairCard`（异地配对）→ `guardOff("remotePair")`；
   - `CustomServerCard`（自定义公网服务器/隧道）→ `guardOff("tunnel")`；
   - `LinksRow` 的「公网连接」列 → `hideRemote = guardOff("cloud") || guardOff("tunnel")`（本机地址列保留）；
   - `AccessCard` 的「公网连接」开关行 → `hideRemote = guardOff("cloud")`（局域网开关保留）。
3. 扫码卡、6 位码卡、连接状态、设备列表、本机地址卡片均未改动，照常工作；`id: "dsh-console-plugin"` 未改。
4. 侧栏更新角标：`updateState` 桩无 `updateAvailable` 字段 → 自然不显示角标；侧栏挂载时的一次 `updateCheck` 现在由宿主返回本地桩（不联网、无报错提示）。

## 4. 验证记录（全部在本机执行，未装 profile、未占 8899、未联网）

Node：`C:\Users\lzh\.dsh\dsh-runtimes\dsh-primary-runtime\dependencies\node\bin\node.exe`

### 4.1 语法 / 模块加载

```powershell
node --check lib/index.js     # exit=0
node --check lib/client.js    # exit=0
node -e "import('file:///.../dsh-console-guard/lib/index.js').then(m=>console.log('IMPORT_OK',typeof m.apply,Object.keys(m).length))"
# IMPORT_OK function 20
```

### 4.2 fake-ctx apply() 冒烟（临时脚本，未入库；不监听真实端口、不占 8899）

做法：fake `ctx`（`get/on/effect` + 内存 `connection.fetch` 注册表）→ 预占 `0.0.0.0:<随机端口>` 让 `lan.start()` 必然 EADDRINUSE（因此 **不会**触发 lan-server 的无条件 UDP 8899 发现应答器）→ `apply()` → 直接调用注册的 4 条面板路由 handler 断言。结果（exit=0）：

```json
{
  "ok": true,
  "routes": ["/api/dsh-console/state","/api/dsh-console/newcode",
             "/api/dsh-console/sessions","/api/dsh-console/cmd"],
  "fetchCalls": [],
  "failures": [],
  "sampleStubs": {
    "updateCheck": { "ok": false, "disabled": true },
    "updateState": { "disabled": true, "version": "0.5.65-guard.1" },
    "pushTokenList": { "items": [], "tokens": [] }
  }
}
```

覆盖断言（全部 PASS）：
- 4 条面板路由注册成功；加载期 + 读取面板 state 后 `fetchCalls == []`（零外联）；
- 6 个只读桩形状正确；16 个危险 op（插件安装/启停、升级/回滚、异地配对写、自定义服务器写、推送注册/测试、桌面代理、权限/预设切换、pvWeather）全部返回 `guard-disabled: <op>`；
- `fsDrives` 只回 `[收件箱]` 且 `home=收件箱`；`fsList(收件箱)`/`readFile(收件箱内文件)` 放行；`fsList(C:\Windows)`、`fsMkdir(C:\Windows\...)`、`readFile(C:\Windows\win.ini)`、根外临时文件 全部返回 `guard: path not allowed`；
- 面板 `state`：`guard.enabled=true`、`features.mobileUpdate=false`、`updateState.disabled=true`、`remotePair=false`、`remotePairCode=""`、`version=0.5.65-guard.1`；
- 清理（`ctx.effect` 的 cleanup）无异常。

### 4.3 静态证据

```powershell
# 作者域名只在未创建的模块常量里，index.js 本身不含
Select-String -Path lib\*.mjs,lib\*.js -Pattern 'gaoshou25\.cn'
#   lib/cloud-link.mjs:7      DEFAULT_CLOUD_BASE
#   lib/ffmpeg-bootstrap.mjs:7 FFMPEG_MANIFEST_URL
#   lib/frpc-bootstrap.mjs:8   FRPC_MANIFEST_URL
# index.js 中 createCloudLink/createCloudPlugin/ensureCompanionPlugin/startTunnel/
# createPushWatcher/createTurnAnnouncer 均只出现在 guardOn 保护/不可达分支：
#   L2893 bootTunnel 首个语句 `if (guardOn) return ...`
#   L2976 `if (guardOn) { 不创建云链路 } else { createCloudLink(...) }`
#   L3046 `const cloudPlugin = guardOn ? null : createCloudPlugin({...})`
#   L3144 `if (!guardOn) { try { bootTunnel() } ... }`
#   L5131 `if (!guardOn) { turnAnnouncer = createTurnAnnouncer(...) }`
#   L5141 `if (guardOn) ... else if (...) createPushWatcher(...)`
#   L5184 `if (guardOn) ... else { ensureCompanionPlugin(...) }`
# 被 import 的模块无顶层 fetch/spawn（上一行为空输出）：
Select-String -Path lib\cloud-link.mjs,lib\dsh-console-cloud.mjs,lib\hw-push.mjs,lib\companion.mjs,lib\meme-gallery.mjs,lib\wan-meter.mjs,lib\tunnel.mjs,lib\frpc-bootstrap.mjs,lib\ffmpeg-bootstrap.mjs,lib\lan-server.mjs,lib\mp-*.mjs,lib\screen-*.mjs -Pattern '^(spawn|execFile|fetch|https?\.request)\('
```

### 4.4 未执行（按任务约束）

- 未跑端到端集成测试（Lead 正在并行改 `lan-server.mjs` / `mp-*.mjs`；e2e/兼容/安全回归由 `protocol-harness` 的 `test/guard` 负责）。
- 未在真实鸿蒙 App / 真实 profile 上验证（红线）。
- 未测试 `config.guard.enabled=false` 分支（会恢复云链路/隧道/推送/升级，故意不跑，避免外联）。

## 5. 残留风险 / 待真机验证

1. **手机文件选择器（fsDrives）**：guard 模式条目对「收件箱/白名单目录」返回绝对路径，仅在盘符根时返回 `C:` 形式。官方 App 对 `drives` 条目的拼接方式未知（是否补 `\`、是否只接受盘符），**需真机验证**。即使拼接失败也只会导致选择器显示/跳转异常，不会越权（越界仍被 `pathWithinRoots` 拒绝）。
2. **只读桩字段**：`updateCheck/updateState/remotePairGet/customServerGet/pushStatus/pushTokenList` 采用「最小形状」，面板端已隐藏相关卡片；手机 App 若直接依赖这些字段渲染设置页，可能显示空/禁用（未在真机验证）。已尽量给 `items`+`tokens` 双字段降低风险。
3. **`state.guard` 契约**：client.js 依赖 lan-server `panelData().guard`（Lead 已加）。若字段缺失/改名，面板会退回上游展示（不会崩，但不会隐藏入口）——集成时请保持 `{ enabled, version, features }`。
4. **未收口的宿主能力（不在本任务红线清单，需 Lead/verifier 决策）**：
   - `hm_weather_card` 工具仍注册给宿主 tools，但 `execute` 返回**固定演示数据、无任何网络请求**（index.js:2194-2238；verifier 复核已确认）。真正会访问 `api.open-meteo.com` 的是 `pvWeather` op，已被 `/cmd` 策略 `guard-disabled` 拒绝；
   - `slashRun`、`create/fork/archive/delete`、`accessSet/masterSet`、`clientSlotDiagnostic` 仍允许已配对设备调用（会话核心操作；`accessSet` 只改开关，无隧道后无公网能力）；
   - `lib/*.mjs` 中的 screen/cloud/tunnel 等模块仍被 import（保持 diff 小），靠 lan-server 路由闸门 + 宿主侧不启动使其不可达；模块顶层无副作用（已 grep）。
5. **`config.guard.enabled=false`** 仅用于与上游做回归对照，会恢复全部高危能力，生产环境禁止使用。
6. 加固版仍保留 6 位码 + 扫码配对（兼容契约），配对鉴权强度依赖配对码/票据（lan-server 已加 loopback/Host/限速，P0 由 Lead 修复）+ 设备 token；未改协议本身。
7. 加载/运行期零外联只覆盖了「加载 + apply + 面板 state + /cmd 桩」；真实会话/附件流程的外部行为由 test/guard 的 C 组用例与 verifier 复测。

## 6. 附：冒烟脚本（可复现，临时保存到 `%TEMP%\guard-host-smoke.mjs` 运行）

> 不写入仓库；与 §4.2 同一套断言的精简版。运行：`node %TEMP%\guard-host-smoke.mjs`，退出码 0 = 全过。  
> 本附录已用 Node 从本文件按 UTF-8 抽取后 `--check` 并实际执行：`ok=true`、`fetchCalls=[]`、`failures=[]`（2026-11-05）。

```js
import net from 'node:net'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'

const ROOT = 'C:/Users/lzh/Documents/deepseek-harness/default-workspace/dsh-console-guard'
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'guard-host-smoke-'))
const inbox = path.join(tmp, 'inbox')
fs.mkdirSync(inbox, { recursive: true })
fs.writeFileSync(path.join(inbox, 'hello.txt'), 'hello')
process.env.USERPROFILE = tmp
process.env.HOME = tmp
process.env.DSH_CONSOLE_INBOX = inbox
process.env.DSH_CONSOLE_NO_COMPANION = '1'
delete process.env.DSH_CONSOLE_NPM_LATEST_URL

const failures = []
const logs = []
const origLog = console.log
console.log = (...a) => logs.push(a.map(String).join(' '))
const fetchCalls = []
const realFetch = globalThis.fetch
globalThis.fetch = (...a) => { fetchCalls.push(String(a[0] || '')); return realFetch.apply(globalThis, a) }
const check = (ok, label, extra) => { if (!ok) failures.push(label + (extra !== undefined ? ' :: ' + JSON.stringify(extra) : '')) }

let blocker = null
try {
  // 预占端口 ⇒ apply 的 lan.start() EADDRINUSE，不会真正监听，也不会启 UDP 8899 发现应答器
  blocker = net.createServer()
  await new Promise((res, rej) => { blocker.once('error', rej); blocker.listen(0, '0.0.0.0', res) })
  const port = blocker.address().port

  const mod = await import('file:///' + ROOT + '/lib/index.js')
  const routes = new Map()
  const disposers = []
  const fakeConn = { fetch: { register: (r) => { routes.set(r.path, r); return () => {} } } }
  const fakeCtx = {
    logger: null,
    get: (n) => (n === 'connection' ? fakeConn : null),
    on: () => () => {},
    effect: (f) => { const d = typeof f === 'function' ? f() : null; if (typeof d === 'function') disposers.push(d); return () => {} }
  }
  await mod.apply(fakeCtx, { port, name: 'guard-smoke', guard: { enabled: true } })
  await new Promise((r) => setTimeout(r, 200))

  const callRoute = async (p, init) => (await routes.get(p).fetch(new Request('http://127.0.0.1' + p, init))).json()
  const callCmd = async (op, payload) => (await callRoute(mod.CMD_PATH, {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ op, payload: payload || {} })
  })).result

  check(routes.size === 4, '4 条面板路由', [...routes.keys()])
  check(fetchCalls.length === 0, '加载期零 fetch', fetchCalls)
  check((await callCmd('updateCheck'))?.disabled === true, 'updateCheck 桩')
  check((await callCmd('updateState'))?.disabled === true, 'updateState 桩')
  check((await callCmd('pushStatus'))?.disabled === true, 'pushStatus 桩')
  check((await callCmd('updateStart'))?.error === 'guard-disabled: updateStart', 'updateStart 拒绝')
  check((await callCmd('pluginBundleInstall'))?.error === 'guard-disabled: pluginBundleInstall', '插件安装拒绝')
  check((await callCmd('readFile', { path: 'C:\\Windows\\win.ini' }))?.error === 'guard: path not allowed', 'readFile 越界拒绝')
  check((await callCmd('fsDrives'))?.drives?.[0] === inbox, 'fsDrives 白名单根')
  check((await callCmd('fsList', { path: inbox }))?.ok === true, 'fsList 根内放行')
  const st = await callRoute(mod.STATE_PATH, { method: 'GET' })
  check(st.updateState?.disabled === true && st.guard?.features?.mobileUpdate === false, '面板 guard 降级')
  check(fetchCalls.length === 0, '读取面板后仍零 fetch', fetchCalls)
  for (const d of disposers.reverse()) { try { d() } catch (e) { failures.push('cleanup: ' + e.message) } }
} catch (e) {
  failures.push('异常: ' + ((e && e.stack) || e))
} finally {
  if (blocker) { try { blocker.close() } catch (e) {} }
  console.log = origLog
  origLog(JSON.stringify({ ok: failures.length === 0, fetchCalls, failures }, null, 2))
  if (failures.length) process.exitCode = 1
}
```

## 7. 交接备注（给 Lead / verifier）

- 允许写盘范围已遵守：仅 `lib/index.js`、`lib/client.js`、本文件。
- 宿主侧接口已与 Lead 对齐：`startLanServer.guard`、`attachMp.guard/fileRoots`、`panelData().guard`。
- task-2 验收对应关系：语法/import ✅；危险能力门控 ✅；`/cmd` 策略 + 只读桩 + fs 白名单 + fsDrives ✅；面板降级 ✅；零外联证据 ✅；本说明 ✅。
- 若 verifier 复测发现 `updateState` 桩缺字段导致面板异常：面板卡片已按 guard 隐藏，属预期；若要增强桩字段，改 `guardStubFor` 一处即可。
