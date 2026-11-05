#!/usr/bin/env node
// dsh-console-guard · 协议兼容 + 安全回归自动测试（PATCH-PLAN §五 A/B/C）
//
// 用法：
//   默认（加固版验收）：
//     node test/guard/run.mjs
//   上游基线对照（证明装置能复现上游漏洞 / 形状一致，写 baseline-upstream.json）：
//     GUARD_LIB=<workspace>/dsh-console-plugin/lib node test/guard/run.mjs
//
// 退出码：0 = fail=0（上游模式下 XFAIL 是预期的安全失败，不计 fail）；1 = 有失败；2 = 装置起不来。
//
// 范围说明：本装置用 stub 宿主 + 真实 lan-server/mp-* 模块；没有真实手机、没有真实
// DSH profile、不联网。宿主侧 /cmd op 策略在 lib/index.js 里，本装置用 stub runCommand
// 镜像其 guard 分支（见 harness/server.mjs 注释 与 NOTES.md）。

import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

import {
  createHarness, netReport, TOKEN,
  DEFAULT_GUARD_LIB, UPSTREAM_LIB, REPO_ROOT, WORKSPACE_ROOT
} from './harness/server.mjs'
import {
  createApp, SkipError, parseTicketFromPayload, parseCookieSecret, PREFIX
} from './harness/app-sim.mjs'

const OUT_DIR = path.dirname(fileURLToPath(import.meta.url))
const LAST_FILE = path.join(OUT_DIR, 'last-result.json')
const BASELINE_FILE = path.join(OUT_DIR, 'baseline-upstream.json')
const NOTES_FILE = path.join(OUT_DIR, 'NOTES.md')

const GUARD_LIB = path.resolve(process.env.GUARD_LIB || DEFAULT_GUARD_LIB)

const PNG_BYTES = Buffer.from(
  'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII=',
  'base64'
)

// ── 小工具 ─────────────────────────────────────────────────────────────────
function assert(cond, msg) {
  if (!cond) throw new Error('断言失败: ' + String(msg || ''))
}

function assertEq(actual, want, msg) {
  if (actual !== want) {
    throw new Error('断言失败: ' + String(msg || '') + '（实际=' + JSON.stringify(actual) + '，期望=' + JSON.stringify(want) + '）')
  }
}

function wrongCodeOf(valid) {
  const v = String(valid || '')
  const candidates = ['000001', '123456', '654321', '999999', '111111', '222222']
  for (const c of candidates) if (c !== v) return c
  return v === '000001' ? '000002' : '000001'
}

function pick6(arr) {
  return arr.map((x) => x && x.status)
}

function rpcOf(res) {
  const j = res.json || {}
  return {
    status: res.status,
    type: j.type,
    rpcId: j.rpcId,
    result: j.result || null,
    ok: !!(j.result && j.result.ok === true),
    value: j.result && j.result.value,
    error: j.result && j.result.error
  }
}

function cursor(len) {
  return String(len).padStart(2, '0')
}

function fmtEvidence(ev) {
  try {
    const s = JSON.stringify(ev)
    return s.length > 520 ? s.slice(0, 517) + '...' : s
  } catch (e) {
    return String(ev)
  }
}

// ── 用例注册 ───────────────────────────────────────────────────────────────
const CASES = []
function test(id, group, title, fn) {
  CASES.push({ id, group, title, fn })
}

const S = {}
let H = null
let APP = null

function requireLan() {
  if (!H.lanIp) throw new SkipError('本机没有非 loopback IPv4，无法模拟局域网来源')
}
function lanSource() {
  requireLan()
  return 'lan'
}

/**
 * 取一份「当前有效」的配对秘密（6 位码 + 票据）。
 *
 * 加固版：HTTP 端点 /newcode、/qr 对任何来源（含 loopback）一律 403（P0-1 + SEC-10 跨站读取），
 * 面板改走宿主认证路由 → index.js 的 POST /api/dsh-console/newcode 直接调 lan.newCode()。
 * 因此测试装置也从 `lan.newCode()`（面板等价路径）取 code/payload/qrDataUrl。
 * 上游基线没有 newCode()，退化为 loopback GET /newcode（上游的既有行为，对照用）。
 */
async function issuePairing() {
  if (H.lan && typeof H.lan.newCode === 'function') {
    const d = (await H.lan.newCode()) || {}
    const payload = String(d.payload || '')
    return {
      source: 'lan.newCode()',
      code: String(d.code || ''),
      payload,
      ticket: parseTicketFromPayload(payload),
      qrDataUrl: d.qrDataUrl,
      data: d
    }
  }
  const res = await APP.newcodeLoopback()
  assertEq(res.status, 200, '上游基线 loopback GET /newcode status')
  const j = res.json || {}
  const payload = String(j.payload || '')
  return {
    source: 'http GET /newcode (upstream)',
    code: String(j.code || ''),
    payload,
    ticket: parseTicketFromPayload(payload),
    qrDataUrl: j.qrDataUrl,
    data: j
  }
}

// ── A. 兼容性（与上游响应形状一致）────────────────────────────────────────

test('A1', 'A', '配对码来源（面板等价路径）→ code 6 位、payload 含 b=/k=pt_/i=/v=、qrDataUrl 可出图（加固版 lan.newCode()；上游 loopback GET /newcode）', async () => {
  const issued = await issuePairing()
  assert(/^\d{6}$/.test(issued.code), 'code 应为 6 位数字，实际=' + JSON.stringify(issued.code))
  const payload = String(issued.payload || '')
  assert(payload.indexOf('dsh-console://pair?') === 0, 'payload 前缀应为 dsh-console://pair?，实际=' + payload.slice(0, 40))
  for (const tokenStr of ['b=', 'k=pt_', 'i=dsh-console', 'v=']) {
    assert(payload.indexOf(tokenStr) >= 0, 'payload 缺少 ' + tokenStr + '：' + payload.slice(0, 160))
  }
  assert(typeof issued.qrDataUrl === 'string' && issued.qrDataUrl.indexOf('data:image/png;base64,') === 0, 'qrDataUrl 应为 PNG dataURL')
  S.code1 = issued.code
  S.payload1 = payload
  S.ticket1 = issued.ticket
  assert(/^pt_[0-9a-f]{32}$/.test(S.ticket1), 'payload 里的 k= 票据形状异常: ' + S.ticket1)
  // 面板数据兼容：加固版 panelData 新增 guard 字段（字段只增不减），客户端据此隐藏已关闭能力。
  if (H.mode === 'guard') {
    const pd = issued.data || {}
    assert(pd.guard && pd.guard.enabled === true, 'newCode() 面板数据缺少 guard.enabled=true')
    assert(pd.guard.features && pd.guard.features.cloud === false && pd.guard.features.tunnel === false &&
      pd.guard.features.screen === false && pd.guard.features.push === false, 'guard.features 未关闭 cloud/tunnel/screen/push')
    assert(typeof pd.token === 'string' && pd.token.length === 64, 'panelData.token 形状异常')
    assert(pd.code === S.code1, 'panelData.code 与 newCode 返回不一致')
  }
  return {
    evidence: {
      source: issued.source,
      code: S.code1,
      payloadHead: payload.slice(0, 120),
      qrBytes: String(issued.qrDataUrl || '').length,
      panelGuard: issued.data && issued.data.guard ? { enabled: issued.data.guard.enabled } : null
    },
    parityStatus: 200
  }
})

test('A2', 'A', '扫码票据流：LAN POST /pair/ticket{k=…} → 200 {ok,token,base,name,c}；重复票据 403', async () => {
  const res = await APP.ticket(S.ticket1, { source: 'lan' })
  assertEq(res.status, 200, 'POST /pair/ticket status')
  const j = res.json || {}
  assertEq(j.ok, true, 'pair/ticket.ok')
  assertEq(j.token, TOKEN, 'pair/ticket.token 应等于访问码')
  assert(typeof j.base === 'string' && j.base.length > 0, 'pair/ticket.base 缺失')
  assert(typeof j.name === 'string', 'pair/ticket.name 缺失')
  assert('c' in j, 'pair/ticket.c 缺失')
  S.token = TOKEN
  const replay = await APP.ticket(S.ticket1, { source: 'lan' })
  assertEq(replay.status, 403, '重复票据应 403')
  return { evidence: { status: res.status, tokenLen: String(j.token || '').length, base: j.base, name: j.name, replayStatus: replay.status }, parityStatus: res.status }
})

test('A3', 'A', '6 位码流：面板等价取码（lan.newCode / 上游 HTTP）→ LAN POST /claim{code} → 200 {ok,token}', async () => {
  const issued = await issuePairing()
  const code = issued.code
  assert(/^\d{6}$/.test(code), '取码形状异常: ' + JSON.stringify(code))
  const res = await APP.claim(code, { source: 'lan' })
  assertEq(res.status, 200, 'LAN /claim status（正确码必须配对成功）')
  const j = res.json || {}
  assertEq(j.ok, true, 'claim.ok')
  assertEq(j.token, TOKEN, 'claim.token')
  assert(typeof j.base === 'string', 'claim.base 缺失')
  S.code3 = code
  return { evidence: { source: issued.source, status: res.status, tokenLen: String(j.token || '').length, base: j.base }, parityStatus: res.status }
})

test('A4', 'A', '6 位码（新）：LAN POST /mp/pair/accept{token:code} → 200 + Set-Cookie: mp_device；错码 403', async () => {
  const issued = await issuePairing()
  const code = issued.code
  const res = await APP.mpAccept(code, { source: 'lan' })
  assertEq(res.status, 200, '/mp/pair/accept 正确码 status')
  const j = res.json || {}
  assertEq(j.ok, true, 'pair/accept.ok')
  assert(typeof j.deviceId === 'string' && j.deviceId.length > 0, 'pair/accept.deviceId 缺失')
  const sc = res.headers['set-cookie']
  const secret = parseCookieSecret(sc)
  assert(secret !== '', 'Set-Cookie 缺少 mp_device')
  S.cookieSecret = secret
  S.cookie = 'mp_device=' + encodeURIComponent(secret)
  const wrong = await APP.mpAccept(wrongCodeOf(code), { source: 'lan' })
  assertEq(wrong.status, 403, '错码应 403')
  return { evidence: { status: res.status, deviceId: j.deviceId, hasSetCookie: !!sc, cookieLen: S.cookie.length, wrongStatus: wrong.status }, parityStatus: res.status }
})

test('A5', 'A', '扫码票据流续：LAN GET /mp-cookie?token=… → 200 {ok,cookie}，Cookie 可用于 /mp/api/session.list', async () => {
  const res = await APP.mpCookie(S.token)
  assertEq(res.status, 200, 'GET /mp-cookie status')
  const j = res.json || {}
  assertEq(j.ok, true, 'mp-cookie.ok')
  const secret = parseCookieSecret(j.cookie)
  assert(secret !== '', '/mp-cookie 返回的 cookie 里没有 mp_device')
  const cookie = 'mp_device=' + encodeURIComponent(secret)
  const rpc = await APP.mpRpc(cookie, 'session.list', {})
  assertEq(rpc.status, 200, 'session.list status')
  const r = rpcOf(rpc)
  assertEq(r.type, 'server-response', 'RPC 壳 type')
  assertEq(r.ok, true, 'session.list result.ok')
  assert(Array.isArray(r.value && r.value.items), 'session.list value.items 应为数组')
  assertEq(r.value.items[0] && r.value.items[0].sessionId, 'sess-1', '与会话桩一致')
  return { evidence: { status: res.status, cookieHead: String(j.cookie || '').slice(0, 24), rpcStatus: rpc.status, items: r.value.items.length }, parityStatus: res.status }
})

test('A6', 'A', '设备通道：session.list 200；无 Cookie 401；session.history/session.prompt 成功；24 白名单 RPC 壳一致；/mp/pair/status 200', async () => {
  const noCookie = await APP.mpRpc('', 'session.list', {})
  assertEq(noCookie.status, 401, '无 Cookie /mp/api/session.list 应 401')

  // App 配对后常会回读配对状态
  const st = await APP.request({ source: 'lan', method: 'GET', path: '/mp/pair/status', headers: { cookie: S.cookie } })
  assertEq(st.status, 200, 'GET /mp/pair/status status')
  assertEq(st.json && st.json.ok, true, '/mp/pair/status.ok')
  assertEq(st.json && st.json.paired, true, '/mp/pair/status.paired')
  const stAnon = await APP.request({ source: 'lan', method: 'GET', path: '/mp/pair/status' })
  assertEq(stAnon.status, 401, '无 Cookie /mp/pair/status 应 401')

  const rpc = (method, payload) => APP.mpRpc(S.cookie, method, payload)
  const cases = [
    ['session.list', {}],
    ['session.history', { sessionId: 'sess-1', maxMessages: 10 }],
    ['session.prompt', { sessionId: 'sess-1', text: '你好' }],
    ['workspace.list', {}],
    ['session.cancel', { sessionId: 'sess-1' }],
    ['session.models', {}],
    ['session.selectModel', { sessionId: 'sess-1', model: 'deepseek-chat' }],
    ['session.attachment', { attachmentId: 'att-1' }],
    ['command.list', {}],
    ['skill.list', {}],
    ['session.pins', {}],
    ['session.pin', { sessionId: 'sess-1', pinned: true }],
    ['push.key', {}],
    ['push.subscribe', {}],
    ['mobile.pending', {}],
    ['quota.read', {}],
    ['session.create', {}]
  ]
  const out = {}
  for (const [method, payload] of cases) {
    const res = await rpc(method, payload)
    const r = rpcOf(res)
    assertEq(res.status, 200, method + ' status')
    assertEq(r.type, 'server-response', method + ' 壳 type')
    assertEq(r.ok, true, method + ' result.ok')
    if (method === 'session.history') {
      assertEq(r.value && r.value.sessionId, 'sess-1', 'history.sessionId')
      assert(Array.isArray(r.value && r.value.events), 'history.events 应为数组')
    }
    if (method === 'session.prompt') {
      assert(!!(r.value && r.value.accepted), 'prompt.accepted 应为 true')
    }
    out[method] = res.status
  }
  // 不在白名单的方法必须被拒
  const unknown = await APP.mpRpc(S.cookie, 'bogus.method', {})
  assertEq(unknown.status, 200, '未知方法 HTTP 壳仍 200')
  const ur = rpcOf(unknown)
  assertEq(ur.ok, false, '未知方法应 result.ok=false')
  return { evidence: { noCookie: noCookie.status, pairStatus: st.status, pairStatusAnon: stAnon.status, methods: Object.keys(out).length, statuses: out, unknownOk: ur.ok }, parityStatus: 200 }
})

test('A7', 'A', '实时流：WS /mp/api/ws/mux 有 Cookie → 101；ping→pong；stub 触发 assistant/chunk → session/event 帧', async () => {
  requireLan()
  // 无 Cookie / 错 Cookie 必须被拒
  const anon = await APP.wsMux('')
  assert(anon.status === 401 || anon.status === 403, '无 Cookie WS 应 401/403，实际=' + anon.status)
  const bad = await APP.wsMux('mp_device=bogus-secret')
  assert(bad.status === 401 || bad.status === 403, '错 Cookie WS 应 401/403，实际=' + bad.status)

  const ws = await APP.wsMux(S.cookie)
  assertEq(ws.status, 101, 'WS 握手 status')
  ws.sendJson({ type: 'ping' })
  const pong = await ws.waitFor((m) => m && m.type === 'pong', 4000)
  assert(!!pong, '未收到 pong')
  await new Promise((r) => setTimeout(r, 80))
  const emitted = H.emit('session/event', H.session, {
    type: 'assistant/chunk',
    seq: 7,
    data: { turn: 1, step: 0, chunk: { type: 'text-delta', text: 'WS-HELLO-123' } }
  })
  assert(emitted >= 1, 'stub ctx 没有 session/event 订阅者')
  const frame = await ws.waitFor((m) => m && m.type === 'session/event', 5000)
  assertEq(frame.sessionId, 'sess-1', 'WS 帧 sessionId')
  assertEq(frame.event && frame.event.type, 'assistant/chunk', 'WS 帧 event.type')
  assertEq(frame.event && frame.event.data && frame.event.data.chunk && frame.event.data.chunk.text, 'WS-HELLO-123', 'WS 帧文本')
  // 说明：上游 0.5.64 服务端不主动发 ready 帧（readyFrame 是死代码），以 101 为就绪；
  // 若未来版本开始下发 ready，这里记录但不断言。
  ws.close()
  return { evidence: { anonStatus: anon.status, badCookieStatus: bad.status, wsStatus: ws.status, receivedReady: ws.receivedReady, gotPong: !!pong, gotSessionEvent: true }, parityStatus: ws.status }
})

test('A8', 'A', '旧版通道：/sessions /cmd{sessions} /cmd{fsList 收件箱} /attachment /upload /file(收件箱) 全 200', async () => {
  const sessions = await APP.sessions(S.token)
  assertEq(sessions.status, 200, 'GET /sessions status')
  const sj = sessions.json || {}
  assertEq(sj.ok, true, 'sessions.ok')
  assert(Array.isArray(sj.sessions), 'sessions.sessions 应为数组')
  assertEq(sj.count, sj.sessions.length, 'sessions.count')
  assertEq(sj.sessions[0] && sj.sessions[0].sessionId, 'sess-1', 'sessions[0].sessionId')
  assert(Array.isArray(sj.workspaces), 'sessions.workspaces 应为数组')

  const cmdSessions = await APP.cmd(S.token, 'sessions', {})
  assertEq(cmdSessions.status, 200, 'POST /cmd {op:sessions} status')
  const cj = cmdSessions.json || {}
  assertEq(cj.ok, true, '/cmd 外层 ok')
  assert(Array.isArray(cj.result), '/cmd sessions 结果应为数组')
  assertEq(cj.result[0] && cj.result[0].sessionId, 'sess-1', 'cmd sessions[0]')

  const cmdList = await APP.cmd(S.token, 'fsList', { path: H.inbox })
  assertEq(cmdList.status, 200, 'POST /cmd {op:fsList,path:收件箱} status')
  const lj = cmdList.json || {}
  assertEq(lj.ok, true, 'fsList 外层 ok')
  assertEq(lj.result && lj.result.ok, true, 'fsList result.ok（收件箱在白名单内必须允许）')
  assert(Array.isArray(lj.result && lj.result.entries), 'fsList result.entries 应为数组')

  const att = await APP.attachment(S.token, 'att-1')
  assertEq(att.status, 200, 'GET /attachment status')
  assertEq(att.headers['content-type'], 'image/png', 'attachment content-type')
  assertEq(att.body.length, PNG_BYTES.length, 'attachment 字节数')

  const upBody = 'hello-upload-123'
  const up = await APP.upload(S.token, 'app-upload.txt', upBody)
  assertEq(up.status, 200, 'POST /upload status')
  const uj = up.json || {}
  assertEq(uj.ok, true, 'upload.ok')
  assertEq(uj.bytes, Buffer.byteLength(upBody), 'upload.bytes')
  assertEq(uj.name, 'app-upload.txt', 'upload.name')
  assert(typeof uj.path === 'string' && uj.path.length > 0, 'upload.path 缺失')
  S.uploadPath = uj.path

  const fileUp = await APP.file(S.token, S.uploadPath)
  assertEq(fileUp.status, 200, 'GET /file 上传文件 status')
  assertEq(fileUp.text, upBody, '/file 内容应等于上传内容')

  const seedPath = path.join(H.inbox, 'seed-inbox.txt')
  const fileSeed = await APP.file(S.token, seedPath)
  assertEq(fileSeed.status, 200, 'GET /file 收件箱种子文件 status')
  assertEq(fileSeed.text, 'seed-inbox-content', '/file 种子内容')

  return {
    evidence: {
      sessions: sessions.status, cmdSessions: cmdSessions.status, cmdFsList: cmdList.status,
      attachment: att.status, upload: up.status, fileUploaded: fileUp.status, fileSeed: fileSeed.status
    },
    parityStatus: 200
  }
})

test('A9', 'A', '/info?token= → 200，含 name/host/version/dshOk；错误 token 401', async () => {
  const res = await APP.info(S.token)
  assertEq(res.status, 200, 'GET /info status')
  const j = res.json || {}
  assertEq(j.ok, true, 'info.ok')
  assertEq(j.name, 'guard-harness-host', 'info.name')
  assertEq(j.host, 'harness-host', 'info.host')
  assert(typeof j.version === 'string' && j.version.length > 0, 'info.version 缺失')
  assertEq(j.dshOk, true, 'info.dshOk')
  const bad = await APP.info('not-the-token')
  assertEq(bad.status, 401, '错误 token 应 401')
  return { evidence: { status: res.status, name: j.name, host: j.host, version: j.version, badTokenStatus: bad.status }, parityStatus: res.status }
})

// ── B. 安全回归（加固版必须拒绝；上游基线应复现漏洞）────────────────────
//
// 约定：fn 返回 { vuln: boolean, blocked: boolean, evidence }。
//   vuln    = 该攻击在上游语义下是否成功（上游模式的对照依据）
//   blocked = 加固版是否按预期拦住（guard 模式的 PASS 依据）

test('B1', 'B', 'P0-1：/newcode、/qr 的 HTTP 端点必须对任何来源（含 loopback）403；上游 LAN+loopback 均 200 泄露码/票据', async () => {
  requireLan()
  const attempts = []
  const probes = [
    ['lan', '/newcode'],
    ['lan', '/qr'],
    ['loop', '/newcode'],
    ['loop', '/qr']
  ]
  for (const [source, p] of probes) {
    const r = await APP.request({ source, method: 'GET', path: p })
    attempts.push({
      source,
      path: p,
      status: r.status,
      error: r.json && r.json.error,
      leakedCode: !!(r.json && /^\d{6}$/.test(String(r.json.code || ''))),
      leakedQr: r.status === 200 && String(r.headers['content-type'] || '').indexOf('image/png') >= 0
    })
  }
  const vuln = attempts.some((a) => a.leakedCode || a.leakedQr)
  const blocked = attempts.every((a) => a.status === 403)
  return { vuln, blocked, evidence: { attempts } }
})

test('B2', 'B', 'DNS rebinding：loopback + Host: evil.example 访问 /newcode /qr /claim /pair/ticket /mp/pair/accept → 必须 403', async () => {
  const evil = { host: 'evil.example' }
  const attempts = []

  const nc = await APP.newcodeLoopback({ headers: evil })
  attempts.push({ path: '/newcode', status: nc.status, error: nc.json && nc.json.error })
  const qr = await APP.qrLoopback({ headers: evil })
  attempts.push({ path: '/qr', status: qr.status, error: qr.json && qr.json.error })

  // Host 伪造时用「有效」的码/票，才能区分「Host 被拒」与「码无效」
  const issued = await issuePairing()
  const code = issued.code

  const claim = await APP.claimAs('loop', code, { headers: evil })
  attempts.push({ path: '/claim', status: claim.status, error: claim.json && claim.json.error })
  const pt = await APP.ticket(issued.ticket, { source: 'loop', headers: evil })
  attempts.push({ path: '/pair/ticket', status: pt.status, error: pt.json && pt.json.error })

  const issued2 = await issuePairing()
  const acc = await APP.mpAcceptAs('loop', issued2.code, { headers: evil })
  attempts.push({ path: '/mp/pair/accept', status: acc.status, error: acc.json && acc.json.error })

  const vuln = attempts.some((a) => a.status === 200)
  const blocked = attempts.every((a) => a.status === 403)
  return { vuln, blocked, evidence: { attempts } }
})

test('B3', 'B', '配对码爆破：LAN 连续错码 /claim 21 次必须出现 429（上游无 429）', async () => {
  requireLan()
  const valid = (await issuePairing()).code
  const statuses = []
  for (let i = 0; i < 21; i += 1) {
    let code = wrongCodeOf(valid)
    if (code === valid) code = '000000'
    const r = await APP.claim(code, { source: 'lan' })
    statuses.push(r.status)
  }
  const any429 = statuses.indexOf(429) >= 0
  return {
    vuln: !any429,
    blocked: any429,
    evidence: { statuses, any429, first429At: statuses.indexOf(429) + 1 }
  }
})

test('B4', 'B', '/mp/pair/accept 爆破：LAN 连续错码 35 次必须至少一次 429（上游无 429）', async () => {
  requireLan()
  const valid = (await issuePairing()).code
  const statuses = []
  for (let i = 0; i < 35; i += 1) {
    let code = wrongCodeOf(valid)
    const r = await APP.mpAccept(code, { source: 'lan' })
    statuses.push(r.status)
  }
  const any429 = statuses.indexOf(429) >= 0
  return {
    vuln: !any429,
    blocked: any429,
    evidence: { statuses, any429, first429At: statuses.indexOf(429) + 1 }
  }
})

test('B5', 'B', '无隧道模式：带 x-forwarded-for 的请求（/newcode /sessions /mp RPC /mp/pair/accept）→ 403', async () => {
  requireLan()
  const xff = { 'x-forwarded-for': '203.0.113.7, 10.0.0.1' }
  const attempts = []

  const nc = await APP.newcodeLan({ headers: xff })
  attempts.push({ path: '/newcode', status: nc.status, error: nc.json && nc.json.error })

  const sess = await APP.sessions(S.token, { headers: xff })
  attempts.push({ path: '/sessions', status: sess.status, error: sess.json && sess.json.error })

  const rpc = await APP.mpRpc(S.cookie, 'session.list', {}, { headers: xff })
  attempts.push({ path: '/mp/api/session.list', status: rpc.status, error: rpc.json && rpc.json.error })

  const nc2 = await issuePairing()
  const code = nc2.code
  const acc = await APP.mpAccept(code, { source: 'lan', headers: xff })
  attempts.push({ path: '/mp/pair/accept', status: acc.status, error: acc.json && acc.json.error })

  const vuln = attempts.some((a) => a.status === 200)
  const blocked = attempts.every((a) => a.status === 403)
  return { vuln, blocked, evidence: { attempts } }
})

test('B6', 'B', '路由白名单：/gui /screen/prepare /cloud/status /dsh-market /web /pet /plugins → 加固版 404（上游非 404）', async () => {
  const paths = ['/gui', '/screen/prepare', '/cloud/status', '/dsh-market', '/web', '/pet', '/plugins']
  const statuses = {}
  for (const p of paths) {
    const r = await APP.request({ source: 'loop', method: 'GET', path: p })
    statuses[p] = { status: r.status, error: r.json && r.json.error }
  }
  const list = Object.values(statuses)
  const all404 = list.every((x) => x.status === 404)
  const anyNot404 = list.some((x) => x.status !== 404)
  return {
    vuln: anyNot404,
    blocked: all404,
    evidence: { statuses }
  }
})

test('B7', 'B', '文件越界：GET /file?path=<收件箱外文件> → 加固版 403（上游 200 读出内容）', async () => {
  const outside = H.outsideFile
  const res = await APP.file(S.token, outside)
  const leaked = res.status === 200 && res.text.indexOf('OUTSIDE-SECRET-CONTENT') >= 0
  return {
    vuln: leaked,
    blocked: res.status === 403 && !!(res.json && String(res.json.error || '').indexOf('path not allowed') >= 0),
    evidence: { path: outside, status: res.status, error: res.json && res.json.error, leaked }
  }
})

test('B8', 'B', '/cmd 危险 op：安装/升级/隧道/推送/桌面代理/权限预设 全部被拒；fsList/readFile 越界被拒；fsDrives 只回白名单根', async () => {
  const dangerous = [
    'pluginBundleInstall', 'pluginBundleToggle', 'updateStart', 'updateCancel', 'updateRollback',
    'remotePairSet', 'remotePairCodeRefresh', 'customServerSet', 'customServerPrompt',
    'pushRegister', 'pushTest', 'desktop', 'desktopWeb', 'permissionSet', 'selectPreset', 'pvWeather'
  ]
  const readonly = ['updateCheck', 'updateState', 'remotePairGet', 'customServerGet', 'pushStatus', 'pushTokenList']

  function denied(op, result) {
    const r = result || {}
    if (dangerous.indexOf(op) >= 0) {
      return r.ok === false && String(r.error || '').indexOf('guard-disabled') === 0
    }
    switch (op) {
      case 'updateCheck': return r.ok === false
      case 'updateState': return r.disabled === true
      case 'remotePairGet': return r.enabled === false
      case 'customServerGet': return r.enabled === false
      case 'pushStatus': return r.disabled === true || r.ready === false
      case 'pushTokenList': return Array.isArray(r.items) && r.items.length === 0 && (!r.tokens || r.tokens.length === 0)
      default: return false
    }
  }

  const opRows = {}
  let accepted = 0
  for (const op of dangerous.concat(readonly)) {
    const res = await APP.cmd(S.token, op, {})
    const result = res.json && res.json.result
    const isDenied = res.status === 200 && res.json && res.json.ok === true && denied(op, result)
    if (!isDenied) accepted += 1
    opRows[op] = { status: res.status, result: result }
  }

  // fsList 越界
  const fsList = await APP.cmd(S.token, 'fsList', { path: H.outsideDir })
  const fsListResult = fsList.json && fsList.json.result
  const fsListDenied = !!(fsListResult && fsListResult.ok === false && String(fsListResult.error || '').indexOf('path not allowed') >= 0)
  opRows['fsList(outside)'] = { status: fsList.status, result: fsListResult }

  // readFile 越界
  const readFile = await APP.cmd(S.token, 'readFile', { path: H.outsideFile })
  const readResult = readFile.json && readFile.json.result
  const readDenied = !!(readResult && readResult.ok === false && String(readResult.error || '').indexOf('path not allowed') >= 0)
  opRows['readFile(outside)'] = { status: readFile.status, result: readResult }

  // fsDrives 只回白名单根
  const drives = await APP.cmd(S.token, 'fsDrives', {})
  const drivesResult = drives.json && drives.json.result
  const driveList = (drivesResult && Array.isArray(drivesResult.drives)) ? drivesResult.drives : null
  const bareDrives = driveList ? driveList.filter((d) => /^[A-Za-z]:$/.test(String(d))) : []
  const allWithin = driveList ? driveList.every((d) => {
    const s = String(d)
    return s === H.inbox || s.startsWith(H.inbox + path.sep) || s.startsWith(H.inbox + '/')
  }) : false
  opRows['fsDrives'] = { status: drives.status, result: drivesResult }

  const blocked = accepted === 0 && fsListDenied && readDenied && bareDrives.length === 0 && allWithin
  const vuln = accepted > 0 || !fsListDenied || !readDenied || bareDrives.length > 0
  return {
    vuln,
    blocked,
    evidence: {
      acceptedCount: accepted,
      fsListDenied,
      readDenied,
      drives: driveList,
      bareDrives,
      sample: { pluginBundleInstall: opRows.pluginBundleInstall, updateStart: opRows.updateStart, fsList: opRows['fsList(outside)'], readFile: opRows['readFile(outside)'] }
    }
  }
})

test('B9', 'B', '吊销是硬边界：被吊销设备重新 /claim 不自动解黑（上游会 unrevoke）', async () => {
  requireLan()
  const store = H.mp && H.mp.store
  assert(store && typeof store.mint === 'function', 'harness 拿不到 mp.store（装置问题）')
  const uid = 'uid-revoke-1'
  const minted = store.mint({ name: 'probe-device', uid })
  assert(minted && minted.deviceId, 'store.mint 失败（装置问题）')
  store.revokeDevice(minted.deviceId)
  const revokedBefore = store.isRevoked({ uid })
  assertEq(revokedBefore, true, 'revokeDevice 后应处于吊销状态（装置问题）')

  const issued = await issuePairing()
  const code = issued.code
  const claim = await APP.request({
    source: 'loop',
    method: 'POST',
    path: '/claim',
    query: { deviceUid: uid, deviceName: 'probe-device' },
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ code })
  })
  assertEq(claim.status, 200, '吊销后重新 claim 的 HTTP 状态')
  const revokedAfter = store.isRevoked({ uid })
  return {
    vuln: revokedBefore === true && revokedAfter === false,
    blocked: revokedBefore === true && revokedAfter === true,
    evidence: { claimStatus: claim.status, revokedBefore, revokedAfter, deviceId: minted.deviceId }
  }
})

test('B10', 'B', '/mp RPC host.listDirectory 越界：白名单外目录 → forbidden（上游可浏览任意目录），白名单内 200', async () => {
  const inside = await APP.mpRpc(S.cookie, 'host.listDirectory', { path: H.inbox })
  const ir = rpcOf(inside)
  assertEq(inside.status, 200, 'host.listDirectory(inside) status')
  assertEq(ir.ok, true, 'host.listDirectory 白名单内必须 ok')
  const outside = await APP.mpRpc(S.cookie, 'host.listDirectory', { path: H.outsideDir })
  const or = rpcOf(outside)
  const denied = or.ok === false && !!(or.error && String(or.error.code || '') === 'forbidden' && String(or.error.message || '').indexOf('path not allowed') >= 0)
  return {
    vuln: or.ok === true,
    blocked: denied,
    evidence: {
      inside: { status: inside.status, ok: ir.ok },
      outside: { status: outside.status, ok: or.ok, error: or.error }
    }
  }
})

test('B11', 'B', '/cmd 请求体上限（SEC-22）：加固版拒绝超大 body（保护宿主内存），上游照单全收', async () => {
  // 加固版：LAN /cmd readBody 上限 12MB（上游为 Infinity）；超限时服务端 destroy 请求。
  const blob = 'x'.repeat(13 * 1024 * 1024)
  let status = 0
  let clientError = ''
  try {
    const res = await APP.cmd(S.token, 'sessions', { blob })
    status = res.status
  } catch (e) {
    clientError = String((e && e.message) || e)
  }
  const accepted = status === 200
  return {
    vuln: accepted,
    blocked: !accepted,
    evidence: { status, clientError: clientError || undefined, bodyMB: Math.round(blob.length / 1048576) }
  }
})

// ── C. 运行期零外联 ─────────────────────────────────────────────────────────
test('C1', 'C', '运行期无外部网络/外联：无 gaoshou25.cn / registry.npmjs.org / huawei；无 frpc/ffmpeg/curl spawn', async () => {
  const report = netReport()
  const badHosts = ['gaoshou25.cn', 'registry.npmjs.org', 'push-api.cloud.huawei.com', 'npmjs.org', 'huawei.com']
  const hitBad = report.external.filter((row) => badHosts.some((b) => String(row.host || '').indexOf(b) >= 0))
  const badSpawn = report.spawnCalls.filter((row) => /frpc|ffmpeg|curl|winget|tar\.exe/i.test(String(row.host || '')))
  assertEq(hitBad.length, 0, '出现外联目标: ' + JSON.stringify(hitBad))
  assertEq(report.external.length, 0, '出现未识别的外部目标: ' + JSON.stringify(report.external))
  assertEq(badSpawn.length, 0, '出现高危子进程: ' + JSON.stringify(badSpawn))
  return {
    evidence: {
      observedHosts: report.observedHosts,
      httpCalls: report.httpCalls,
      httpsCalls: report.httpsCalls,
      fetchCalls: report.fetchCalls,
      spawnCalls: report.spawnCalls,
      external: report.external
    }
  }
})

// ── 执行器 ─────────────────────────────────────────────────────────────────
function loadBaseline() {
  try {
    const raw = fs.readFileSync(BASELINE_FILE, 'utf8')
    const j = JSON.parse(raw)
    const map = {}
    for (const c of j.cases || []) map[c.id] = c
    return map
  } catch (e) {
    return null
  }
}

function writeJson(file, obj) {
  try {
    fs.writeFileSync(file, JSON.stringify(obj, null, 2))
  } catch (e) {
    console.error('写结果文件失败:', e && e.message)
  }
}

async function main() {
  const startedAt = new Date()
  const t0 = Date.now()
  let fatal = null
  try {
    H = await createHarness({ libDir: GUARD_LIB })
    APP = createApp({ port: H.port, token: TOKEN, lanIp: H.lanIp })
  } catch (e) {
    fatal = String((e && e.stack) || e)
  }

  const rows = []
  if (!fatal) {
    console.log('')
    console.log('════════ dsh-console-guard 协议兼容 + 安全回归 ════════')
    console.log('被测 lib : ' + GUARD_LIB)
    console.log('模式     : ' + H.mode + (H.mode === 'upstream' ? '（上游基线对照）' : '（加固版验收）'))
    console.log('监听     : 127.0.0.1:' + H.port + '  LAN=' + (H.lanIp || '(无 LAN IP)') + '  token=' + TOKEN.slice(0, 8) + '…')
    console.log('')

    for (const c of CASES) {
      const caseStarted = Date.now()
      let outcome = null
      let error = ''
      try {
        outcome = await c.fn()
      } catch (e) {
        if (e && e.skip) {
          outcome = { skip: true, reason: String(e.message || 'SKIP') }
        } else {
          error = String((e && e.message) || e)
        }
      }
      let status = 'PASS'
      let evidence = outcome && outcome.evidence ? outcome.evidence : null
      if (outcome && outcome.skip) {
        status = 'SKIP'
      } else if (error) {
        status = 'FAIL'
      } else if (c.group === 'B') {
        const blocked = !!(outcome && outcome.blocked)
        const vuln = !!(outcome && outcome.vuln)
        if (H.mode === 'guard') {
          status = blocked ? 'PASS' : 'FAIL'
          if (!blocked && !error) error = '加固版未拦住该攻击（vuln=' + String(vuln) + '）'
        } else {
          // 上游基线：漏洞被复现 → 预期失败 XFAIL；没复现 → 对照无效 FAIL
          status = vuln ? 'XFAIL' : 'FAIL'
          if (!vuln && !error) error = '上游基线未复现该已知漏洞，对照无效（装置/用例需检查）'
        }
      } else if (c.group === 'A') {
        status = 'PASS'
      }
      const row = {
        id: c.id,
        group: c.group,
        title: c.title,
        status,
        ms: Date.now() - caseStarted,
        evidence,
        error: error || undefined
      }
      if (c.group === 'A' && outcome && outcome.parityStatus !== undefined) row.parityStatus = outcome.parityStatus
      rows.push(row)
      const tag = status.padEnd(5)
      let line = '[' + c.id + '] ' + tag + ' ' + c.title
      if (status === 'SKIP') line += ' —— ' + (outcome.reason || '')
      if (error) line += ' —— ' + error
      console.log(line)
      if (evidence) console.log('        证据: ' + fmtEvidence(evidence))
      if (outcome && outcome.skip) console.log('        SKIP: ' + outcome.reason)
    }

    // A 组与上游基线做链路级 parity 对照（仅当基线文件存在）
    let parity = { baselineFile: fs.existsSync(BASELINE_FILE) ? BASELINE_FILE : null, compared: 0, mismatches: [] }
    if (H.mode === 'guard' && parity.baselineFile) {
      const baseline = loadBaseline()
      if (baseline) {
        for (const row of rows) {
          if (row.group !== 'A' || row.status !== 'PASS') continue
          const base = baseline[row.id]
          if (!base || base.status !== 'PASS' || base.parityStatus === undefined) continue
          if (row.parityStatus === undefined) continue
          parity.compared += 1
          if (row.parityStatus !== base.parityStatus) {
            parity.mismatches.push({ id: row.id, guard: row.parityStatus, upstream: base.parityStatus })
            row.status = 'FAIL'
            row.error = 'A 组与上游基线状态不一致（guard=' + row.parityStatus + ' upstream=' + base.parityStatus + '）'
          }
        }
        if (parity.mismatches.length > 0) {
          rows.push({
            id: 'A-parity', group: 'A', title: 'A 组响应状态与上游基线一致',
            status: 'FAIL', ms: 0, evidence: parity.mismatches, error: '存在 parity 不一致'
          })
        } else {
          rows.push({
            id: 'A-parity', group: 'A', title: 'A 组响应状态与上游基线一致',
            status: 'PASS', ms: 0, evidence: { compared: parity.compared }
          })
        }
      }
    }
    console.log('')
    if (H.mode === 'upstream') {
      console.log('Parity 对照: 上游模式（已写 ' + path.basename(BASELINE_FILE) + '；A 组即 shape 基准，B 组 XFAIL 为已知漏洞复现）')
    } else if (parity.baselineFile) {
      console.log('Parity 对照: ' + (parity.mismatches.length === 0 ? 'PASS' : 'FAIL') + '（与 ' + path.basename(parity.baselineFile) + ' 比较 ' + parity.compared + ' 项）')
    } else {
      console.log('Parity 对照: 跳过（还没有 baseline-upstream.json，先跑一次上游基线）')
    }
  } else {
    console.log('装置启动失败:' + fatal)
    rows.push({ id: 'H1', group: 'H', title: '装置启动', status: 'FAIL', ms: 0, error: fatal })
  }

  if (H) {
    try { await H.stop() } catch (e) { /* ignore */ }
    try { H.cleanup() } catch (e) { /* ignore */ }
  }

  const summary = { total: rows.length, pass: 0, fail: 0, xfail: 0, skip: 0 }
  for (const row of rows) {
    if (row.status === 'PASS') summary.pass += 1
    else if (row.status === 'XFAIL') summary.xfail += 1
    else if (row.status === 'SKIP') summary.skip += 1
    else summary.fail += 1
  }
  const result = {
    tool: 'dsh-console-guard/test/guard/run.mjs',
    mode: H ? H.mode : 'unknown',
    libDir: GUARD_LIB,
    token: TOKEN,
    port: H ? H.port : null,
    lanIp: H ? H.lanIp : null,
    startedAt: startedAt.toISOString(),
    finishedAt: new Date().toISOString(),
    durationMs: Date.now() - t0,
    summary,
    cases: rows,
    parity: (rows.find((r) => r.id === 'A-parity') || null) ? {
      baselineFile: fs.existsSync(BASELINE_FILE) ? BASELINE_FILE : null,
      compared: (rows.find((r) => r.id === 'A-parity').evidence || {}).compared || 0,
      result: rows.find((r) => r.id === 'A-parity').status
    } : null,
    net: H ? netReport() : null,
    note: H && H.mode === 'upstream'
      ? '上游基线对照：B 组 XFAIL = 已知漏洞被成功复现（装置有效）；A 组 PASS = 协议形状与上游一致。'
      : '加固版验收：B 组 PASS = 攻击被拒；A 组 PASS = 与上游协议兼容。'
  }
  writeJson(LAST_FILE, result)
  if (H && H.mode === 'upstream') {
    writeJson(BASELINE_FILE, Object.assign({}, result, {
      note: '上游 dsh-console-plugin@0.5.64 基线（仅供加固版 parity 对照；XFAIL=已知漏洞被复现）'
    }))
  }

  console.log('')
  console.log('════════ 汇总 [' + result.mode + '] ════════')
  console.log('  PASS=' + summary.pass + '  FAIL=' + summary.fail + '  XFAIL=' + summary.xfail + '  SKIP=' + summary.skip + '  (共 ' + summary.total + ' 项, ' + result.durationMs + 'ms)')
  console.log('  结果文件: ' + LAST_FILE)
  if (H && H.mode === 'upstream') console.log('  基线文件: ' + BASELINE_FILE)
  if (summary.fail > 0) {
    console.log('')
    console.log('失败项:')
    for (const row of rows) {
      if (row.status === 'FAIL') console.log('  - [' + row.id + '] ' + row.title + ' :: ' + (row.error || 'FAIL'))
    }
  }
  console.log('')
  process.exit(summary.fail === 0 ? 0 : 1)
}

main().catch((e) => {
  console.error('运行器异常:', (e && e.stack) || e)
  try {
    if (H) { H.stop(); H.cleanup() }
  } catch (e2) { /* ignore */ }
  process.exit(2)
})
