// dsh-console-guard 测试装置 · 被测服务组装
//
// 作用：不启动真实 DSH、不装真实 profile、不联网；用 stub 宿主 + 真实被测
// `startLanServer()` / `attachMp()`（照抄 lib/index.js 的 wiring）在 19600-19700
// 的临时端口上起一个被测局域网服务，供 run.mjs 以「官方 App 行为」调用。
//
// 两个被测目标：
//   GUARD_LIB=<dir>  默认 <repo>/lib（加固版）；指向 <ws>/dsh-console-plugin/lib 时是上游基线对照。
//
// 关键点：
//  - 在动态 import 被测模块 *之前* 把 USERPROFILE/HOME 指到临时目录，并设置
//    DSH_CONSOLE_DEVICES_FILE / DSH_CONSOLE_REVOKED_FILE / DSH_CONSOLE_INBOX，
//    保证不写用户真实 ~/.dsh。
//  - 装一个离线 qrcode shim（copy 自 analysis/security/sandbox 的离线 stub），
//    并用 module.registerHooks 兜底解析，使上游基线的 /qr 也能 200。
//  - 装运行期外联记录器（fetch / http(s).request / child_process），供 §五 C 断言。
//  - stub ctx.runCommand 按 lib/index.js 的 guard 分支镜像 host 侧策略
//    （guard-policy.mjs 存在时用它的 deny/stub/文件根目录逻辑，不存在时=上游行为）。

import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import http from 'node:http'
import https from 'node:https'
import { createRequire, registerHooks } from 'node:module'
import { fileURLToPath, pathToFileURL } from 'node:url'

// ── 路径 ────────────────────────────────────────────────────────────────────
const HARNESS_DIR = path.dirname(fileURLToPath(import.meta.url))
export const REPO_ROOT = path.resolve(HARNESS_DIR, '..', '..', '..') // dsh-console-guard/
export const WORKSPACE_ROOT = path.resolve(REPO_ROOT, '..')
export const DEFAULT_GUARD_LIB = path.join(REPO_ROOT, 'lib')
export const UPSTREAM_LIB = path.join(WORKSPACE_ROOT, 'dsh-console-plugin', 'lib')
const QR_SHIM_SRC = path.join(WORKSPACE_ROOT, 'analysis', 'security', 'sandbox', 'node_modules', 'qrcode')
const QR_SHIM_DST = path.join(REPO_ROOT, 'node_modules', 'qrcode')

// 固定 64 hex token（不随机，便于用例断言；与真实服务无关）
export const TOKEN = 'a1b2c3d4e5f60718'.repeat(4) // 64 chars

// ── 离线 qrcode shim ───────────────────────────────────────────────────────
let qrHookDone = false

function ensureQrShim() {
  try {
    if (fs.existsSync(path.join(QR_SHIM_DST, 'index.js'))) return true
    if (!fs.existsSync(path.join(QR_SHIM_SRC, 'index.js'))) return false
    fs.mkdirSync(path.dirname(QR_SHIM_DST), { recursive: true })
    fs.cpSync(QR_SHIM_SRC, QR_SHIM_DST, { recursive: true })
    return fs.existsSync(path.join(QR_SHIM_DST, 'index.js'))
  } catch (e) {
    return false
  }
}

function installQrHook() {
  if (qrHookDone) return
  qrHookDone = true
  const shim = path.join(QR_SHIM_DST, 'index.js')
  if (!fs.existsSync(shim)) return
  registerHooks({
    resolve(specifier, context, nextResolve) {
      if (specifier === 'qrcode') return { url: pathToFileURL(shim).href, shortCircuit: true }
      return nextResolve(specifier, context)
    }
  })
}

// ── 运行期外联记录器（§五 C）────────────────────────────────────────────────
const netRec = {
  http: [],
  https: [],
  fetch: [],
  spawn: [],
  external: [],
  patched: false
}

function lanIps() {
  const out = []
  try {
    const ifs = os.networkInterfaces()
    for (const name of Object.keys(ifs)) {
      for (const ni of ifs[name] || []) {
        if ((ni.family === 'IPv4' || ni.family === 4) && !ni.internal) out.push(ni.address)
      }
    }
  } catch (e) { /* ignore */ }
  return out
}

function isLocalHost(raw) {
  let h = String(raw == null ? '' : raw).trim().toLowerCase()
  if (h === '') return true // 无 host 视为本机/未知，不算外联
  if (h.charAt(0) === '[') {
    const end = h.indexOf(']')
    if (end > 0) h = h.slice(1, end)
  } else {
    const colon = h.lastIndexOf(':')
    if (colon > 0 && h.indexOf(':') === colon) h = h.slice(0, colon)
  }
  if (h === 'localhost' || h === '127.0.0.1' || h === '::1' || h === '0.0.0.0') return true
  if (/^127\./.test(h)) return true
  for (const ip of lanIps()) if (h === ip.toLowerCase()) return true
  return false
}

function noteNet(kind, host) {
  const row = { kind, host: String(host || ''), at: Date.now() }
  if (kind.indexOf('fetch') === 0) netRec.fetch.push(row)
  else if (kind.indexOf('https') === 0) netRec.https.push(row)
  else if (kind.indexOf('spawn') === 0) netRec.spawn.push(row)
  else netRec.http.push(row)
  if (!isLocalHost(row.host)) netRec.external.push(row)
}

function hostOfRequestArgs(kind, args) {
  try {
    const a0 = args[0]
    if (typeof a0 === 'string') return new URL(a0).hostname
    if (a0 && typeof a0 === 'object') {
      if (a0.host) return String(a0.host)
      if (a0.hostname) return String(a0.hostname)
      return 'localhost'
    }
  } catch (e) { /* ignore */ }
  return ''
}

function patchHttp(mod, kind) {
  for (const name of ['request', 'get']) {
    const orig = mod[name]
    if (typeof orig !== 'function') continue
    mod[name] = function patchedHttp(...args) {
      const host = hostOfRequestArgs(kind, args)
      noteNet(kind + '.' + name, host)
      if (!isLocalHost(host)) {
        throw new Error('harness-net-block: ' + kind + '.' + name + ' -> ' + host)
      }
      return orig.apply(this, args)
    }
  }
}

function patchChildProcess() {
  try {
    const require = createRequire(import.meta.url)
    const cp = require('node:child_process')
    for (const name of ['spawn', 'exec', 'execFile', 'execFileSync', 'spawnSync', 'execSync']) {
      const orig = cp[name]
      if (typeof orig !== 'function') continue
      cp[name] = function patchedCp(...args) {
        const cmd = String(args[0] == null ? '' : args[0])
        noteNet('spawn.' + name, cmd)
        return orig.apply(this, args)
      }
    }
  } catch (e) { /* ignore */ }
}

function patchGlobalFetch() {
  const orig = globalThis.fetch
  if (typeof orig !== 'function') return
  globalThis.fetch = function patchedFetch(input, init) {
    let host = ''
    try {
      const raw = typeof input === 'string' ? input : (input && input.url) || String(input)
      host = new URL(raw).hostname
    } catch (e) { host = '' }
    noteNet('fetch', host)
    if (!isLocalHost(host)) {
      return Promise.reject(new Error('harness-net-block: fetch -> ' + host))
    }
    return orig.call(this, input, init)
  }
}

function installNetRecorder() {
  if (netRec.patched) return
  netRec.patched = true
  patchHttp(http, 'http')
  patchHttp(https, 'https')
  patchGlobalFetch()
  patchChildProcess()
}

export function netReport() {
  const hosts = {}
  for (const bucket of [netRec.http, netRec.https, netRec.fetch]) {
    for (const row of bucket) {
      const k = row.host || '(空)'
      hosts[k] = (hosts[k] || 0) + 1
    }
  }
  return {
    observedHosts: hosts,
    httpCalls: netRec.http.length,
    httpsCalls: netRec.https.length,
    fetchCalls: netRec.fetch.length,
    spawnCalls: netRec.spawn.slice(),
    external: netRec.external.slice()
  }
}

// ── 网络工具 ────────────────────────────────────────────────────────────────
export async function pickLanIp() {
  const list = lanIps()
  return list.length ? list[0] : ''
}

async function findFreePort(start = 19600, end = 19700) {
  for (let port = start; port <= end; port += 1) {
    const ok = await new Promise((resolve) => {
      const srv = http.createServer()
      srv.once('error', () => resolve(false))
      srv.listen(port, '0.0.0.0', () => srv.close(() => resolve(true)))
    })
    if (ok) return port
  }
  throw new Error('找不到 19600-19700 的空闲端口')
}

// ── 测试数据 ────────────────────────────────────────────────────────────────
const PNG_PIXEL = Buffer.from(
  'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII=',
  'base64'
)

function seedInbox(inbox) {
  fs.mkdirSync(inbox, { recursive: true })
  fs.writeFileSync(path.join(inbox, 'seed-inbox.txt'), 'seed-inbox-content')
}

function uniquePathIn(dir, name) {
  const safe = String(name || 'file.bin').replace(/[\\/:*?"<>|]/g, '_').slice(0, 120) || 'file.bin'
  let out = path.join(dir, safe)
  const dot = safe.lastIndexOf('.')
  const stem = dot > 0 ? safe.slice(0, dot) : safe
  const ext = dot > 0 ? safe.slice(dot) : ''
  for (let i = 2; fs.existsSync(out); i += 1) out = path.join(dir, stem + '-' + i + ext)
  return out
}

function readVersionOf(libDir) {
  try {
    const pkg = JSON.parse(fs.readFileSync(path.join(libDir, '..', 'package.json'), 'utf8'))
    return String(pkg.version || '')
  } catch (e) {
    return ''
  }
}

// ── stub ctx（宿主服务桩）───────────────────────────────────────────────────
function createStubCtx({ log }) {
  const handlers = new Map()
  const session = { id: 'sess-1' }

  const sessionList = [
    {
      sessionId: 'sess-1', title: '测试会话-1', cwd: 'C:\\harness\\ws',
      updatedAt: 1700000001000, running: false,
      modelSelection: { lastUsed: 'deepseek-chat' }
    },
    {
      sessionId: 'sess-2', title: '测试会话-2', cwd: 'C:\\harness\\ws',
      updatedAt: 1700000000000, running: true,
      modelSelection: { next: 'deepseek-reasoner' }
    }
  ]

  const ctl = {
    list: async () => ({ items: sessionList }),
    history: async (req) => ({
      sessionId: String((req && req.sessionId) || 'sess-1'),
      maxSeq: 2,
      events: [
        { type: 'user/message', seq: 1, data: { content: [{ type: 'text', text: '你好' }] } },
        { type: 'assistant/chunk', seq: 2, data: { chunk: { type: 'text-delta', text: '收到' } } }
      ]
    }),
    prompt: async (req) => ({
      accepted: true,
      requestId: String((req && req.requestId) || ''),
      sessionId: String((req && req.sessionId) || '')
    }),
    cancel: async (req) => ({ ok: true, sessionId: String((req && req.sessionId) || '') }),
    attachment: async () => ({
      attachmentId: 'att-1',
      mime: 'image/png',
      name: 'pixel.png',
      bytes: PNG_PIXEL.length,
      dataUrl: 'data:image/png;base64,' + PNG_PIXEL.toString('base64')
    }),
    modelCatalog: async () => ({
      current: 'deepseek-chat',
      models: [
        { id: 'deepseek-chat', name: 'DeepSeek Chat', provider: 'deepseek' },
        { id: 'deepseek-reasoner', name: 'DeepSeek Reasoner', provider: 'deepseek' }
      ]
    }),
    selectModel: async (req) => ({
      ok: true,
      selected: {
        provider: 'deepseek',
        model: String((req && req.model) || 'deepseek-chat'),
        reasoningEffort: ''
      }
    }),
    commands: async () => ({ items: [{ name: 'clear', description: '清空会话' }] }),
    create: async (req) => ({
      sessionId: 'sess-new-1',
      title: '新会话',
      cwd: 'C:\\harness\\ws',
      updatedAt: Date.now(),
      running: false,
      modelSelection: { lastUsed: 'deepseek-chat' },
      requestId: String((req && req.requestId) || '')
    })
  }

  const services = {
    sessionController: ctl,
    host: {
      listDirectory: async ({ path: p }) => ({
        path: String(p || ''),
        entries: [
          { name: 'a.txt', type: 'file', size: 11 },
          { name: 'sub', type: 'dir', size: 0 }
        ]
      })
    },
    quota: { read: async () => ({ usedBytes: 0, quotaBytes: 0, unlimited: true }) }
  }

  const ctx = {
    get(name) { return services[String(name)] || null },
    on(event, fn) {
      const key = String(event || '')
      if (!handlers.has(key)) handlers.set(key, new Set())
      handlers.get(key).add(fn)
      return () => {
        const set = handlers.get(key)
        if (set) set.delete(fn)
      }
    },
    emit(event, ...args) {
      const set = handlers.get(String(event || ''))
      if (!set) return 0
      let n = 0
      for (const fn of [...set]) {
        n += 1
        try { fn(...args) } catch (e) {
          log('[harness] ctx.' + String(event) + ' 处理器异常: ' + ((e && e.message) || e))
        }
      }
      return n
    },
    handlerCount(event) {
      const set = handlers.get(String(event || ''))
      return set ? set.size : 0
    }
  }

  return { ctx, ctl, session, sessionList }
}

// ── stub runCommand（镜像 lib/index.js 的 guard 分支）─────────────────────
// 说明：真实宿主 runCommand 在 lib/index.js 里，依赖整个 DSH 宿主，无法在本装置加载；
// 这里镜像其「guard 分支 + 允许 op 的最小行为」，用于验证 /cmd 通道与 guard-policy
// 的策略边界。上游基线（无 guard-policy.mjs）走纯 stub = 无任何 op 策略。
function createRunCommand({ guardPolicy, roots, inbox, sessions, outsideDir, log }) {
  function guardStubFor(op) {
    switch (String(op || '')) {
      case 'updateCheck': return { ok: false, disabled: true }
      case 'updateState': return { disabled: true, version: 'guard-harness' }
      case 'remotePairGet': return { enabled: false, available: false }
      case 'customServerGet': return { enabled: false }
      case 'pushStatus': return { ready: false, disabled: true }
      case 'pushTokenList': return { items: [], tokens: [] }
      default: return { ok: false, disabled: true, error: 'guard-disabled: ' + String(op || '') }
    }
  }

  return async function runCommand(op, payload) {
    const p = payload && typeof payload === 'object' ? payload : {}

    if (guardPolicy) {
      if (guardPolicy.cmdOpDenied(op)) {
        if (guardPolicy.cmdOpReadonlyStub(op)) return guardStubFor(op)
        return { ok: false, error: 'guard-disabled: ' + String(op) }
      }
      if (guardPolicy.isFsCmd(op)) {
        const target = guardPolicy.fsCmdPathOf(op, p)
        if (target !== '' && !guardPolicy.pathWithinRoots(target, roots)) {
          return { ok: false, error: 'guard: path not allowed' }
        }
      }
    }

    switch (String(op)) {
      case 'sessions':
        return sessions.slice()
      case 'fsDrives': {
        if (guardPolicy) {
          const drives = roots.map((root) => {
            const m = /^([A-Za-z]):[\\/]?$/.exec(root)
            return m ? m[1].toUpperCase() + ':' : root
          })
          return { ok: true, drives, home: roots[0] || '' }
        }
        const drives = []
        for (let i = 67; i <= 90; i += 1) {
          const d = String.fromCharCode(i) + ':\\'
          try { fs.accessSync(d, fs.constants.R_OK); drives.push(d.slice(0, 2)) } catch (e) { /* ignore */ }
        }
        return { ok: true, drives, home: os.homedir() }
      }
      case 'fsList': {
        const dir = String(p.path || '').trim()
        if (!dir) throw new Error('缺少 path')
        const st = fs.statSync(dir)
        if (!st.isDirectory()) throw new Error('不是文件夹：' + dir)
        const names = fs.readdirSync(dir).sort((a, b) => String(a).localeCompare(String(b)))
        const dirs = []
        for (const n of names) {
          if (String(n).charAt(0) === '.') continue
          let isDir = false
          try { isDir = fs.statSync(path.join(dir, String(n))).isDirectory() } catch (e) { continue }
          if (isDir) dirs.push({ name: String(n), path: path.join(dir, String(n)) })
        }
        return { ok: true, path: dir, dirs, sep: path.sep, entries: names }
      }
      case 'readFile': {
        const fp = String(p.path || '').trim()
        if (!fp) throw new Error('缺少 path')
        if (!path.isAbsolute(fp)) throw new Error('必须是绝对路径：' + fp)
        const st = fs.statSync(fp)
        if (!st.isFile()) throw new Error('不是文件：' + fp)
        const name = path.basename(fp)
        return {
          ok: true,
          path: path.resolve(fp),
          name,
          mime: 'application/octet-stream',
          bytes: st.size,
          b64: fs.readFileSync(fp).toString('base64')
        }
      }
      default:
        return { op: String(op), stub: true, accepted: true }
    }
  }
}

// ── 组装被测服务 ────────────────────────────────────────────────────────────
/**
 * @param {{ libDir?: string, port?: number, verbose?: boolean }} opts
 */
export async function createHarness(opts = {}) {
  const libDir = path.resolve(opts.libDir || DEFAULT_GUARD_LIB)
  if (!fs.existsSync(path.join(libDir, 'lan-server.mjs'))) {
    throw new Error('被测 lib 不存在: ' + libDir)
  }
  if (!fs.existsSync(path.join(libDir, 'mp-support.mjs'))) {
    throw new Error('被测 lib 缺少 mp-support.mjs: ' + libDir)
  }
  ensureQrShim()
  installQrHook()
  installNetRecorder()

  const logs = []
  const log = (m) => {
    const line = String(m == null ? '' : m)
    logs.push(line)
    if (logs.length > 400) logs.splice(0, logs.length - 400)
    if (opts.verbose) console.log('[lib] ' + line)
  }

  // 临时目录：home / inbox / outside / devices / revoked
  const rootTmp = fs.mkdtempSync(path.join(os.tmpdir(), 'dsh-guard-harness-'))
  const home = path.join(rootTmp, 'home')
  const inbox = path.join(rootTmp, 'inbox')
  const outsideDir = path.join(rootTmp, 'outside')
  fs.mkdirSync(home, { recursive: true })
  fs.mkdirSync(outsideDir, { recursive: true })
  seedInbox(inbox)
  const outsideFile = path.join(outsideDir, 'outside-secret.txt')
  fs.writeFileSync(outsideFile, 'OUTSIDE-SECRET-CONTENT')
  const devicesFile = path.join(rootTmp, 'devices.json')
  const revokedFile = path.join(rootTmp, 'revoked.json')

  // 进程环境必须在 import 被测模块之前设置：不写用户真实 ~/.dsh
  process.env.USERPROFILE = home
  process.env.HOME = home
  process.env.DSH_CONSOLE_INBOX = inbox
  process.env.DSH_CONSOLE_DEVICES_FILE = devicesFile
  process.env.DSH_CONSOLE_REVOKED_FILE = revokedFile
  process.env.DSH_CLOUD_GATE = 'off'
  process.env.DSH_DEVICE_GATE = 'off'
  // 空 PATH：任何误触发的 ffmpeg/frpc/curl 下载/执行都会 ENOENT
  const emptyBin = path.join(rootTmp, 'empty-bin')
  fs.mkdirSync(emptyBin, { recursive: true })
  process.env.PATH = emptyBin

  const lanServerMod = await import(pathToFileURL(path.join(libDir, 'lan-server.mjs')).href)
  const mpSupportMod = await import(pathToFileURL(path.join(libDir, 'mp-support.mjs')).href)
  let guardPolicy = null
  try {
    guardPolicy = await import(pathToFileURL(path.join(libDir, 'guard-policy.mjs')).href)
  } catch (e) {
    guardPolicy = null
  }

  const mode = guardPolicy ? 'guard' : 'upstream'
  const version = readVersionOf(libDir)
  const { ctx, ctl, session, sessionList } = createStubCtx({ log })

  const guard = { enabled: true, fileRoots: [inbox] }
  const roots = [inbox]

  const runCommand = createRunCommand({
    guardPolicy,
    roots,
    inbox,
    sessions: sessionList,
    outsideDir,
    log
  })

  const attachmentOf = async (id) => {
    if (String(id) !== 'att-1') return null
    return { mime: 'image/png', name: 'pixel.png', data: PNG_PIXEL, bytes: PNG_PIXEL.length }
  }

  const uploadSink = async (info) => {
    const i = info || {}
    fs.mkdirSync(inbox, { recursive: true })
    const out = uniquePathIn(inbox, i.name || 'upload.bin')
    const tmp = String(i.tmpPath || '')
    if (tmp && tmp !== out) {
      try { fs.renameSync(tmp, out) } catch (e) {
        fs.copyFileSync(tmp, out)
        try { fs.unlinkSync(tmp) } catch (e2) { /* ignore */ }
      }
    }
    let bytes = Number(i.bytes) || 0
    if (!bytes) { try { bytes = fs.statSync(out).size } catch (e) { bytes = 0 } }
    return { path: out, name: path.basename(out), bytes, notified: false }
  }

  const getInfo = () => ({
    name: 'guard-harness-host',
    nodeId: 'dsh-console',
    host: 'harness-host',
    dshOk: true,
    dshError: '',
    version: version || (mode === 'guard' ? '0.5.65-guard.1' : '0.5.64'),
    latestVersion: '',
    agentPreset: '',
    agentPresetAvailable: false
  })

  const listSessions = async () => sessionList.slice()
  const listWorkspaces = async () => ([
    { workspaceId: 'ws-1', path: 'C:\\harness\\ws', title: '测试工作区', sessionIds: ['sess-1', 'sess-2'] }
  ])

  // 照抄 lib/index.js 的 wiring 顺序：startLanServer → attachMp → lan.setMp → lan.start()
  // 注意：start() 创建 http server 时会把 o.mp.onUpgrade 捕获进 upgrade 监听器，
  // 所以 setMp 必须发生在 start() 之前（否则 WS 升级会被直接 destroy）。
  let lan = null
  let mp = null
  let started = null
  let port = 0
  let lastErr = null
  for (let attempt = 0; attempt < 5 && !started; attempt += 1) {
    port = opts.port && attempt === 0 ? Number(opts.port) : await findFreePort(19600 + attempt, 19700)
    lan = lanServerMod.startLanServer({
      port,
      allowShift: false,
      getToken: () => TOKEN,
      getInfo,
      listSessions,
      listWorkspaces,
      runCommand,
      attachmentOf,
      uploadSink,
      getMaster: () => true,
      getAccess: () => ({ lan: true, remote: true }),
      getRemotePair: () => false,
      getUpdateState: () => null,
      dshLaunchToken: () => '',
      webGuiPort: () => 0,
      cloud: null,
      wanMeter: null,
      getWanLimits: () => null,
      guard, // 加固版读取；上游忽略
      log
    })
    mp = mpSupportMod.attachMp(ctx, {
      log,
      config: {},
      isPairCode: (code) => code === lan.peekPairCode(),
      onStream: () => {},
      guard, // 加固版读取；上游忽略
      fileRoots: roots
    })
    lan.setMp({
      branch: mp.branch,
      onUpgrade: typeof mp.onUpgrade === 'function' ? mp.onUpgrade : null,
      issueForCode: (code, about) => (typeof mp.issueForCode === 'function' ? mp.issueForCode(code, about) : ''),
      issueDevice: (about) => (typeof mp.issueDevice === 'function' ? mp.issueDevice(about) : ''),
      store: mp.store
    })
    started = await lan.start()
    if (!started) {
      lastErr = 'startLanServer 启动失败（端口 ' + port + ' 可能被占用）'
      try { if (typeof mp.dispose === 'function') mp.dispose() } catch (e) { /* ignore */ }
      try { lan.stop() } catch (e) { /* ignore */ }
      lan = null
      mp = null
      await new Promise((r) => setTimeout(r, 60))
    }
  }
  if (!started) {
    throw new Error(lastErr || 'startLanServer 启动失败')
  }
  port = Number(started.port) || port

  const lanIp = await pickLanIp()

  const harness = {
    mode,
    libDir,
    version,
    rootTmp,
    home,
    inbox,
    outsideDir,
    outsideFile,
    devicesFile,
    revokedFile,
    token: TOKEN,
    port,
    lanIp,
    lan,
    mp,
    ctx,
    ctl,
    session,
    sessionList,
    guardPolicy,
    logs,
    log,
    emit: (event, ...args) => ctx.emit(event, ...args),
    async stop() {
      try { if (mp && typeof mp.dispose === 'function') mp.dispose() } catch (e) { /* ignore */ }
      try { lan.stop() } catch (e) { /* ignore */ }
      await new Promise((r) => setTimeout(r, 60))
    },
    cleanup() {
      try { fs.rmSync(rootTmp, { recursive: true, force: true }) } catch (e) { /* ignore */ }
    }
  }
  // 等 UDP discovery 应答器/监听完全就绪
  await new Promise((r) => setTimeout(r, 120))
  return harness
}
