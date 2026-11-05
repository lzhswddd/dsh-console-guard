// guard-policy.mjs — 加固版 dsh-console 的共享安全策略（宿主侧与局域网服务共用）
//
// 设计目标（与 docs/PATCH-PLAN.md 一致）：
//  1. 只保留手机 App 核心协议所需的 HTTP/WS 路由；其余一律 404。
//  2. 未鉴权配对端点（/claim、/pair/ticket、/qr、/newcode、/mp/pair/accept）加限速，
//     并校验 Host 头，阻断 DNS rebinding（SEC-10）。
//  3. /qr、/newcode 只允许 loopback 来源（SEC-01/SEC-16 修复），且 loopback 也校验 Host。
//  4. 文件读写限制在「收件箱 + 配置的白名单根目录」内（SEC-04 修复）。
//  5. 手机端 /cmd 去掉插件安装/启停、升级、隧道/自定义服务器、推送、桌面代理、
//     权限预设切换、演示工具等 op（SEC-03/14/15 修复）。
//  6. 模块本身无外部依赖、无副作用，便于独立测试。

import fs from 'node:fs'
import path from 'node:path'

export const GUARD_VERSION = 1

/** 默认加固配置。`enabled:false` 只用于回归对比测试，绝不要在日常使用中关闭。 */
export const GUARD_DEFAULTS = Object.freeze({
  enabled: true,
  // 允许文件浏览/读取的根目录（绝对路径）；收件箱目录总是允许。
  fileRoots: [],
  // 额外可用于配对/手机连接的基地址，例如 Tailscale: ["http://100.64.0.8:8899"]
  // 会写进二维码的 c=（候选地址）并加入 Host 白名单，不开启任何隧道。
  extraBaseUrls: [],
  // /claim 错码限速（全局窗口）
  claimFailMax: 20,
  claimFailWindowMs: 15 * 60 * 1000,
  // /mp/pair/accept 限速（按来源 IP 窗口）
  pairAcceptMax: 30,
  pairAcceptWindowMs: 15 * 60 * 1000,
  // 局域网服务监听地址（手机必须能从局域网访问，默认 0.0.0.0）
  bindHost: '0.0.0.0'
})

const LIMIT_KEYS_MAX = 512

function asString(v) {
  return typeof v === 'string' ? v.trim() : ''
}

function asStringList(v) {
  if (!Array.isArray(v)) return []
  const out = []
  for (const one of v) {
    const s = asString(one)
    if (s !== '' && out.indexOf(s) === -1) out.push(s)
  }
  return out
}

function asPositiveInt(v, fallback) {
  const n = Number(v)
  return Number.isFinite(n) && n > 0 ? Math.floor(n) : fallback
}

/** 把插件 config.guard 归一化成完整策略对象。 */
export function resolveGuardConfig(raw) {
  const src = raw && typeof raw === 'object' && !Array.isArray(raw) ? raw : {}
  return {
    enabled: src.enabled !== false,
    fileRoots: asStringList(src.fileRoots),
    extraBaseUrls: asStringList(src.extraBaseUrls),
    claimFailMax: asPositiveInt(src.claimFailMax, GUARD_DEFAULTS.claimFailMax),
    claimFailWindowMs: asPositiveInt(src.claimFailWindowMs, GUARD_DEFAULTS.claimFailWindowMs),
    pairAcceptMax: asPositiveInt(src.pairAcceptMax, GUARD_DEFAULTS.pairAcceptMax),
    pairAcceptWindowMs: asPositiveInt(src.pairAcceptWindowMs, GUARD_DEFAULTS.pairAcceptWindowMs),
    bindHost: asString(src.bindHost) || GUARD_DEFAULTS.bindHost
  }
}

// ── 路由白名单 ───────────────────────────────────────────────────────────────
// 手机 App 会用到的全部路由。`/` 与 `/pair` 保留（上游本来就返回 403 JSON，
// 某些客户端会先探测端口），除此之外的一律拒绝。
export const ROUTE_ALLOWED_EXACT = Object.freeze(new Set([
  '/',
  '/pair',
  '/claim',
  '/pair/ticket',
  '/qr',
  '/newcode',
  '/info',
  '/sessions',
  '/attachment',
  '/file',
  '/upload',
  '/cmd',
  '/mp-cookie'
]))

export function routeAllowed(pathname) {
  const p = typeof pathname === 'string' && pathname !== '' ? pathname : '/'
  if (ROUTE_ALLOWED_EXACT.has(p)) return true
  // 手机端专用通道：/mp/pair/* 与 /mp/api/*
  if (p === '/mp' || p.startsWith('/mp/')) return true
  return false
}

/** 未鉴权（或仅凭设备 Cookie 之外方式）即可触达的配对相关端点，需要 Host 校验。 */
export const PAIRING_PATHS = Object.freeze(new Set([
  '/claim',
  '/pair/ticket',
  '/qr',
  '/newcode',
  '/mp/pair/accept'
]))

export function isPairingPath(pathname) {
  return PAIRING_PATHS.has(String(pathname || ''))
}

/** 仅 loopback 可访问的端点在加固版里额外限制。 */
export const LOOPBACK_ONLY_PATHS = Object.freeze(new Set(['/qr', '/newcode']))

export function isLoopbackOnlyPath(pathname) {
  return LOOPBACK_ONLY_PATHS.has(String(pathname || ''))
}

// ── Host / 来源校验 ──────────────────────────────────────────────────────────

export function normalizeHostHeader(hostHeader) {
  let h = asString(hostHeader).toLowerCase()
  if (h === '') return ''
  // 去掉端口（IPv6 形如 [::1]:8899）
  if (h.charAt(0) === '[') {
    const end = h.indexOf(']')
    return end === -1 ? h : h.slice(1, end)
  }
  const colon = h.lastIndexOf(':')
  if (colon > 0 && h.indexOf(':') === colon) return h.slice(0, colon)
  return h
}

function hostnameOfUrl(raw) {
  try {
    const u = new URL(asString(raw))
    return u.hostname.toLowerCase().replace(/^\[|\]$/g, '')
  } catch (e) {
    return ''
  }
}

/**
 * 校验 Host 头是否属于本机（loopback / 局域网 IP / 配置的额外基地址）。
 * 用于所有未鉴权配对端点，阻断 DNS rebinding 与跨站请求。
 * 无 Host 头（HTTP/1.0 原始客户端）按不通过处理。
 */
export function hostAllowed(hostHeader, ctx) {
  const host = normalizeHostHeader(hostHeader)
  if (host === '') return false
  if (host === '' ) return false
  // 注意：不把 0.0.0.0 加入白名单（部分浏览器/工具会把它当作可访问的本机地址）。
  if (host === 'localhost' || host === '127.0.0.1' || host === '::1') return true
  const lan = (ctx && Array.isArray(ctx.lanAddresses)) ? ctx.lanAddresses : []
  for (const ip of lan) {
    // 兼容 lanAddresses() 的 [{name,address}] 形状与纯字符串
    const addr = (ip && typeof ip === 'object') ? String(ip.address || '') : String(ip)
    if (normalizeHostHeader(addr) === host) return true
  }
  const extra = (ctx && Array.isArray(ctx.extraBaseUrls)) ? ctx.extraBaseUrls : []
  for (const base of extra) {
    if (hostnameOfUrl(base) === host) return true
  }
  return false
}

/** 是否来自本机 loopback（不含任何转发头）。 */
export function isLoopbackPeer(req) {
  const addr = String((req && req.socket && req.socket.remoteAddress) || '')
  return addr === '127.0.0.1' || addr === '::1' || addr === '::ffff:127.0.0.1'
}

// ── 限速 ────────────────────────────────────────────────────────────────────

export class RateLimiter {
  constructor({ max, windowMs }) {
    this.max = Math.max(1, asPositiveInt(max, 1))
    this.windowMs = asPositiveInt(windowMs, 60 * 1000)
    this.map = new Map()
  }

  _row(key) {
    const now = Date.now()
    const k = String(key || '')
    let row = this.map.get(k)
    if (!row || now - row.start >= this.windowMs) {
      row = { start: now, n: 0 }
      this.map.set(k, row)
      if (this.map.size > LIMIT_KEYS_MAX) {
        for (const [kk, rr] of this.map) {
          if (now - rr.start >= this.windowMs) this.map.delete(kk)
        }
      }
    }
    return row
  }

  /** 记一次尝试；返回 { ok, retryAfterMs, n }。 */
  hit(key) {
    const row = this._row(key)
    row.n += 1
    if (row.n > this.max) {
      return { ok: false, retryAfterMs: Math.max(0, this.windowMs - (Date.now() - row.start)), n: row.n }
    }
    return { ok: true, retryAfterMs: 0, n: row.n }
  }

  reset(key) {
    this.map.delete(String(key || ''))
  }

  /** 只查当前窗口是否已封顶（不增加计数）。 */
  blocked(key) {
    const row = this.map.get(String(key || ''))
    const now = Date.now()
    if (!row || now - row.start >= this.windowMs) return { blocked: false, retryAfterMs: 0 }
    if (row.n >= this.max) {
      return { blocked: true, retryAfterMs: Math.max(0, this.windowMs - (now - row.start)) }
    }
    return { blocked: false, retryAfterMs: 0 }
  }
}

/** 局域网的「错码」计数也应该按来源区分：一个攻击者刷满不应锁死所有人。 */
export function clientKeyOf(req) {
  const xff = String((req && req.headers && req.headers['x-forwarded-for']) || '').trim()
  // 加固版不接受任何转发来源（见 lan-server），这里只用于限速分桶。
  const addr = String((req && req.socket && req.socket.remoteAddress) || '')
  return (xff !== '' ? xff.split(',')[0].trim() : addr) || 'unknown'
}

// ── /cmd op 策略 ────────────────────────────────────────────────────────────
// 保留手机端会话操作与只读查询；去掉一切会改变宿主全局状态或执行代码的 op。

// 读接口保留 op 名，但宿主侧必须返回「未启用」桩数据（不能落到上游实现，
// 否则 updateCheck 会联网查 registry、remotePairGet 会读云端状态）。
export const CMD_OPS_READONLY_STUB = Object.freeze(new Set([
  'updateCheck',
  'updateState',
  'remotePairGet',
  'customServerGet',
  'pushStatus',
  'pushTokenList'
]))

// 直接拒绝、返回 { ok:false, error:'guard-disabled:...' } 的 op。
export const CMD_OPS_DENIED = Object.freeze(new Set([
  // 插件安装 / 启停（SEC-03、SEC-14）
  'pluginBundleInstall',
  'pluginBundleToggle',
  // 升级 / 回滚（SEC-15）
  'updateStart',
  'updateCancel',
  'updateRollback',
  // 云端 / 隧道 / 自定义服务器写操作（SEC-02、SEC-13）
  'remotePairSet',
  'remotePairCodeRefresh',
  'customServerSet',
  'customServerPrompt',
  // 华为推送注册 / 测试发送（SEC-09）
  'pushRegister',
  'pushTest',
  // 桌面 Web GUI 代理（SEC-06）
  'desktop',
  'desktopWeb',
  // 改权限预设 / 改 agent 预设（手机端不应有）
  'permissionSet',
  'selectPreset',
  // 演示卡片工具
  'pvWeather'
]))

export function cmdOpDenied(op) {
  const o = String(op || '')
  return CMD_OPS_DENIED.has(o) || CMD_OPS_READONLY_STUB.has(o)
}

export function cmdOpReadonlyStub(op) {
  return CMD_OPS_READONLY_STUB.has(String(op || ''))
}

/** 需要在 runCommand 里做根目录校验的 op。 */
export const FS_CMDS = Object.freeze(new Set(['fsList', 'fsMkdir', 'readFile']))

export function isFsCmd(op) {
  return FS_CMDS.has(String(op || ''))
}

export function fsCmdPathOf(op, payload) {
  const p = payload && typeof payload === 'object' ? payload : {}
  const raw = asString(p.path) || asString(p.dir) || asString(p.file)
  return raw
}

// ── 文件根目录 ──────────────────────────────────────────────────────────────

export function resolveFileRoots(inboxDir, guard) {
  const roots = []
  const add = (raw) => {
    const s = asString(raw)
    if (s === '') return
    let abs = s
    try { abs = path.resolve(s) } catch (e) { return }
    if (roots.indexOf(abs) === -1) roots.push(abs)
  }
  if (inboxDir) add(inboxDir)
  const extra = guard && Array.isArray(guard.fileRoots) ? guard.fileRoots : []
  for (const one of extra) add(one)
  return roots
}

function realpathLoose(abs) {
  // 对存在的路径做 realpath；对不存在的路径回溯到最近的存在祖先，防符号链接逃逸。
  let cur = abs
  const tail = []
  for (let i = 0; i < 32; i += 1) {
    try {
      const rp = fs.realpathSync(cur)
      return path.join.apply(path, [rp].concat(tail.reverse()))
    } catch (e) {
      const parent = path.dirname(cur)
      if (parent === cur) return abs
      tail.push(path.basename(cur))
      cur = parent
    }
  }
  return abs
}

function within(root, target) {
  const r = realpathLoose(root)
  const t = realpathLoose(target)
  if (r === t) return true
  const rel = path.relative(r, t)
  return rel !== '' && rel !== '..' && !rel.startsWith('..' + path.sep) && !path.isAbsolute(rel)
}

/**
 * 路径是否落在白名单根目录内。root 只允许目录；target 必须是绝对路径。
 * 使用 realpath 防符号链接逃逸；文件不存在时校验其最近存在祖先。
 */
export function pathWithinRoots(target, roots) {
  const t = asString(target)
  if (t === '' || t.indexOf('\u0000') !== -1) return false
  if (!path.isAbsolute(t)) return false
  const list = Array.isArray(roots) ? roots : []
  for (const root of list) {
    if (within(root, t)) return true
  }
  return false
}

// ── 面板展示用特性开关 ──────────────────────────────────────────────────────
export const GUARD_FEATURES = Object.freeze({
  cloud: false,
  tunnel: false,
  screen: false,
  screenInput: false,
  push: false,
  remotePair: false,
  companion: false,
  mobilePluginInstall: false,
  mobileUpdate: false,
  desktopProxy: false,
  memeGallery: false
})
