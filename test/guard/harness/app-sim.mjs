// dsh-console-guard 测试装置 · 官方 App 行为模拟
//
// 只做「协议客户端」该做的事：HTTP（node:http，可自定义 Host 头/来源 IP）、
// WebSocket（node:net + 手写握手/帧，等价于 App 的 WS 客户端），
// 覆盖 PATCH-PLAN §二 的扫码票据流、6 位码流、/mp 设备通道、旧版通道。
//
// 说明：socket.remoteAddress 由「连哪个 IP」决定 —— 连 127.0.0.1 即 loopback，
// 连本机局域网 IP 即 LAN 来源，从而在不装真手机的情况下模拟官方 App 的来源。

import http from 'node:http'
import net from 'node:net'
import crypto from 'node:crypto'

export const PREFIX = '/dsh-console'

/** LAN 来源不可用（本机没有非 loopback IPv4）时抛出，用例标记 SKIP。 */
export class SkipError extends Error {
  constructor(message) {
    super(message || 'SKIP')
    this.name = 'SkipError'
    this.skip = true
  }
}

/**
 * 发一个 HTTP 请求。
 * @param {{host?:string, port:number, method?:string, path?:string, query?:object,
 *          headers?:object, body?:string|Buffer|null, timeoutMs?:number}} opts
 * @returns {Promise<{status:number, headers:object, rawHeaders:string[], body:Buffer,
 *                    text:string, json:any, ms:number}>}
 */
export function httpRequest(opts) {
  const o = opts || {}
  const host = o.host || '127.0.0.1'
  const port = Number(o.port) || 0
  const method = String(o.method || 'GET').toUpperCase()
  let p = String(o.path || '/')
  if (o.query && typeof o.query === 'object') {
    const usp = new URLSearchParams()
    for (const [k, v] of Object.entries(o.query)) {
      if (v === undefined || v === null) continue
      usp.set(k, String(v))
    }
    const q = usp.toString()
    if (q) p += (p.indexOf('?') >= 0 ? '&' : '?') + q
  }
  const headers = Object.assign({ connection: 'close' }, o.headers || {})
  let payload = null
  if (o.body !== undefined && o.body !== null) {
    payload = Buffer.isBuffer(o.body) ? o.body : Buffer.from(String(o.body), 'utf8')
    if (headers['content-length'] === undefined && headers['Content-Length'] === undefined) {
      headers['content-length'] = String(payload.length)
    }
  }
  const startedAt = Date.now()
  return new Promise((resolve, reject) => {
    const req = http.request({ host, port, method, path: p, headers }, (res) => {
      const chunks = []
      res.on('data', (c) => chunks.push(c))
      res.on('end', () => {
        const body = Buffer.concat(chunks)
        let json = null
        try { json = JSON.parse(body.toString('utf8')) } catch (e) { json = null }
        resolve({
          status: res.statusCode || 0,
          headers: res.headers,
          rawHeaders: res.rawHeaders,
          body,
          text: body.toString('utf8'),
          json,
          ms: Date.now() - startedAt
        })
      })
      res.on('error', reject)
    })
    req.on('error', reject)
    req.setTimeout(Number(o.timeoutMs) || 8000, () => {
      try { req.destroy(new Error('http-timeout')) } catch (e) { /* ignore */ }
    })
    if (payload) req.write(payload)
    req.end()
  })
}

// ── WebSocket 客户端（最小实现，够测 App 的 mux 通道）───────────────────────
function encodeMaskedFrame(opcode, payloadBuf) {
  const payload = Buffer.isBuffer(payloadBuf) ? payloadBuf : Buffer.from(String(payloadBuf), 'utf8')
  const len = payload.length
  let header
  if (len < 126) {
    header = Buffer.alloc(2)
    header[1] = 0x80 | len
  } else if (len < 65536) {
    header = Buffer.alloc(4)
    header[1] = 0x80 | 126
    header.writeUInt16BE(len, 2)
  } else {
    header = Buffer.alloc(10)
    header[1] = 0x80 | 127
    header.writeBigUInt64BE(BigInt(len), 2)
  }
  header[0] = 0x80 | opcode
  const mask = crypto.randomBytes(4)
  const masked = Buffer.alloc(len)
  for (let i = 0; i < len; i += 1) masked[i] = payload[i] ^ mask[i & 3]
  return Buffer.concat([header, mask, masked])
}

/**
 * 连 WebSocket（/mp/api/ws/mux），返回客户端对象。
 * 服务端 0.5.64 在 101 之后只下行业务帧（没有 ready 帧，见 NOTES.md），
 * 因此这里提供 waitFor 让用例等待 any/pong/session/event。
 */
export function wsConnect(opts) {
  const o = opts || {}
  const host = o.host || '127.0.0.1'
  const port = Number(o.port) || 0
  const wsPath = String(o.path || (PREFIX + '/mp/api/ws/mux'))
  const timeoutMs = Number(o.timeoutMs) || 8000
  const key = crypto.randomBytes(16).toString('base64')
  const messages = []
  const waiters = []
  let handshaken = false
  let closed = false
  let buffer = Buffer.alloc(0)
  let settled = false

  return new Promise((resolve, reject) => {
    const sock = net.connect({ host, port })
    const client = {
      messages,
      status: 0,
      head: '',
      rawHead: '',
      receivedReady: false,
      waitFor(predicate, waitMs) {
        const pred = typeof predicate === 'function' ? predicate : (m) => m && m.type === predicate
        const existing = messages.find((m) => { try { return pred(m) } catch (e) { return false } })
        if (existing) return Promise.resolve(existing)
        return new Promise((res, rej) => {
          const waiter = { pred, res, rej, timer: null }
          waiter.timer = setTimeout(() => {
            const i = waiters.indexOf(waiter)
            if (i >= 0) waiters.splice(i, 1)
            rej(new Error('ws-wait-timeout'))
          }, Number(waitMs) || 4000)
          waiters.push(waiter)
        })
      },
      sendJson(obj) {
        if (sock.destroyed) return false
        sock.write(encodeMaskedFrame(0x1, JSON.stringify(obj)))
        return true
      },
      close() {
        if (settled && sock.destroyed) return
        try { sock.write(encodeMaskedFrame(0x8, Buffer.from([0x03, 0xe8]))) } catch (e) { /* ignore */ }
        try { sock.destroy() } catch (e) { /* ignore */ }
      }
    }

    function pushMessage(m) {
      messages.push(m)
      if (m && m.type === 'ready') client.receivedReady = true
      for (let i = waiters.length - 1; i >= 0; i -= 1) {
        const w = waiters[i]
        let hit = false
        try { hit = !!w.pred(m) } catch (e) { hit = false }
        if (!hit) continue
        waiters.splice(i, 1)
        clearTimeout(w.timer)
        w.res(m)
      }
    }

    function drainFrames() {
      for (;;) {
        if (buffer.length < 2) return
        const b0 = buffer[0]
        const b1 = buffer[1]
        const opcode = b0 & 0x0f
        const masked = (b1 & 0x80) !== 0
        let len = b1 & 0x7f
        let offset = 2
        if (len === 126) {
          if (buffer.length < offset + 2) return
          len = buffer.readUInt16BE(offset)
          offset += 2
        } else if (len === 127) {
          if (buffer.length < offset + 8) return
          len = Number(buffer.readBigUInt64BE(offset))
          offset += 8
        }
        const maskKey = masked ? buffer.subarray(offset, offset + 4) : null
        if (masked) offset += 4
        if (buffer.length < offset + len) return
        const payload = Buffer.from(buffer.subarray(offset, offset + len))
        if (maskKey) {
          for (let i = 0; i < payload.length; i += 1) payload[i] ^= maskKey[i & 3]
        }
        buffer = buffer.subarray(offset + len)
        if (opcode === 0x8) { client.close(); continue }
        if (opcode === 0x9) { try { sock.write(encodeMaskedFrame(0xa, payload)) } catch (e) { /* ignore */ } continue }
        if (opcode === 0xa) { pushMessage({ type: 'pong-raw' }); continue }
        if (opcode !== 0x1 && opcode !== 0x2) continue
        const text = payload.toString('utf8')
        let msg = null
        try { msg = JSON.parse(text) } catch (e) { msg = { type: 'raw', text } }
        pushMessage(msg)
      }
    }

    function fail(err) {
      if (settled) return
      settled = true
      for (const w of waiters.splice(0)) {
        clearTimeout(w.timer)
        try { w.rej(err) } catch (e) { /* ignore */ }
      }
      reject(err)
    }

    sock.setNoDelay(true)
    sock.on('connect', () => {
      const lines = [
        'GET ' + wsPath + ' HTTP/1.1',
        'Host: ' + host + ':' + String(port),
        'Upgrade: websocket',
        'Connection: Upgrade',
        'Sec-WebSocket-Key: ' + key,
        'Sec-WebSocket-Version: 13',
        'Sec-WebSocket-Protocol: dsh-console'
      ]
      if (o.cookie) lines.push('Cookie: ' + String(o.cookie))
      for (const [k, v] of Object.entries(o.headers || {})) lines.push(k + ': ' + v)
      sock.write(lines.join('\r\n') + '\r\n\r\n')
    })
    sock.on('data', (chunk) => {
      buffer = Buffer.concat([buffer, chunk])
      if (!handshaken) {
        const idx = buffer.indexOf('\r\n\r\n')
        if (idx < 0) return
        const rawHead = buffer.subarray(0, idx).toString('utf8')
        buffer = buffer.subarray(idx + 4)
        const statusLine = rawHead.split('\r\n')[0] || ''
        const m = /^HTTP\/1\.1\s+(\d{3})/.exec(statusLine)
        client.status = m ? Number(m[1]) : 0
        client.head = statusLine
        client.rawHead = rawHead
        handshaken = true
        settled = true
        if (client.status !== 101) {
          resolve(client)
          setImmediate(() => { try { sock.destroy() } catch (e) { /* ignore */ } })
          return
        }
        resolve(client)
        drainFrames()
        return
      }
      drainFrames()
    })
    sock.on('error', (err) => { if (!handshaken) fail(err) })
    sock.on('close', () => {
      closed = true
      client.closed = true
      if (!handshaken) fail(new Error('ws-closed-before-handshake'))
    })
    sock.setTimeout(timeoutMs, () => { fail(new Error('ws-handshake-timeout')) })
  })
}

// ── 官方 App 协议客户端 ─────────────────────────────────────────────────────
export function parseTicketFromPayload(payload) {
  const m = /(?:^|\?|&)k=([^&]+)/.exec(String(payload || ''))
  if (!m) return ''
  try { return decodeURIComponent(m[1]) } catch (e) { return '' }
}

export function parseCookieSecret(setCookieOrCookie) {
  const raw = Array.isArray(setCookieOrCookie) ? setCookieOrCookie.join('; ') : String(setCookieOrCookie || '')
  const m = /(?:^|[;\s])mp_device=([^;\s]+)/.exec(raw)
  if (!m) return ''
  try { return decodeURIComponent(m[1]) } catch (e) { return m[1] }
}

/**
 * @param {{port:number, token:string, lanIp?:string}} cfg
 */
export function createApp(cfg) {
  const c = cfg || {}
  const port = Number(c.port)
  const token = String(c.token || '')
  const lanIp = String(c.lanIp || '')
  const loopHost = '127.0.0.1'

  function sourceHost(source) {
    const src = String(source || 'loop')
    if (src === 'loop' || src === 'loopback' || src === 'local') return loopHost
    if (src === 'lan') {
      if (lanIp === '') throw new SkipError('本机没有非 loopback IPv4，无法模拟局域网来源')
      return lanIp
    }
    return src
  }

  function urlFor(source) {
    const h = sourceHost(source)
    return 'http://' + h + ':' + String(port) + PREFIX
  }

  async function request(opts) {
    const o = Object.assign({}, opts || {})
    const source = o.source || 'loop'
    const host = o.host || sourceHost(source)
    return httpRequest({
      host,
      port,
      method: o.method || 'GET',
      path: o.path || '/',
      query: o.query,
      headers: o.headers,
      body: o.body,
      timeoutMs: o.timeoutMs
    })
  }

  function raw(p) {
    const opts = Object.assign({}, p || {})
    const pathPart = String(opts.path || '/')
    const full = pathPart.indexOf(PREFIX) === 0 ? pathPart : PREFIX + pathPart
    opts.path = full
    return request(opts)
  }

  const get = (p, opts) => raw(Object.assign({ method: 'GET' }, opts || {}, { path: p }))
  const post = (p, body, opts) => raw(Object.assign({
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: body === undefined ? '{}' : JSON.stringify(body)
  }, opts || {}, { path: p }))

  const app = {
    port,
    token,
    lanIp,
    urlFor,
    sourceHost,
    request: raw,
    get,
    post,
    base: { loop: urlFor('loop'), lan: lanIp ? urlFor('lan') : '' },

    // ① loopback 取码（官方面板行为）
    newcodeLoopback: (opts) => get('/newcode', Object.assign({ source: 'loop' }, opts || {})),
    qrLoopback: (opts) => get('/qr', Object.assign({ source: 'loop' }, opts || {})),
    newcodeLan: (opts) => get('/newcode', Object.assign({ source: 'lan' }, opts || {})),
    qrLan: (opts) => get('/qr', Object.assign({ source: 'lan' }, opts || {})),

    // ② 扫码票据流：payload 里的 pt_ 票据 → /pair/ticket → token
    ticket: (ticket, opts) => post('/pair/ticket', { ticket }, Object.assign({ source: 'loop' }, opts || {})),

    // ③ 6 位码流
    claim: (code, opts) => post('/claim', { code }, Object.assign({ source: 'lan' }, opts || {})),
    claimAs: (source, code, opts) => post('/claim', { code }, Object.assign({ source }, opts || {})),

    // ④ /mp 配对（新 6 位码流）
    mpAccept: (code, opts) => post('/mp/pair/accept', { token: code }, Object.assign({ source: 'lan' }, opts || {})),
    mpAcceptAs: (source, code, opts) => post('/mp/pair/accept', { token: code }, Object.assign({ source }, opts || {})),

    // ⑤ token → mp_device Cookie
    mpCookie: (tok, opts) => get('/mp-cookie', Object.assign({ source: 'loop', query: { token: tok } }, opts || {})),

    // ⑥ 设备通道 RPC
    mpRpc: (cookie, method, payload, opts) => {
      const o = Object.assign({ source: 'lan' }, opts || {})
      o.headers = Object.assign({ cookie }, (opts && opts.headers) || {})
      return post('/mp/api/' + method, {
        rpcId: String((opts && opts.rpcId) || ('rpc-' + method + '-' + Date.now().toString(36))),
        payload: payload || {}
      }, o)
    },

    // 旧版通道
    info: (tok, opts) => get('/info', Object.assign({ source: 'lan', query: { token: tok } }, opts || {})),
    sessions: (tok, opts) => get('/sessions', Object.assign({ source: 'lan', query: { token: tok } }, opts || {})),
    cmd: (tok, op, payload, opts) => post('/cmd', { op, payload: payload || {} }, Object.assign({ source: 'lan', query: { token: tok } }, opts || {})),
    attachment: (tok, id, opts) => get('/attachment', Object.assign({ source: 'lan', query: { token: tok, id } }, opts || {})),
    upload: (tok, name, data, opts) => raw(Object.assign({
      method: 'POST',
      source: 'lan',
      path: '/upload',
      query: { token: tok, name },
      headers: { 'content-type': 'application/octet-stream' },
      body: data
    }, opts || {})),
    file: (tok, filePath, opts) => get('/file', Object.assign({ source: 'lan', query: { token: tok, path: filePath } }, opts || {})),

    // WebSocket
    wsMux: (cookie, opts) => wsConnect(Object.assign({
      host: sourceHost('lan'),
      port,
      path: PREFIX + '/mp/api/ws/mux',
      cookie
    }, opts || {}))
  }
  return app
}
