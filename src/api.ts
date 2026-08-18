import type {
  DnsResult,
  IpLocationResult,
  SpeedResult,
  SslResult,
  Stack,
  TcpingResult,
  WebsiteResult,
  EmailSecurityResult,
  RBLResult,
  CDNResult,
  BatchLocationResult,
  SecurityHeadersResult,
  CTLogResult,
} from './types'
import type { SourceNode } from './nodes'

const configuredBase = (import.meta.env.VITE_API_BASE_URL || '').trim().replace(/\/$/, '')
const configuredPublicToken = (import.meta.env.VITE_PUBLIC_QUERY_TOKEN || '').trim()
// Keep the default same-origin so production always reaches the local API service.
const savedBaseKey = 'ipw-api-base-v2'
const savedPublicTokenKey = 'ipw-public-token-v1'

function currentBase() {
  if (typeof window !== 'undefined') {
    const saved = window.localStorage.getItem(savedBaseKey)?.trim().replace(/\/$/, '')
    if (saved) return saved
  }
  return configuredBase || '/api'
}

function currentPublicToken() {
  if (typeof window !== 'undefined') {
    const saved = window.localStorage.getItem(savedPublicTokenKey)?.trim()
    if (saved) return saved
  }
  return configuredPublicToken
}

function encodePath(value: string) {
  return encodeURIComponent(value.trim())
}

async function request<T>(path: string, signal?: AbortSignal, init?: RequestInit): Promise<T> {
  return requestUrl<T>(`${currentBase()}${path}`, signal, init)
}

// IP 归属地和当前地区必须走部署站点自己的后端，避免外部节点跨域或不可达。
async function requestLocal<T>(path: string, signal?: AbortSignal): Promise<T> {
  return requestUrl<T>(`/api${path}`, signal)
}

async function requestUrl<T>(url: string, signal?: AbortSignal, init?: RequestInit): Promise<T> {
  const controller = new AbortController()
  const abort = () => controller.abort(signal?.reason)
  signal?.addEventListener('abort', abort, { once: true })
  const timer = window.setTimeout(() => controller.abort('timeout'), 25_000)

  try {
    const response = await fetch(url, {
      ...init,
      signal: controller.signal,
      headers: {
        Accept: 'application/json',
        ...init?.headers,
      },
    })
    const text = await response.text()
    let body: unknown = null
    try {
      body = text ? JSON.parse(text) : null
    } catch {
      body = text
    }
    if (!response.ok) {
      const message = typeof body === 'object' && body && 'error' in body
        ? String((body as { error: unknown }).error)
        : `请求失败（${response.status}）`
      throw new Error(message)
    }
    return body as T
  } catch (error) {
    if (controller.signal.aborted && !signal?.aborted) {
      throw new Error('节点响应超时')
    }
    throw error
  } finally {
    window.clearTimeout(timer)
    signal?.removeEventListener('abort', abort)
  }
}

export interface ManagedNode {
  id: string
  label: string
  base: string
}

export type PublicProbeKind = 'http' | 'tcp' | 'udp' | 'trace' | 'dns' | 'dnssec' | 'asn' | 'whois' | 'email' | 'rbl' | 'cdn' | 'security'

async function nodeRequest<T>(node: ManagedNode, path: string, options: RequestInit = {}): Promise<T> {
  const response = await fetch(`${node.base.replace(/\/$/, '')}${path}`, {
    ...options,
    headers: {
      Accept: 'application/json',
      ...(options.body ? { 'Content-Type': 'application/json' } : {}),
      ...(options.headers || {}),
    },
  })
  const text = await response.text()
  let body: unknown = null
  try { body = text ? JSON.parse(text) : null } catch { body = text }
  if (!response.ok) {
    const message = typeof body === 'object' && body && 'error' in body
      ? String((body as { error: unknown }).error)
      : `Request failed (${response.status})`
    throw new Error(message)
  }
  return body as T
}

function keyHeaders(key: string) {
  return { Authorization: `Bearer ${key.trim()}` }
}

export const nodeDiagnosticsApi = {
  httpTest: (node: ManagedNode, key: string, body: Record<string, unknown>) => nodeRequest<Record<string, unknown>>(node, '/v1/http-test', { method: 'POST', headers: keyHeaders(key), body: JSON.stringify(body) }),
  tcpTest: (node: ManagedNode, key: string, body: Record<string, unknown>) => nodeRequest<Record<string, unknown>>(node, '/v1/tcp-test', { method: 'POST', headers: keyHeaders(key), body: JSON.stringify(body) }),
  udpTest: (node: ManagedNode, key: string, body: Record<string, unknown>) => nodeRequest<Record<string, unknown>>(node, '/v1/udp-test', { method: 'POST', headers: keyHeaders(key), body: JSON.stringify(body) }),
  traceTest: (node: ManagedNode, key: string, body: Record<string, unknown>) => nodeRequest<Record<string, unknown>>(node, '/v1/traceroute', { method: 'POST', headers: keyHeaders(key), body: JSON.stringify(body) }),
  dnsTest: (node: ManagedNode, key: string, body: Record<string, unknown>) => nodeRequest<Record<string, unknown>>(node, '/v1/dns-query', { method: 'POST', headers: keyHeaders(key), body: JSON.stringify(body) }),
  dnssecTest: (node: ManagedNode, key: string, body: Record<string, unknown>) => nodeRequest<Record<string, unknown>>(node, '/v1/dnssec-query', { method: 'POST', headers: keyHeaders(key), body: JSON.stringify(body) }),
  asnTest: (node: ManagedNode, key: string, body: Record<string, unknown>) => nodeRequest<Record<string, unknown>>(node, '/v1/asn', { method: 'POST', headers: keyHeaders(key), body: JSON.stringify(body) }),
  whoisTest: (node: ManagedNode, key: string, body: Record<string, unknown>) => nodeRequest<Record<string, unknown>>(node, '/v1/whois', { method: 'POST', headers: keyHeaders(key), body: JSON.stringify(body) }),
}

export const publicDiagnosticsApi = {
  listNodes: () => nodeRequest<{ nodes: Array<{ id: string; label: string }> }>({ id: 'public', label: 'Public query', base: '/api' }, '/v1/public-query/nodes'),
  run: (nodeId: string, probe: PublicProbeKind, body: Record<string, unknown>) => {
    const token = currentPublicToken()
    const headers: Record<string, string> = { 'Content-Type': 'application/json' }
    if (token) {
      headers.Authorization = `Bearer ${token}`
    }
    return nodeRequest<Record<string, unknown>>(
      { id: nodeId, label: nodeId, base: '/api' },
      `/v1/public-query/${encodeURIComponent(nodeId)}/${encodeURIComponent(probe)}`,
      { method: 'POST', headers, body: JSON.stringify(body) },
    )
  },
}

function nodeUrl(node: SourceNode, path: string) {
  return `${node.url.replace(/\/$/, '')}${path}`
}

export function extractHost(value: string) {
  const input = value.trim()
  if (!input) return ''
  try {
    const normalized = /^[a-z][a-z\d+.-]*:\/\//i.test(input) ? input : `https://${input}`
    return new URL(normalized).hostname
  } catch {
    return input
      .replace(/^[a-z][a-z\d+.-]*:\/\//i, '')
      .split(/[/?#]/, 1)[0]
      .replace(/^\[|\]$/g, '')
  }
}

export const nodeApi = {
  health: (node: SourceNode, signal?: AbortSignal) => requestUrl<{ status: string }>(nodeUrl(node, '/'), signal),
  myLocation: (node: SourceNode, signal?: AbortSignal) => requestUrl<IpLocationResult>(nodeUrl(node, '/v1/location'), signal),
  location: (node: SourceNode, ip: string, signal?: AbortSignal) => requestUrl<IpLocationResult>(nodeUrl(node, `/v1/location/${encodePath(ip)}`), signal),
  website: (node: SourceNode, value: string, signal?: AbortSignal) => requestUrl<WebsiteResult>(nodeUrl(node, `/v1/detail/${encodePath(extractHost(value))}`), signal),
  ssl: (node: SourceNode, value: string, signal?: AbortSignal) => requestUrl<SslResult>(nodeUrl(node, `/v1/ssl/${encodePath(extractHost(value))}`), signal),
  dns: (node: SourceNode, type: string, domain: string, signal?: AbortSignal) => requestUrl<DnsResult>(nodeUrl(node, `/v1/dns/${type}/${encodePath(domain)}`), signal),
  tcping: (node: SourceNode, host: string, port: number, count: number, signal?: AbortSignal) => requestUrl<TcpingResult>(nodeUrl(node, `/v1/tcping/${encodePath(extractHost(host))}?port=${port}&count=${count}`), signal),
  speed: (node: SourceNode, version: Stack, value: string, signal?: AbortSignal) => requestUrl<SpeedResult>(nodeUrl(node, `/v1/speed/${version}/${encodePath(extractHost(value))}`), signal),
}

export async function firstAvailable<T>(nodes: readonly SourceNode[], load: (node: SourceNode) => Promise<T>) {
  let lastError: unknown = new Error('没有可用节点')
  for (const node of nodes) {
    try {
      return { data: await load(node), node }
    } catch (error) {
      lastError = error
    }
  }
  throw lastError
}

export const api = {
  health: (signal?: AbortSignal) => request<{ status: string }>('/', signal),
  myLocation: (signal?: AbortSignal) => request<IpLocationResult>('/v1/location', signal),
  location: (ip: string, signal?: AbortSignal) => request<IpLocationResult>(`/v1/location/${encodePath(ip)}`, signal),
  website: (url: string, signal?: AbortSignal) => request<WebsiteResult>(`/v1/detail?url=${encodeURIComponent(url.trim())}`, signal),
  ssl: (url: string, signal?: AbortSignal) => request<SslResult>(`/v1/ssl?url=${encodeURIComponent(url.trim())}`, signal),
  dns: (type: string, domain: string, signal?: AbortSignal) => request<DnsResult>(`/v1/dns/${type}/${encodePath(domain)}`, signal),
  tcping: (host: string, port: number, count: number, signal?: AbortSignal) => request<TcpingResult>(`/v1/tcping/${encodePath(host)}?port=${port}&count=${count}`, signal),
  speed: (version: Stack, url: string, signal?: AbortSignal) => request<SpeedResult>(`/v1/speed/${version}?url=${encodeURIComponent(url.trim())}`, signal),
  emailSecurity: (domain: string, signal?: AbortSignal) =>
    request<EmailSecurityResult>(`/v1/email-security/${encodePath(extractHost(domain))}`, signal),
  rblCheck: (ip: string, signal?: AbortSignal) =>
    request<RBLResult>(`/v1/rbl/${encodePath(ip)}`, signal),
  cdnDetect: (url: string, signal?: AbortSignal) =>
    request<CDNResult>(`/v1/cdn/${encodePath(extractHost(url))}`, signal),
  batchLocation: (ips: string[], signal?: AbortSignal) =>
    request<BatchLocationResult>('/v1/batch-location', signal, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ips: ips.map((ip) => ip.trim()).filter(Boolean) }),
    }),
  securityHeaders: (url: string, signal?: AbortSignal) =>
    request<SecurityHeadersResult>(`/v1/security-headers/${encodePath(extractHost(url))}`, signal),
  ctLogs: (domain: string, signal?: AbortSignal) =>
    request<CTLogResult>(`/v1/ct-logs/${encodePath(extractHost(domain))}`, signal),
}

export const localApi = {
  myLocation: (signal?: AbortSignal) => requestLocal<IpLocationResult>('/v1/location', signal),
  location: (ip: string, signal?: AbortSignal) => requestLocal<IpLocationResult>(`/v1/location/${encodePath(ip)}`, signal),
}

export function getApiBase() {
  return currentBase()
}

export function setApiBase(value: string) {
  const normalized = value.trim().replace(/\/$/, '')
  if (typeof window !== 'undefined') {
    if (normalized) window.localStorage.setItem(savedBaseKey, normalized)
    else window.localStorage.removeItem(savedBaseKey)
  }
}
