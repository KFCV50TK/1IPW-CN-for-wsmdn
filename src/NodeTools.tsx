import Alert from 'tdesign-react/es/alert'
import Button from 'tdesign-react/es/button'
import Card from 'tdesign-react/es/card'
import Input from 'tdesign-react/es/input'
import Loading from 'tdesign-react/es/loading'
import Select from 'tdesign-react/es/select'
import Tag from 'tdesign-react/es/tag'
import Textarea from 'tdesign-react/es/textarea'
import {
  CheckCircleIcon,
  ErrorCircleIcon,
  FileSearchIcon,
  InfoCircleIcon,
  SearchIcon,
} from 'tdesign-icons-react'
import { useEffect, useMemo, useState, type ReactNode } from 'react'
import { useSearchParams } from 'react-router-dom'
import {
  api,
  publicDiagnosticsApi,
  type ManagedNode,
  type PublicProbeKind,
} from './api'
import type {
  EmailSecurityResult,
  EmailSecurityRecord,
  RBLResult,
  CDNResult,
  BatchLocationResult,
  BatchLocationEntry,
  BatchLocationGeo,
  SecurityHeadersResult,
} from './types'

const fallbackQueryNodes = [
  { id: 'zaozhuang', label: '中国 山东 枣庄 移动/电信双线' },
  { id: 'hongkong', label: '中国 香港 Cogent' },
]

type ProbeKind = PublicProbeKind
// 节点能力检测：可通过节点代理执行（email/rbl/cdn/security）
type NodeCapableKind = 'email' | 'rbl' | 'cdn' | 'security'
// 主站专属检测：只能在主站执行（batch 依赖 ipdb）
type MainSiteOnlyKind = 'batch'
type LocalCheckKind = NodeCapableKind | MainSiteOnlyKind
type QueryKind = ProbeKind | LocalCheckKind
type QueryResult = Record<string, unknown>
type ResultTone = 'success' | 'warning' | 'error' | 'neutral'

const nodeCapableKinds: readonly NodeCapableKind[] = ['email', 'rbl', 'cdn', 'security']
const mainSiteOnlyKinds: readonly MainSiteOnlyKind[] = ['batch']
const localCheckKinds: readonly LocalCheckKind[] = [...nodeCapableKinds, ...mainSiteOnlyKinds]

function isLocalCheck(kind: QueryKind): kind is LocalCheckKind {
  return (localCheckKinds as readonly string[]).includes(kind)
}

function isNodeCapable(kind: QueryKind): kind is NodeCapableKind {
  return (nodeCapableKinds as readonly string[]).includes(kind)
}

const BATCH_LIMIT = 50

const queryOptions = [
  {
    group: '节点探测',
    children: [
      { label: 'HTTP GET / POST', value: 'http' },
      { label: 'TCP 连接', value: 'tcp' },
      { label: 'UDP 探测', value: 'udp' },
      { label: '路由追踪', value: 'trace' },
      { label: '递归 DNS', value: 'dns' },
      { label: 'DNSSEC 验证', value: 'dnssec' },
      { label: 'ASN 信息', value: 'asn' },
      { label: '域名 WHOIS', value: 'whois' },
    ],
  },
  {
    group: '节点检测',
    children: [
      { label: '邮件安全 SPF/DKIM/DMARC', value: 'email' },
      { label: 'RBL 黑名单', value: 'rbl' },
      { label: 'CDN 识别', value: 'cdn' },
      { label: 'HTTP 安全响应头', value: 'security' },
    ],
  },
  {
    group: '主站检测',
    children: [
      { label: '批量 IP 归属地', value: 'batch' },
    ],
  },
]

const kindLabels: Record<LocalCheckKind, string> = {
  email: '邮件安全',
  rbl: 'RBL 黑名单',
  cdn: 'CDN 识别',
  batch: '批量 IP 归属地',
  security: '安全响应头',
}

const rcodeLabels: Record<number, string> = {
  0: 'NOERROR',
  1: 'FORMERR',
  2: 'SERVFAIL',
  3: 'NXDOMAIN',
  4: 'NOTIMP',
  5: 'REFUSED',
}

function defaultTarget(probe: QueryKind) {
  if (probe === 'http') return 'https://example.com'
  if (probe === 'asn' || probe === 'rbl') return '8.8.8.8'
  if (probe === 'trace') return '1.1.1.1'
  if (probe === 'cdn' || probe === 'security') return 'https://example.com'
  if (probe === 'batch') return ''
  return 'example.com'
}

function targetLabel(probe: QueryKind) {
  if (probe === 'whois' || probe === 'email') return '域名'
  if (probe === 'asn') return '公网 IP'
  if (probe === 'rbl') return '待查 IP'
  if (probe === 'batch') return 'IP 列表'
  if (probe === 'dns' || probe === 'dnssec') return '查询域名'
  if (probe === 'cdn' || probe === 'security') return '网站地址'
  return probe === 'http' ? '目标 URL' : '目标主机'
}

function formatDate(value: unknown) {
  if (!value) return '—'
  const date = new Date(String(value))
  return Number.isNaN(date.getTime()) ? String(value) : date.toLocaleString('zh-CN', { hour12: false })
}

function valueText(value: unknown, fallback = '—') {
  if (value === null || value === undefined || value === '') return fallback
  return String(value)
}

function valueNumber(value: unknown) {
  const number = Number(value)
  return Number.isFinite(number) ? number : 0
}

function valueBoolean(value: unknown) {
  return value === true || value === 'true'
}

function valueList(value: unknown) {
  return Array.isArray(value) ? value.map((item) => String(item)) : []
}

function valueRecord(value: unknown): QueryResult {
  return value && typeof value === 'object' && !Array.isArray(value) ? value as QueryResult : {}
}

function valueRecords(value: unknown): QueryResult[] {
  return Array.isArray(value)
    ? value.filter((item): item is QueryResult => Boolean(item) && typeof item === 'object' && !Array.isArray(item))
    : []
}

function formatDuration(value: unknown) {
  const duration = valueNumber(value)
  if (duration >= 1000) return `${(duration / 1000).toFixed(2)} 秒`
  return `${duration.toFixed(duration >= 100 ? 0 : 1)} 毫秒`
}

function formatBytes(value: unknown) {
  const bytes = valueNumber(value)
  if (bytes >= 1024 * 1024) return `${(bytes / 1024 / 1024).toFixed(2)} MB`
  if (bytes >= 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${bytes} B`
}

function formatWhoisDate(value: unknown) {
  const text = valueText(value, '')
  if (!text || text === '未提供') return '未提供'
  if (/^\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}$/.test(text)) return text.replace('T', ' ')
  return formatDate(text)
}

function friendlyError(error: unknown) {
  const message = error instanceof Error ? error.message : '查询请求失败'
  if (/too many queries/i.test(message)) return '查询过于频繁，请稍后再试。'
  if (/service is busy/i.test(message)) return '当前查询较多，请稍后重试。'
  if (/temporarily unavailable|failed to fetch|networkerror/i.test(message)) return '所选节点暂时不可用，请切换节点或稍后重试。'
  if (/valid api key required/i.test(message)) return '节点服务配置异常，请联系管理员。'
  if (/traceroute is unavailable/i.test(message)) return '所选节点未安装路由追踪工具，请切换节点。'
  if (/private|internal/i.test(message)) return '不允许检测私网或内部网络地址。'
  if (/unsupported dns record type/i.test(message)) return '该 DNS 记录类型暂不支持。'
  return message
}

function NodeError({ message }: { message: string }) {
  if (!message) return null
  return <Alert className="node-tool-alert" theme="error" icon={<ErrorCircleIcon />} message={message} />
}

function ResultStatus({ tone, title, detail }: { tone: ResultTone; title: string; detail?: string }) {
  return (
    <div className={`query-result-status is-${tone}`} role="status">
      <span className="query-result-status-icon">
        {tone === 'success' ? <CheckCircleIcon /> : tone === 'error' ? <ErrorCircleIcon /> : <InfoCircleIcon />}
      </span>
      <span>
        <strong>{title}</strong>
        {detail && <small>{detail}</small>}
      </span>
    </div>
  )
}

function ResultMetrics({ items }: { items: Array<{ label: string; value: ReactNode }> }) {
  return (
    <div className="query-result-metrics">
      {items.map((item) => (
        <div key={item.label}>
          <span>{item.label}</span>
          <strong>{item.value}</strong>
        </div>
      ))}
    </div>
  )
}

function DetailList({ items }: { items: Array<{ label: string; value: ReactNode }> }) {
  return (
    <dl className="query-detail-list">
      {items.map((item) => (
        <div key={item.label}>
          <dt>{item.label}</dt>
          <dd>{item.value}</dd>
        </div>
      ))}
    </dl>
  )
}

function RawResponse({ result }: { result: QueryResult }) {
  const text = useMemo(() => JSON.stringify(result, null, 2), [result])
  return (
    <details className="query-raw-response">
      <summary>查看原始响应</summary>
      <pre>{text}</pre>
    </details>
  )
}

function ResponseBody({ body, contentType, truncated }: { body: string; contentType: string; truncated: boolean }) {
  let preview = body
  if (/json/i.test(contentType)) {
    try { preview = JSON.stringify(JSON.parse(body), null, 2) } catch { /* Keep the original response. */ }
  }
  const clipped = preview.length > 12_000
  if (clipped) preview = `${preview.slice(0, 12_000)}\n…`
  return (
    <section className="query-result-section">
      <div className="query-section-heading">
        <h3>响应摘要</h3>
        {(truncated || clipped) && <Tag theme="warning" variant="light">内容已截断</Tag>}
      </div>
      <pre className="query-response-preview">{preview || '响应体为空'}</pre>
    </section>
  )
}

function HttpResult({ result }: { result: QueryResult }) {
  const status = valueNumber(result.status)
  const successful = status >= 200 && status < 400
  const contentType = valueText(result.content_type, '未提供')
  return (
    <>
      <ResultStatus
        tone={successful ? 'success' : status >= 400 ? 'error' : 'warning'}
        title={successful ? `HTTP ${status}，请求成功` : `HTTP ${status || '未知'}，目标返回异常状态`}
        detail={`${valueText(result.method, 'GET')} ${valueText(result.url)}`}
      />
      <ResultMetrics items={[
        { label: '状态码', value: status || '—' },
        { label: '总耗时', value: formatDuration(result.duration) },
        { label: '响应大小', value: formatBytes(result.size) },
        { label: '内容类型', value: contentType.split(';')[0] || '—' },
      ]} />
      <DetailList items={[
        { label: '目标地址', value: <code>{valueText(result.url)}</code> },
        { label: '请求方法', value: valueText(result.method) },
        { label: '完整内容类型', value: contentType },
        { label: '节点截断', value: valueBoolean(result.truncated) ? '是' : '否' },
      ]} />
      <ResponseBody body={valueText(result.body, '')} contentType={contentType} truncated={valueBoolean(result.truncated)} />
    </>
  )
}

function SocketResult({ result, protocol }: { result: QueryResult; protocol: 'TCP' | 'UDP' }) {
  const success = valueBoolean(result.success)
  const confirmed = protocol === 'TCP' || valueBoolean(result.confirmed)
  const tone: ResultTone = !success ? 'error' : confirmed ? 'success' : 'warning'
  const title = !success
    ? `${protocol} 连接失败`
    : confirmed
      ? `${protocol} 目标已响应`
      : 'UDP 数据报已发送，未收到回包'
  return (
    <>
      <ResultStatus tone={tone} title={title} detail={valueText(result.error || result.note, undefined)} />
      <ResultMetrics items={[
        { label: '协议', value: protocol },
        { label: '目标', value: <code>{valueText(result.address)}</code> },
        { label: '耗时', value: formatDuration(result.duration) },
        { label: '连通状态', value: success ? (confirmed ? '已确认' : '已发送') : '失败' },
      ]} />
      <DetailList items={[
        { label: '目标地址', value: <code>{valueText(result.address)}</code> },
        { label: '节点协议', value: valueText(result.protocol, protocol.toLowerCase()).toUpperCase() },
        ...(protocol === 'UDP' ? [
          { label: '发送字节', value: valueText(result.bytes_written, '0') },
          { label: '接收字节', value: valueText(result.bytes_read, '0') },
        ] : []),
        { label: '错误原因', value: valueText(result.error, '无') },
      ]} />
    </>
  )
}

function TraceResult({ result }: { result: QueryResult }) {
  const hops = valueRecords(result.hops)
  const reached = valueBoolean(result.reached)
  const responding = hops.filter((hop) => !valueBoolean(hop.timed_out) && valueText(hop.address, '') !== '')
  const lastResponding = responding[responding.length - 1]
  return (
    <>
      <ResultStatus
        tone={reached ? 'success' : hops.length ? 'warning' : 'error'}
        title={reached ? '已追踪到目标地址' : hops.length ? '已返回部分路由' : '没有收到路由响应'}
        detail={`${valueText(result.target)} → ${valueText(result.resolved_ip)}`}
      />
      <ResultMetrics items={[
        { label: '目标 IP', value: <code>{valueText(result.resolved_ip)}</code> },
        { label: '经过跳数', value: valueText(result.hop_count, String(hops.length)) },
        { label: '总耗时', value: formatDuration(result.duration) },
        { label: '最终响应', value: lastResponding ? <code>{valueText(lastResponding.address)}</code> : '—' },
      ]} />
      <section className="query-result-section">
        <div className="query-section-heading"><h3>路由节点</h3><span>最多 {valueText(result.max_hops, '18')} 跳</span></div>
        <div className="query-record-table-wrap">
          <table className="query-record-table trace-route-table">
            <thead><tr><th>跳数</th><th>节点地址</th><th>往返延迟</th><th>状态</th></tr></thead>
            <tbody>{hops.map((hop, index) => {
              const timedOut = valueBoolean(hop.timed_out)
              return (
                <tr key={`${valueText(hop.hop, String(index + 1))}-${valueText(hop.address, 'timeout')}-${index}`}>
                  <td className="trace-hop-number">{valueText(hop.hop, String(index + 1))}</td>
                  <td>{timedOut ? <span className="trace-timeout">未响应</span> : <code>{valueText(hop.address)}</code>}</td>
                  <td className="trace-rtt">{timedOut ? '—' : formatDuration(hop.rtt_ms)}</td>
                  <td>{timedOut ? '超时' : valueText(hop.annotation, '已响应')}</td>
                </tr>
              )
            })}</tbody>
          </table>
        </div>
        {hops.length === 0 && <div className="query-empty-records">节点没有返回可解析的路由记录。</div>}
      </section>
    </>
  )
}

interface ParsedRecord {
  name: string
  ttl: string
  className: string
  type: string
  value: string
}

function parseRecord(record: string): ParsedRecord {
  const match = record.trim().match(/^(\S+)\s+(\d+)\s+(\S+)\s+(\S+)\s+(.+)$/)
  if (!match) return { name: '—', ttl: '—', className: '—', type: '—', value: record }
  return { name: match[1], ttl: match[2], className: match[3], type: match[4], value: match[5] }
}

function DnsRecordTable({ title, records }: { title: string; records: string[] }) {
  if (records.length === 0) return null
  return (
    <section className="query-result-section">
      <div className="query-section-heading"><h3>{title}</h3><span>{records.length} 条</span></div>
      <div className="query-record-table-wrap">
        <table className="query-record-table">
          <thead><tr><th>名称</th><th>TTL</th><th>类型</th><th>记录值</th></tr></thead>
          <tbody>{records.map((record, index) => {
            const parsed = parseRecord(record)
            return <tr key={`${record}-${index}`}><td><code>{parsed.name}</code></td><td>{parsed.ttl}</td><td>{parsed.type}</td><td><code>{parsed.value}</code></td></tr>
          })}</tbody>
        </table>
      </div>
    </section>
  )
}

function DnsResultView({ result, dnssec }: { result: QueryResult; dnssec: boolean }) {
  const answers = valueList(result.answers)
  const authorities = valueList(result.authorities)
  const additionals = valueList(result.additionals)
  const allRecords = [...answers, ...authorities, ...additionals]
  const rcode = valueNumber(result.rcode)
  const authenticated = valueBoolean(result.authenticated)
  const signedRecords = allRecords.filter((record) => /\sRRSIG\s/i.test(record)).length
  const dsRecords = allRecords.filter((record) => /\sDS\s/i.test(record)).length
  const dnskeyRecords = allRecords.filter((record) => /\sDNSKEY\s/i.test(record)).length
  const dnssecTone: ResultTone = authenticated ? 'success' : dnssec ? 'warning' : rcode === 0 ? 'success' : 'error'
  const title = dnssec
    ? authenticated ? 'DNSSEC 验证通过' : '解析器未确认 DNSSEC 验证'
    : rcode === 0 ? 'DNS 查询成功' : `DNS 返回 ${rcodeLabels[rcode] || `RCODE ${rcode}`}`
  return (
    <>
      <ResultStatus
        tone={dnssecTone}
        title={title}
        detail={dnssec && !authenticated ? 'AD 标志未设置，可能是域名未签名或所选解析器未完成验证。' : `${valueText(result.domain)} · ${valueText(result.record_type)}`}
      />
      <ResultMetrics items={[
        { label: '响应状态', value: rcodeLabels[rcode] || `RCODE ${rcode}` },
        { label: '查询耗时', value: formatDuration(result.duration) },
        { label: '回答记录', value: answers.length },
        { label: '解析服务器', value: <code>{valueText(result.server)}</code> },
      ]} />
      <DetailList items={[
        { label: '查询域名', value: <code>{valueText(result.domain)}</code> },
        { label: '记录类型', value: valueText(result.record_type) },
        { label: '权威响应', value: valueBoolean(result.authoritative) ? '是' : '否' },
        { label: '响应截断', value: valueBoolean(result.truncated) ? '是' : '否' },
      ]} />
      {dnssec && <section className="query-result-section dnssec-chain-section">
        <div className="query-section-heading"><h3>DNSSEC 链路</h3><span>{authenticated ? '已验证' : '未验证'}</span></div>
        <div className="dnssec-chain-grid">
          <div><span>AD 标志</span><strong>{authenticated ? '已设置' : '未设置'}</strong></div>
          <div><span>RRSIG 签名</span><strong>{signedRecords} 条</strong></div>
          <div><span>DS 记录</span><strong>{dsRecords} 条</strong></div>
          <div><span>DNSKEY</span><strong>{dnskeyRecords} 条</strong></div>
        </div>
      </section>}
      <DnsRecordTable title="回答记录" records={answers} />
      <DnsRecordTable title="权威记录" records={authorities} />
      <DnsRecordTable title="附加记录" records={additionals} />
      {allRecords.length === 0 && <div className="query-empty-records">本次查询没有返回记录。</div>}
    </>
  )
}

function AsnResult({ result }: { result: QueryResult }) {
  const asn = valueText(result.asn)
  const organization = valueText(result.organization)
  return (
    <>
      <ResultStatus tone={asn === '—' ? 'warning' : 'success'} title={asn === '—' ? '未找到 ASN 信息' : `${asn} 查询成功`} detail={organization} />
      <ResultMetrics items={[
        { label: 'AS 号码', value: asn },
        { label: '组织', value: organization },
        { label: '查询 IP', value: <code>{valueText(result.ip)}</code> },
      ]} />
      <DetailList items={[
        { label: '公网 IP', value: <code>{valueText(result.ip)}</code> },
        { label: 'AS 号码', value: asn },
        { label: '网络组织', value: organization },
      ]} />
    </>
  )
}

function parseWhois(raw: string) {
  const fields = new Map<string, string[]>()
  for (const line of raw.split(/\r?\n/)) {
    const match = line.match(/^\s*([^:%][^:]{1,80}):\s*(.+?)\s*$/)
    if (!match) continue
    const key = match[1].trim().toLowerCase()
    const values = fields.get(key) || []
    values.push(match[2].trim())
    fields.set(key, values)
  }
  const find = (...keys: string[]) => keys.flatMap((key) => fields.get(key) || [])
  return {
    registrar: find('registrar', 'sponsoring registrar')[0] || '未提供',
    registrant: find('registrant', 'registrant name')[0] || '未提供',
    registrantEmail: find('registrant contact email', 'registrant email')[0] || '未提供',
    created: find('creation date', 'created on', 'registered on', 'registration time', 'registration date', 'created date')[0] || '未提供',
    updated: find('updated date', 'last updated on', 'updated on', 'last updated date')[0] || '未提供',
    expires: find('registry expiry date', 'expiration date', 'registrar registration expiration date', 'expiry date', 'expiration time', 'expiry time', 'renewal date', 'paid-till')[0] || '未提供',
    roid: find('roid')[0] || '未提供',
    dnssec: find('dnssec')[0] || '未提供',
    statuses: find('domain status', 'status'),
    nameservers: [...new Set(find('name server', 'nserver'))],
  }
}

function WhoisResult({ result }: { result: QueryResult }) {
  const raw = valueText(result.raw, '')
  const fallback = parseWhois(raw)
  const structured = valueRecord(result.parsed)
  const structuredStatuses = valueList(structured.statuses)
  const structuredNameServers = valueList(structured.nameservers)
  const parsed = {
    registrar: valueText(structured.registrar, fallback.registrar),
    registrant: valueText(structured.registrant, fallback.registrant),
    registrantEmail: valueText(structured.registrant_email, fallback.registrantEmail),
    created: valueText(structured.created, fallback.created),
    updated: valueText(structured.updated, fallback.updated),
    expires: valueText(structured.expires, fallback.expires),
    roid: valueText(structured.roid, fallback.roid),
    dnssec: valueText(structured.dnssec, fallback.dnssec),
    statuses: structuredStatuses.length ? structuredStatuses : fallback.statuses,
    nameservers: structuredNameServers.length ? structuredNameServers : fallback.nameservers,
  }
  return (
    <>
      <ResultStatus tone={raw ? 'success' : 'warning'} title={raw ? 'WHOIS 查询成功' : 'WHOIS 未返回注册信息'} detail={valueText(result.domain)} />
      <ResultMetrics items={[
        { label: '域名', value: <code>{valueText(result.domain)}</code> },
        { label: '注册商', value: parsed.registrar },
        { label: '注册时间', value: formatWhoisDate(parsed.created) },
        { label: '到期时间', value: formatWhoisDate(parsed.expires) },
      ]} />
      <DetailList items={[
        { label: 'WHOIS 服务器', value: <code>{valueText(result.server)}</code> },
        { label: '注册人', value: parsed.registrant },
        { label: '联系邮箱', value: parsed.registrantEmail },
        { label: '更新时间', value: formatWhoisDate(parsed.updated) },
        { label: 'ROID', value: parsed.roid },
        { label: 'DNSSEC', value: parsed.dnssec },
      ]} />
      <section className="query-result-section whois-lists">
        <div>
          <h3>域名状态</h3>
          {parsed.statuses.length ? parsed.statuses.map((status, index) => <code key={`${status}-${index}`}>{status}</code>) : <span>未提供</span>}
        </div>
        <div>
          <h3>名称服务器</h3>
          {parsed.nameservers.length ? parsed.nameservers.map((server) => <code key={server}>{server}</code>) : <span>未提供</span>}
        </div>
      </section>
    </>
  )
}

// 渲染在 ResultMetrics 的 <strong> 内，只能使用短语内容元素。
function ScoreBadge({ value, tone, caption }: { value: string; tone: ResultTone; caption: string }) {
  return (
    <span className={`query-score-badge is-${tone}`}>
      <b>{value}</b>
      <small>{caption}</small>
    </span>
  )
}

function EmailRecordRow({ title, record, fallback }: { title: string; record?: EmailSecurityRecord; fallback: string }) {
  if (!record) return null
  const tone: ResultTone = record.status === 'pass' ? 'success' : record.status === 'fail' ? 'error' : 'warning'
  return (
    <tr>
      <td>{title}</td>
      <td><Tag theme={tone === 'success' ? 'success' : tone === 'error' ? 'danger' : 'warning'} variant="light-outline">{record.found ? '已配置' : '未配置'}</Tag></td>
      <td><code>{record.record || record.details?.join(' · ') || fallback}</code></td>
    </tr>
  )
}

function EmailCheckResult({ result }: { result: EmailSecurityResult }) {
  const tone: ResultTone = result.status === 'secure' ? 'success' : result.status === 'partial' ? 'warning' : 'error'
  const title = result.status === 'secure' ? '邮件安全配置完整'
    : result.status === 'partial' ? '邮件安全配置不完整'
    : result.status === 'blocked' ? '查询被拒绝' : '缺少关键邮件安全记录'
  return (
    <div className="query-parsed-result">
      <ResultStatus tone={tone} title={title} detail={`域名 ${result.domain || '—'}`} />
      <ResultMetrics items={[
        { label: '综合评分', value: <ScoreBadge value={String(result.score)} tone={tone} caption="满分 100" /> },
        { label: 'SPF', value: result.spf?.found ? '已配置' : '未配置' },
        { label: 'DKIM', value: result.dkim?.found ? '已配置' : '未配置' },
        { label: 'DMARC', value: result.dmarc?.found ? '已配置' : '未配置' },
      ]} />
      <section className="query-result-section">
        <div className="query-section-heading"><h3>记录明细</h3></div>
        <div className="query-record-table-wrap">
          <table className="query-record-table">
            <thead><tr><th>记录</th><th>状态</th><th>内容</th></tr></thead>
            <tbody>
              <EmailRecordRow title="SPF" record={result.spf} fallback="未找到 SPF 记录" />
              <EmailRecordRow title="DKIM" record={result.dkim} fallback="需要 selector 才能查询" />
              <EmailRecordRow title="DMARC" record={result.dmarc} fallback="未找到 DMARC 记录" />
            </tbody>
          </table>
        </div>
      </section>
    </div>
  )
}

function RblCheckResult({ result }: { result: RBLResult }) {
  const rows = result.blacklist ?? []
  const listed = rows.filter((row) => row.listed)
  const clean = result.status === 'clean' && listed.length === 0
  return (
    <div className="query-parsed-result">
      <ResultStatus
        tone={clean ? 'success' : 'error'}
        title={clean ? '未出现在任何黑名单' : `命中 ${listed.length} 个黑名单`}
        detail={`IP ${result.ip || '—'} · 共比对 ${rows.length} 个 RBL 服务`}
      />
      {rows.length > 0 && (
        <section className="query-result-section">
          <div className="query-section-heading"><h3>比对结果</h3><span>{rows.length} 项</span></div>
          <div className="query-record-table-wrap">
            <table className="query-record-table">
              <thead><tr><th>RBL 服务</th><th>状态</th><th>原因</th></tr></thead>
              <tbody>{rows.map((row) => (
                <tr key={row.rbl}>
                  <td><code>{row.rbl}</code></td>
                  <td><Tag theme={row.listed ? 'danger' : 'success'} variant="light-outline">{row.listed ? '已列入' : '干净'}</Tag></td>
                  <td>{row.reason || '—'}</td>
                </tr>
              ))}</tbody>
            </table>
          </div>
        </section>
      )}
    </div>
  )
}

function CdnCheckResult({ result }: { result: CDNResult }) {
  const blocked = result.cdn === 'blocked'
  const detected = Boolean(result.cdn) && result.cdn !== 'None' && !blocked
  return (
    <div className="query-parsed-result">
      <ResultStatus
        tone={blocked ? 'error' : detected ? 'success' : 'neutral'}
        title={blocked ? '目标被安全策略拦截' : detected ? `识别到 ${result.cdn}` : '未识别到 CDN'}
        detail={result.provider || (detected ? undefined : '后端依据 CNAME 与 IP 归属判断，未匹配到已知特征')}
      />
      <DetailList items={[
        { label: '查询目标', value: <code>{result.url || '—'}</code> },
        { label: 'CDN', value: result.cdn || '—' },
        { label: '厂商', value: result.provider || '—' },
        { label: 'CNAME', value: result.cname?.length ? result.cname.map((item) => <code key={item}>{item}</code>) : '—' },
        { label: '解析 IP', value: result.ips?.length ? result.ips.map((item) => <code key={item}>{item}</code>) : '—' },
      ]} />
    </div>
  )
}

function joinRegion(geo?: BatchLocationGeo) {
  if (!geo) return ''
  const parts = [geo.country, geo.administrative_area, geo.city]
    .map((part) => String(part || '').trim())
    .filter(Boolean)
  return parts.filter((part, index, all) => all.indexOf(part) === index).join(' · ')
}

// 按数据源可靠性依次回退：国内库优先，海外 IP 由 dbip/ip2region 兜底。
function batchRegion(entry: BatchLocationEntry) {
  if (entry.error) return entry.error
  for (const geo of [entry.geocn, entry.qqwry, entry.maxmind_city, entry.dbip_city]) {
    const region = joinRegion(geo)
    if (region) return region
  }
  if (typeof entry.ip2region === 'string') {
    const region = entry.ip2region.split('|')
      .map((part) => part.trim())
      .filter((part) => part && part !== '0')
      .slice(0, 3)
      .join(' · ')
    if (region) return region
  }
  return '—'
}

function BatchCheckResult({ result }: { result: BatchLocationResult }) {
  const rows = result.results ?? []
  const failed = rows.filter((row) => Boolean(row.error)).length
  return (
    <div className="query-parsed-result">
      <ResultStatus
        tone={failed === 0 ? 'success' : failed === rows.length ? 'error' : 'warning'}
        title={`成功解析 ${result.success} / ${result.total} 个地址`}
        detail="查询本站数据库，不经过检测节点"
      />
      {rows.length > 0 && (
        <section className="query-result-section">
          <div className="query-section-heading"><h3>归属地明细</h3><span>{rows.length} 条</span></div>
          <div className="query-record-table-wrap">
            <table className="query-record-table">
              <thead><tr><th>IP 地址</th><th>归属地</th><th>运营商 / ASN</th></tr></thead>
              <tbody>{rows.map((row, index) => (
                <tr key={`${row.ip || index}`}>
                  <td><code>{row.ip || '—'}</code></td>
                  <td>{batchRegion(row)}</td>
                  <td>{row.geocn?.isp || row.qqwry?.isp || valueText(valueRecord(row.maxmind_asn).org)}</td>
                </tr>
              ))}</tbody>
            </table>
          </div>
        </section>
      )}
    </div>
  )
}

function SecurityCheckResult({ result }: { result: SecurityHeadersResult }) {
  const rows = Object.entries(result.headers ?? {}).map(([name, info]) => ({ name, ...info }))
  const missing = rows.filter((row) => !row.present)
  const tone: ResultTone = result.grade === 'A' || result.grade === 'B'
    ? 'success'
    : result.grade === 'F' || result.grade === 'N/A' ? 'error' : 'warning'
  return (
    <div className="query-parsed-result">
      <ResultStatus
        tone={tone}
        title={missing.length === 0 ? '关键安全响应头齐全' : `缺失 ${missing.length} 个安全响应头`}
        detail={result.url || undefined}
      />
      <ResultMetrics items={[
        { label: '安全评级', value: <ScoreBadge value={result.grade} tone={tone} caption={`${result.score} / 100`} /> },
        { label: '检测项', value: `${rows.length} 个` },
        { label: '已设置', value: `${rows.length - missing.length} 个` },
        { label: '缺失', value: `${missing.length} 个` },
      ]} />
      {rows.length > 0 && (
        <section className="query-result-section">
          <div className="query-section-heading"><h3>响应头明细</h3><span>{rows.length} 项</span></div>
          <div className="query-record-table-wrap">
            <table className="query-record-table">
              <thead><tr><th>安全头</th><th>状态</th><th>值</th><th>说明</th></tr></thead>
              <tbody>{rows.map((row) => (
                <tr key={row.name}>
                  <td><code>{row.name}</code></td>
                  <td><Tag theme={row.present ? 'success' : 'danger'} variant="light-outline">{row.present ? '已设置' : '缺失'}</Tag></td>
                  <td><code>{row.value || '—'}</code></td>
                  <td>{row.info || '—'}</td>
                </tr>
              ))}</tbody>
            </table>
          </div>
        </section>
      )}
    </div>
  )
}

function LocalCheckResult({ kind, result }: { kind: LocalCheckKind; result: unknown }) {
  if (kind === 'email') return <EmailCheckResult result={result as EmailSecurityResult} />
  if (kind === 'rbl') return <RblCheckResult result={result as RBLResult} />
  if (kind === 'cdn') return <CdnCheckResult result={result as CDNResult} />
  if (kind === 'batch') return <BatchCheckResult result={result as BatchLocationResult} />
  if (kind === 'security') return <SecurityCheckResult result={result as SecurityHeadersResult} />
  return null
}

function NodeProbeResult({ probe, result }: { probe: ProbeKind; result: QueryResult }) {
  return (
    <div className="query-parsed-result">
      {probe === 'http' && <HttpResult result={result} />}
      {probe === 'tcp' && <SocketResult result={result} protocol="TCP" />}
      {probe === 'udp' && <SocketResult result={result} protocol="UDP" />}
      {probe === 'trace' && <TraceResult result={result} />}
      {probe === 'dns' && <DnsResultView result={result} dnssec={false} />}
      {probe === 'dnssec' && <DnsResultView result={result} dnssec />}
      {probe === 'asn' && <AsnResult result={result} />}
      {probe === 'whois' && <WhoisResult result={result} />}
      <RawResponse result={result} />
    </div>
  )
}

export function NetworkQueryPage() {
  const [searchParams, setSearchParams] = useSearchParams()
  const initialKind = (() => {
    const requested = searchParams.get('kind') || ''
    const known = queryOptions.flatMap((group) => group.children.map((item) => item.value))
    return (known.includes(requested) ? requested : 'http') as QueryKind
  })()

  const [queryNodes, setQueryNodes] = useState(fallbackQueryNodes)
  const [nodeId, setNodeId] = useState(fallbackQueryNodes[0].id)
  const [probe, setProbe] = useState<QueryKind>(initialKind)
  const [resultKind, setResultKind] = useState<QueryKind>(initialKind)
  const [target, setTarget] = useState(defaultTarget(initialKind))
  const [method, setMethod] = useState('GET')
  const [body, setBody] = useState('')
  const [port, setPort] = useState('443')
  const [dnsType, setDnsType] = useState('A')
  const [dnsServer, setDnsServer] = useState('1.1.1.1')
  const [result, setResult] = useState<QueryResult | null>(null)
  const [checkResult, setCheckResult] = useState<unknown>(null)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  const nodeLabel = queryNodes.find((item) => item.id === nodeId)?.label || nodeId
  const localMode = isLocalCheck(probe)

  const batchIps = useMemo(() => {
    if (probe !== 'batch') return []
    const seen = new Set<string>()
    for (const token of target.split(/[\s,;，、]+/)) {
      const value = token.trim()
      if (value) seen.add(value)
    }
    return [...seen]
  }, [probe, target])

  useEffect(() => {
    let active = true
    publicDiagnosticsApi.listNodes().then((response) => {
      if (!active || response.nodes.length === 0) return
      const ordered = [...response.nodes].sort((a, b) => (a.id === 'zaozhuang' ? -1 : b.id === 'zaozhuang' ? 1 : a.label.localeCompare(b.label, 'zh-CN')))
      setQueryNodes(ordered)
      if (!ordered.some((item) => item.id === nodeId)) setNodeId(ordered[0].id)
    }).catch(() => { /* Keep the known node list when discovery is unavailable. */ })
    return () => { active = false }
  }, [])

  const changeProbe = (value: unknown) => {
    const next = String(value) as QueryKind
    setProbe(next)
    setTarget(defaultTarget(next))
    if (next === 'tcp') setPort('443')
    if (next === 'udp') setPort('53')
    setResult(null)
    setCheckResult(null)
    setError('')
    const params = new URLSearchParams(searchParams)
    if (isLocalCheck(next)) params.set('kind', next)
    else params.delete('kind')
    setSearchParams(params, { replace: true })
  }

  const runLocalCheck = async (kind: LocalCheckKind, value: string) => {
    if (kind === 'email') return api.emailSecurity(value)
    if (kind === 'rbl') return api.rblCheck(value)
    if (kind === 'cdn') return api.cdnDetect(value)
    if (kind === 'security') return api.securityHeaders(value)
    return api.batchLocation(batchIps)
  }

  const runQuery = async () => {
    if (probe === 'batch') {
      if (batchIps.length === 0) {
        setError('请输入至少一个 IP 地址。')
        return
      }
      if (batchIps.length > BATCH_LIMIT) {
        setError(`单次最多查询 ${BATCH_LIMIT} 个 IP，当前 ${batchIps.length} 个。`)
        return
      }
    } else if (!target.trim()) {
      setError(`请输入${targetLabel(probe)}`)
      return
    }
    if ((probe === 'tcp' || probe === 'udp') && (!Number.isInteger(Number(port)) || Number(port) < 1 || Number(port) > 65535)) {
      setError('端口必须是 1 到 65535 之间的整数。')
      return
    }
    setLoading(true)
    setError('')
    setResult(null)
    setCheckResult(null)
    try {
      if (isLocalCheck(probe)) {
        let data: unknown
        if (isNodeCapable(probe)) {
          // 节点检测：走公共代理
          data = await publicDiagnosticsApi.run(nodeId, probe as PublicProbeKind, { target: target.trim() })
        } else {
          // 主站检测：直接调用
          data = await runLocalCheck(probe, target.trim())
        }
        setResultKind(probe)
        setCheckResult(data as QueryResult)
        return
      }
      let payload: Record<string, unknown>
      if (probe === 'http') payload = { url: target.trim(), method, body }
      else if (probe === 'tcp' || probe === 'udp') payload = { host: target.trim(), port: Number(port) }
      else if (probe === 'trace') payload = { host: target.trim(), max_hops: 18 }
      else if (probe === 'dns' || probe === 'dnssec') payload = { domain: target.trim(), type: dnsType, server: dnsServer.trim() }
      else if (probe === 'asn') payload = { ip: target.trim() }
      else payload = { domain: target.trim() }
      const data = await publicDiagnosticsApi.run(nodeId, probe, payload)
      setResultKind(probe)
      setResult(data)
    } catch (requestError) {
      setError(friendlyError(requestError))
    } finally {
      setLoading(false)
    }
  }

  const hasResult = localMode ? checkResult !== null : result !== null
  const resultBadge = isLocalCheck(resultKind) ? (isNodeCapable(resultKind) ? nodeLabel : '主站后端') : nodeLabel
  const runningLabel = localMode ? (isNodeCapable(probe) ? nodeLabel : '主站后端') : nodeLabel

  return (
    <>
      <Card className="node-query-shell" bordered={false} title="查询参数" actions={<span className="query-service-status"><i />公共服务可用</span>}>
        <form className="node-query-grid" onSubmit={(event) => { event.preventDefault(); void runQuery() }}>
          <label><span>查询类型</span><Select value={probe} options={queryOptions} onChange={changeProbe} /></label>
          {localMode && !isNodeCapable(probe)
            ? <label><span>数据来源</span><Input name="network-scope" value="主站后端（不经过检测节点）" readOnly /></label>
            : <label><span>检测节点</span><Select value={nodeId} options={queryNodes.map((item) => ({ label: item.label, value: item.id }))} onChange={(value) => setNodeId(String(value))} /></label>}
          {probe === 'batch'
            ? <label className="query-body-field"><span>{targetLabel(probe)}</span><Textarea name="network-batch" value={target} onChange={setTarget} placeholder={`每行一个 IP，也可用逗号或空格分隔，最多 ${BATCH_LIMIT} 个`} autosize={{ minRows: 4, maxRows: 10 }} /></label>
            : <label className="query-target-field"><span>{targetLabel(probe)}</span><Input name="network-target" value={target} onChange={setTarget} placeholder={defaultTarget(probe)} /></label>}
          {probe === 'http' && <label><span>HTTP 方法</span><Select value={method} options={[{ label: 'GET', value: 'GET' }, { label: 'POST', value: 'POST' }]} onChange={(value) => setMethod(String(value))} /></label>}
          {(probe === 'tcp' || probe === 'udp') && <label><span>端口</span><Input name="network-port" value={port} onChange={setPort} type="number" /></label>}
          {(probe === 'dns' || probe === 'dnssec') && <>
            <label><span>记录类型</span><Select value={dnsType} options={['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'DS', 'DNSKEY', 'RRSIG', 'NSEC', 'NSEC3'].map((value) => ({ label: value, value }))} onChange={(value) => setDnsType(String(value))} /></label>
            <label><span>递归 DNS 服务器</span><Input name="network-dns-server" value={dnsServer} onChange={setDnsServer} placeholder="1.1.1.1 或 8.8.8.8:53" /></label>
          </>}
          {probe === 'http' && method === 'POST' && <label className="query-body-field"><span>请求体</span><Textarea name="network-body" value={body} onChange={setBody} placeholder="可选，最多 4 KB" autosize={{ minRows: 3, maxRows: 7 }} maxlength={4096} /></label>}
          <div className="query-submit-row">
            {probe === 'batch' && <span className={`query-batch-meter${batchIps.length > BATCH_LIMIT ? ' is-over' : ''}`}>已识别 {batchIps.length} / {BATCH_LIMIT} 个地址</span>}
            <Button type="submit" theme="primary" loading={loading} icon={<SearchIcon />}>运行查询</Button>
          </div>
        </form>
      </Card>
      <NodeError message={error} />
      <Card
        className="node-result-card parsed-result-card"
        bordered={false}
        title="查询结果"
        actions={hasResult ? <Tag theme="success" variant="light" icon={<CheckCircleIcon />}>{resultBadge}</Tag> : undefined}
      >
        {loading
          ? <div className="node-result-state"><Loading size="small" /><span>{runningLabel} 正在执行{isLocalCheck(probe) ? kindLabels[probe] : '查询'}</span></div>
          : isLocalCheck(resultKind) && checkResult !== null
            ? <LocalCheckResult kind={resultKind} result={checkResult} />
            : !isLocalCheck(resultKind) && result !== null
              ? <NodeProbeResult probe={resultKind} result={result} />
              : <div className="node-result-state"><FileSearchIcon /><span>填写参数后运行查询</span></div>}
      </Card>
    </>
  )
}
