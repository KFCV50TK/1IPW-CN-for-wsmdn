export type Stack = 'v4' | 'v6'

export interface IpLocationResult {
  ip?: string
  ip2region?: unknown
  qqwry?: Record<string, unknown> | string
  maxmind_city?: Record<string, unknown> | string
  maxmind_asn?: Record<string, unknown> | string
  geocn?: Record<string, unknown> | string
  dbip_city?: Record<string, unknown> | string
  bilibili?: Record<string, unknown> | string
  [key: string]: unknown
}

export interface WebsiteDetail {
  host_record: string
  http_status_code: number
  https_status_code: number
  dns_lookup_time: number
  tcp_connect_time: number
  http_connect_time: number
  first_byte_time: number
  total_time: number
  page_size: number
  download_speed: number
  is_reachable: boolean
}

export interface WebsiteResult {
  ipv4?: WebsiteDetail
  ipv6?: WebsiteDetail
}

export interface SslDetail {
  cert_validity_days: number
  cert_start_time: string
  cert_end_time: string
  http_version: string
  host_record: string
  https_status_code: number
  total_time: number
  download_speed: number
  domain: string
  issuer_organization: string[]
  issuer_common_name: string
  subject_common_name: string
  is_expired: boolean
  is_reachable: boolean
}

export interface SslResult {
  ipv4?: SslDetail
  ipv6?: SslDetail
}

export interface DnsResult {
  domain: string
  record: string[]
  ttl: number
  duration: number
}

export interface TcpResult {
  ip: string
  port: string
  success: boolean
  rtt: number
  error: string
  timestamp: string
}

export interface TcpStats {
  ip: string
  port: string
  sent: number
  success: number
  loss_rate: number
  max_rtt: number
  min_rtt: number
  avg_rtt: number
  results: TcpResult[]
}

export interface TcpingResult {
  ipv4?: TcpStats
  ipv6?: TcpStats
}

export interface SpeedResult {
  version: string
  host_record: string
  http_status_code: number
  https_status_code: number
  dns_lookup_time: number
  tcp_connect_time: number
  http_connect_time: number
  first_byte_time: number
  total_time: number
  page_size: number
  download_speed: number
  message: string
  headers: string
  is_reachable: boolean
}

export type NodeResultStatus = 'idle' | 'loading' | 'success' | 'error'

export interface NodeResult<T> {
  id: string
  label: string
  stack: Stack | 'dual'
  status: NodeResultStatus
  data?: T
  error?: string
}

export interface HistoryItem {
  id: string
  label: string
  value: string
  tool: string
  at: number
}

export interface NodeAdminKey {
  id: string
  name: string
  created_at: string
  revoked_at?: string
}

export interface NodeAdminKeyCreated extends NodeAdminKey {
  key: string
}

// ========== 新增功能类型 ==========

// 邮件安全检测
export interface EmailSecurityResult {
  domain: string
  spf?: EmailSecurityRecord
  dkim?: EmailSecurityRecord
  dmarc?: EmailSecurityRecord
  score: number
  status: 'secure' | 'partial' | 'vulnerable' | 'blocked'
}

export interface EmailSecurityRecord {
  found: boolean
  record?: string
  status: 'pass' | 'fail' | 'warning' | 'unknown'
  details?: string[]
}

// IP黑名单查询
export interface RBLResult {
  ip: string
  blacklist: RBLRecord[]
  status: 'clean' | 'listed'
}

export interface RBLRecord {
  rbl: string
  listed: boolean
  reason?: string
}

// CDN识别
export interface CDNResult {
  url: string
  cdn: string
  provider: string
  ips: string[]
  cname: string[]
}

// 批量IP查询
export interface BatchLocationRequest {
  ips: string[]
}

// 字段名依据线上 /v1/batch-location 实测响应，勿改成 province/location。
export interface BatchLocationGeo {
  country?: string
  country_code?: string
  administrative_area?: string
  city?: string
  isp?: string
  division_code?: string
  latitude?: number | string
  longitude?: number | string
}

export interface BatchLocationEntry {
  ip: string
  error?: string
  geocn?: BatchLocationGeo
  qqwry?: BatchLocationGeo
  maxmind_city?: BatchLocationGeo
  dbip_city?: BatchLocationGeo
  bilibili?: BatchLocationGeo
  ip2region?: string
  [key: string]: unknown
}

export interface BatchLocationResult {
  results: BatchLocationEntry[]
  total: number
  success: number
}

// HTTP安全头检测
export interface SecurityHeadersResult {
  url: string
  headers: Record<string, HeaderInfo>
  score: number
  grade: 'A' | 'B' | 'C' | 'D' | 'F' | 'N/A'
}

export interface HeaderInfo {
  present: boolean
  value?: string
  status: 'pass' | 'fail' | 'warning'
  info?: string
}

// CT Log查询
export interface CTLogResult {
  domain: string
  certificates: CTLogCert[]
  total: number
}

export interface CTLogCert {
  issuer: string
  common_name: string
  not_before: string
  not_after: string
  serial_number: string
}
