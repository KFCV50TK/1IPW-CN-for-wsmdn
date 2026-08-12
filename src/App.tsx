import Alert from 'tdesign-react/es/alert'
import Button from 'tdesign-react/es/button'
import Card from 'tdesign-react/es/card'
import Empty from 'tdesign-react/es/empty'
import Input from 'tdesign-react/es/input'
import Layout from 'tdesign-react/es/layout'
import Loading from 'tdesign-react/es/loading'
import Menu from 'tdesign-react/es/menu'
import Progress from 'tdesign-react/es/progress'
import Select from 'tdesign-react/es/select'
import Table from 'tdesign-react/es/table'
import Tag from 'tdesign-react/es/tag'
import {
  CertificateIcon,
  CheckCircleIcon,
  CloseIcon,
  CopyIcon,
  DashboardIcon,
  DataSearchIcon,
  ErrorCircleIcon,
  FileSearchIcon,
  InternetIcon,
  LocationIcon,
  MenuIcon,
  MoonIcon,
  RefreshIcon,
  RootListIcon,
  SearchIcon,
  SunnyIcon,
  TaskTimeIcon,
  ThunderIcon,
} from 'tdesign-icons-react'
import { createContext, lazy, Suspense, useCallback, useContext, useEffect, useMemo, useState, type ReactElement, type ReactNode } from 'react'
import { Link, Navigate, Outlet, Route, Routes, useLocation, useNavigate } from 'react-router-dom'
import { firstAvailable, localApi, nodeApi } from './api'
import { nodeStackLabel, sourceNodes, type SourceNode } from './nodes'
const NetworkQueryPage = lazy(() => import('./NodeTools').then((module) => ({ default: module.NetworkQueryPage })))
const SpeedTestPage = lazy(() => import('./SpeedTest').then((module) => ({ default: module.SpeedTestPage })))
import type {
  DnsResult,
  HistoryItem,
  IpLocationResult,
  NodeResult,
  SpeedResult,
  SslDetail,
  SslResult,
  Stack,
  TcpingResult,
  WebsiteDetail,
  WebsiteResult,
} from './types'

type Theme = 'light' | 'dark'
type ToolId = 'home' | 'location' | 'website' | 'ssl' | 'dns' | 'tcping' | 'speed' | 'speedtest' | 'network'

interface HistoryContextValue {
  history: HistoryItem[]
  addHistory: (item: Omit<HistoryItem, 'id' | 'at'>) => void
}

const HistoryContext = createContext<HistoryContextValue | null>(null)

function createNodeRows<T>(nodes: readonly SourceNode[]): NodeResult<T>[] {
  return nodes.map((node) => ({
    id: node.id,
    label: node.label,
    stack: node.stack,
    status: 'idle',
  }))
}

function useNodeResults<T>(nodes: readonly SourceNode[]) {
  const nodeKey = nodes.map((node) => node.id).join('|')
  const initialRows = useMemo(() => createNodeRows<T>(nodes), [nodeKey])
  const [rows, setRows] = useState<NodeResult<T>[]>(initialRows)
  const [running, setRunning] = useState(false)

  useEffect(() => {
    setRows(initialRows)
    setRunning(false)
  }, [initialRows])

  const runAll = useCallback(async (load: (node: SourceNode) => Promise<T>) => {
    setRunning(true)
    setRows(createNodeRows<T>(nodes).map((row) => ({ ...row, status: 'loading' })))
    await Promise.all(nodes.map(async (node) => {
      try {
        const data = await load(node)
        setRows((current) => current.map((row) => row.id === node.id
          ? { ...row, status: 'success', data, error: undefined }
          : row))
      } catch (error) {
        const raw = error instanceof Error ? error.message : '节点请求失败'
        const message = /failed to fetch|networkerror/i.test(raw) ? '节点当前不可达' : raw
        setRows((current) => current.map((row) => row.id === node.id
          ? { ...row, status: 'error', data: undefined, error: message }
          : row))
      }
    }))
    setRunning(false)
  }, [nodeKey])

  return { rows, running, runAll }
}

const toolItems: Array<{ value: ToolId; label: string; description: string; icon: ReactElement; path: string }> = [
  { value: 'home', label: '工作台', description: '系统概览与最近查询', icon: <DashboardIcon />, path: '/' },
  { value: 'location', label: 'IP 地址查询', description: '多数据源归属地与 ASN', icon: <LocationIcon />, path: '/location' },
  { value: 'website', label: '网站检测', description: 'HTTP/HTTPS 双栈可达性', icon: <InternetIcon />, path: '/website' },
  { value: 'ssl', label: 'SSL 检查', description: '证书、有效期与颁发者', icon: <CertificateIcon />, path: '/ssl' },
  { value: 'dns', label: 'DNS 解析', description: 'A / AAAA / MX 等记录', icon: <RootListIcon />, path: '/dns' },
  { value: 'tcping', label: 'TCPing', description: '端口连接与延迟统计', icon: <TaskTimeIcon />, path: '/tcping' },
  { value: 'speed', label: '网站测速', description: '响应时间与下载速度', icon: <DataSearchIcon />, path: '/speed' },
  { value: 'speedtest', label: '速度测试', description: '就近节点实时测速', icon: <ThunderIcon />, path: '/speedtest' },
  { value: 'network', label: '网络查询', description: 'HTTP、DNS 与链路诊断', icon: <FileSearchIcon />, path: '/network' },
]

function useHistoryStore(): HistoryContextValue {
  const [history, setHistory] = useState<HistoryItem[]>(() => {
    try {
      return JSON.parse(window.localStorage.getItem('ipw-history') || '[]') as HistoryItem[]
    } catch {
      return []
    }
  })

  const addHistory = useCallback((item: Omit<HistoryItem, 'id' | 'at'>) => {
    setHistory((current) => {
      const next = [{ ...item, id: `${Date.now()}-${Math.random()}`, at: Date.now() }, ...current]
        .slice(0, 12)
      window.localStorage.setItem('ipw-history', JSON.stringify(next))
      return next
    })
  }, [])

  return { history, addHistory }
}

function currentTool(pathname: string): ToolId {
  if (pathname === '/') return 'home'
  const match = toolItems.find((item) => item.path !== '/' && pathname.startsWith(item.path))
  return match?.value || 'home'
}

function locatorTrail(tool: ToolId): string {
  if (tool === 'home') return '工作台 · 系统概览'
  const item = toolItems.find((entry) => entry.value === tool)
  return item ? `工具箱 · ${item.label}` : '工具箱'
}

function App() {
  const historyStore = useHistoryStore()
  const [theme, setTheme] = useState<Theme>(() => (window.localStorage.getItem('ipw-theme') as Theme) || 'light')

  useEffect(() => {
    document.documentElement.dataset.theme = theme
    document.documentElement.classList.toggle('dark', theme === 'dark')
    document.documentElement.setAttribute('theme-mode', theme)
    document.documentElement.style.colorScheme = theme
    window.localStorage.setItem('ipw-theme', theme)
    const meta = document.querySelector<HTMLMetaElement>('meta[name="theme-color"]')
    meta?.setAttribute('content', theme === 'dark' ? '#0f141d' : '#f3f6fa')
  }, [theme])

  return (
    <HistoryContext.Provider value={historyStore}>
      <Routes>
        <Route element={<AppShell theme={theme} onThemeChange={setTheme} />}>
          <Route path="/" element={<Dashboard />} />
          <Route path="/location" element={<LocationPage />} />
          <Route path="/website" element={<WebsitePage />} />
          <Route path="/ssl" element={<SslPage />} />
          <Route path="/dns" element={<DnsPage />} />
          <Route path="/tcping" element={<TcpingPage />} />
          <Route path="/speed" element={<SpeedPage />} />
          <Route path="/speedtest" element={
            <Suspense fallback={<div className="status-block"><Loading size="small" /> <span>正在加载速度测试…</span></div>}>
              <SpeedTestPage />
            </Suspense>
          } />
          <Route path="/network" element={
            <Suspense fallback={<div className="status-block"><Loading size="small" /> <span>正在加载网络查询工具…</span></div>}>
              <NetworkQueryPage />
            </Suspense>
          } />
          <Route path="/email" element={<Navigate to="/network?kind=email" replace />} />
          <Route path="/rbl" element={<Navigate to="/network?kind=rbl" replace />} />
          <Route path="/cdn" element={<Navigate to="/network?kind=cdn" replace />} />
          <Route path="/batch" element={<Navigate to="/network?kind=batch" replace />} />
          <Route path="/security" element={<Navigate to="/network?kind=security" replace />} />

        </Route>
      </Routes>
    </HistoryContext.Provider>
  )
}

function AppShell({ theme, onThemeChange }: { theme: Theme; onThemeChange: (theme: Theme) => void }) {
  const navigate = useNavigate()
  const location = useLocation()
  const [mobileOpen, setMobileOpen] = useState(false)
  const selected = currentTool(location.pathname)

  useEffect(() => {
    if (!mobileOpen) return

    const previousOverflow = document.body.style.overflow
    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') setMobileOpen(false)
    }

    document.body.style.overflow = 'hidden'
    window.addEventListener('keydown', handleKeyDown)
    return () => {
      document.body.style.overflow = previousOverflow
      window.removeEventListener('keydown', handleKeyDown)
    }
  }, [mobileOpen])

  const menu = (
    <Menu
      value={selected}
      theme={theme}
      className="side-menu"
      onChange={(value) => {
        const item = toolItems.find((entry) => entry.value === value)
        if (item) navigate(item.path)
        setMobileOpen(false)
      }}
    >
      <div className="menu-section-label">工具箱</div>
      {toolItems.map((item) => (
        <Menu.MenuItem key={item.value} value={item.value} icon={item.icon}>
          <span className="menu-item-copy">
            <strong>{item.label}</strong>
            <span>{item.description}</span>
          </span>
        </Menu.MenuItem>
      ))}
    </Menu>
  )

  return (
    <Layout className="app-layout">
      <Layout.Header className="app-header">
        <div className="header-inner">
          <Button
            className="mobile-menu-button"
            variant="text"
            shape="square"
            aria-label="打开导航"
            aria-controls="mobile-navigation"
            aria-expanded={mobileOpen}
            onClick={() => setMobileOpen(true)}
            icon={<MenuIcon />}
          />
          <Link to="/" className="brand-lockup" aria-label="1IPW.CN 工作台">
            <span className="brand-mark">1</span>
            <span>
              <strong>1IPW.CN</strong>
              <small>网络诊断工具箱</small>
            </span>
          </Link>
          <div className="header-context">
            <span className="header-context-dot" />
            <span>原生检测节点</span>
            <code>{sourceNodes.dns.length} 个在线来源</code>
          </div>
          <div className="header-actions">
            <Button
              variant="text"
              shape="square"
              aria-label={theme === 'dark' ? '切换浅色模式' : '切换深色模式'}
              onClick={() => onThemeChange(theme === 'dark' ? 'light' : 'dark')}
              icon={theme === 'dark' ? <SunnyIcon /> : <MoonIcon />}
            />
          </div>
        </div>
      </Layout.Header>
      <Layout>
        <Layout.Aside className="app-aside">{menu}</Layout.Aside>
        <Layout.Content className="app-content">
          <main id="main-content" className="content-inner">
            <div className="page-locator"><span className="page-locator-trail">{locatorTrail(selected)}</span></div>
            <div className="route-view" key={location.pathname}><Outlet /></div>
          </main>
          <footer className="app-footer">
            <span>1IPW.CN 网络诊断工具箱</span>
            <span>仅调用公开后端接口 · 后端项目 GPL-3.0</span>
            <a href="https://github.com/nomdn/ipw-cn" target="_blank" rel="noreferrer">查看后端源码</a>
          </footer>
        </Layout.Content>
      </Layout>
      <div
        id="mobile-navigation"
        className={`mobile-nav-layer${mobileOpen ? ' is-open' : ''}`}
        role="dialog"
        aria-modal={mobileOpen ? true : undefined}
        aria-hidden={!mobileOpen}
        aria-label="移动端导航"
      >
        <button className="mobile-nav-backdrop" aria-label="关闭导航" onClick={() => setMobileOpen(false)} />
        <aside className="mobile-nav-panel">
          <div className="mobile-nav-title">
            <strong>工具箱</strong>
            <Button
              variant="text"
              shape="square"
              aria-label="关闭导航"
              onClick={() => setMobileOpen(false)}
              icon={<CloseIcon />}
            />
          </div>
          {menu}
        </aside>
      </div>
    </Layout>
  )
}


function QueryPanel({ children, onSubmit, loading, submitLabel = '开始查询' }: { children: ReactNode; onSubmit: () => void; loading?: boolean; submitLabel?: string }) {
  return (
    <Card className="query-panel" bordered={false}>
      <div className="query-fields">{children}</div>
      <Button theme="primary" loading={loading} onClick={onSubmit} icon={<SearchIcon />}>{submitLabel}</Button>
    </Card>
  )
}

function ToolStatus({ loading, error }: { loading: boolean; error: string }) {
  if (loading) return <div className="status-block"><Loading size="small" /> <span>正在请求后端，请稍候…</span></div>
  if (error) return <Alert theme="error" icon={<ErrorCircleIcon />} message={error} />
  return null
}

function EmptyResult({ text = '输入参数并开始查询，结果会显示在这里。' }: { text?: string }) {
  return <div className="empty-result"><Empty description={text} /></div>
}

function StatusTag({ ok, children }: { ok: boolean; children: ReactNode }) {
  return <Tag theme={ok ? 'success' : 'danger'} variant="light-outline" icon={ok ? <CheckCircleIcon /> : <ErrorCircleIcon />}>{children}</Tag>
}

function Dashboard() {
  const { history } = useHistoryStoreFallback()
  const [location, setLocation] = useState<IpLocationResult | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  const load = useCallback(() => {
    setLoading(true)
    setError('')
    localApi.myLocation()
      .then((data) => setLocation(data))
      .catch((err: Error) => setError(err.message))
      .finally(() => setLoading(false))
  }, [])

  useEffect(() => { load() }, [load])

  const ip = location?.ip || '—'
  const region = formatLocationRegion(location)

  return (
    <>
      <div className="page-hero"><h1>{greeting()}</h1></div>
      <div className="metric-grid">
        <Card className="metric-card metric-card--primary" bordered={false}>
          <div className="metric-head">
            <span className="metric-label">当前地区</span>
            <Button variant="text" shape="square" size="small" aria-label="刷新状态" icon={<RefreshIcon />} onClick={load} loading={loading} />
          </div>
          <div className="metric-value metric-value--region">{loading ? '…' : region}</div>
          <div className="metric-foot">公网 IP：{loading ? '正在获取' : ip}</div>
        </Card>
      </div>
      {error && <Alert className="dashboard-alert" theme="warning" message={`无法连接后端：${error}`} />}
      <CurlQueryCard />
      <div className="dashboard-grid">
        <Card className="section-card quick-card" title="常用工具" bordered={false}>
          <div className="quick-tools">
            {toolItems.slice(1).map((item) => (
              <Link to={item.path} className="quick-tool" key={item.value}>
                <span className="quick-tool-icon">{item.icon}</span>
                <span><strong>{item.label}</strong><small>{item.description}</small></span>
              </Link>
            ))}
          </div>
        </Card>
        <Card className="section-card history-card" title="最近查询" bordered={false}>
          {history.length === 0 ? <EmptyResult text="还没有查询记录" /> : (
            <div className="history-list">
              {history.slice(0, 6).map((item) => (
                <Link to={item.tool} className="history-row" key={item.id}>
                  <span className="history-type">{item.label}</span>
                  <code>{item.value}</code>
                  <time>{relativeTime(item.at)}</time>
                </Link>
              ))}
            </div>
          )}
        </Card>
      </div>
    </>
  )
}

function CurlQueryCard() {
  const command = 'curl https://1ipw.cn'
  const [copied, setCopied] = useState(false)

  const copyCommand = async () => {
    try {
      await navigator.clipboard.writeText(command)
      setCopied(true)
      window.setTimeout(() => setCopied(false), 1800)
    } catch {
      setCopied(false)
    }
  }

  return (
    <Card className="section-card curl-card" title="命令行 IP 查询" bordered={false}>
      <p>在终端直接返回当前公网 IP，不需要 API Key。</p>
      <div className="curl-command">
        <code>{command}</code>
        <Button size="small" variant="outline" icon={<CopyIcon />} onClick={() => void copyCommand()}>
          {copied ? '已复制' : '复制命令'}
        </Button>
      </div>
      <small>也可使用 <code>curl https://1ipw.cn/ip</code>。</small>
    </Card>
  )
}

function useHistoryStoreFallback(): HistoryContextValue {
  const context = useContext(HistoryContext)
  if (!context) throw new Error('HistoryContext is not available')
  return context
}

function LocationPage() {
  const { addHistory } = useHistoryStoreFallback()
  const [value, setValue] = useState('')
  const [result, setResult] = useState<IpLocationResult | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const run = async (target = value) => {
    const ip = target.trim()
    if (!ip) { setError('请输入 IPv4 或 IPv6 地址。'); return }
    setLoading(true); setError(''); setResult(null)
    try { const data = await localApi.location(ip); setResult(data); addHistory({ label: 'IP 查询', value: ip, tool: '/location' }) }
    catch (err) { setError((err as Error).message) }
    finally { setLoading(false) }
  }
  return (
    <>
      <QueryPanel onSubmit={() => void run()} loading={loading} submitLabel="查询地址">
        <Input value={value} onChange={setValue} placeholder="例如：1.1.1.1 或 2400:3200::1" clearable onEnter={() => void run()} />
        <Button variant="outline" onClick={() => { setValue(''); setResult(null); setError('') }}>清空</Button>
      </QueryPanel>
      <ToolStatus loading={loading} error={error} />
      {!loading && !error && result && <IpResult result={result} />}
      {!loading && !error && !result && <EmptyResult />}
    </>
  )
}

function IpResult({ result }: { result: IpLocationResult }) {
  const rows = Object.entries(result).filter(([key]) => key !== 'ip').map(([source, value]) => ({ source, value }))
  return <Card className="result-card" bordered={false} title={<span>查询结果 <code className="title-code">{result.ip || '—'}</code></span>}>
    {rows.length === 0 ? <EmptyResult text="后端没有返回数据源结果" /> : <Table rowKey="source" data={rows} columns={[{ colKey: 'source', title: '数据源', cell: ({ row }) => <strong>{sourceLabel(row.source)}</strong> }, { colKey: 'value', title: '返回信息', cell: ({ row }) => <JsonValue value={row.value} /> }]} bordered={false} hover />}
  </Card>
}

function WebsitePage() {
  const { addHistory } = useHistoryStoreFallback()
  const [value, setValue] = useState('https://example.com')
  const [result, setResult] = useState<WebsiteResult | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const run = async () => {
    if (!value.trim()) { setError('请输入要检测的网站地址。'); return }
    setLoading(true); setError(''); setResult(null)
    try { const { data } = await firstAvailable(sourceNodes.core, (node) => nodeApi.website(node, value)); setResult(data); addHistory({ label: '网站检测', value, tool: '/website' }) }
    catch (err) { setError((err as Error).message) }
    finally { setLoading(false) }
  }
  return <>
    <QueryPanel onSubmit={() => void run()} loading={loading} submitLabel="开始检测"><Input value={value} onChange={setValue} placeholder="https://example.com" onEnter={() => void run()} /></QueryPanel>
    <ToolStatus loading={loading} error={error} />
    {!loading && !error && result && <WebsiteResultView result={result} />}
    {!loading && !error && !result && <EmptyResult />}
  </>
}

function WebsiteResultView({ result }: { result: WebsiteResult }) {
  const metrics: Array<{ label: string; key: keyof WebsiteDetail; format?: (value: unknown) => string }> = [
    { label: '主机记录', key: 'host_record' },
    { label: 'HTTP 状态码', key: 'http_status_code' },
    { label: 'HTTPS 状态码', key: 'https_status_code' },
    { label: 'DNS 查询', key: 'dns_lookup_time', format: formatMs },
    { label: 'TCP 连接', key: 'tcp_connect_time', format: formatMs },
    { label: 'HTTP 连接', key: 'http_connect_time', format: formatMs },
    { label: '首字节', key: 'first_byte_time', format: formatMs },
    { label: '总耗时', key: 'total_time', format: formatMs },
    { label: '页面大小', key: 'page_size', format: formatBytes },
    { label: '下载速度', key: 'download_speed', format: formatSpeed },
  ]
  return <Card className="result-card" bordered={false} title="双栈检测结果">
    <div className="stack-summary"><StackSummary label="IPv4" detail={result.ipv4} /><StackSummary label="IPv6" detail={result.ipv6} /></div>
    <div className="comparison-table-wrap"><table className="comparison-table"><thead><tr><th>检测项目</th><th>IPv4</th><th>IPv6</th></tr></thead><tbody>{metrics.map((metric) => <tr key={metric.key}><th>{metric.label}</th><td>{metric.format ? metric.format(result.ipv4?.[metric.key]) : formatCell(result.ipv4?.[metric.key])}</td><td>{metric.format ? metric.format(result.ipv6?.[metric.key]) : formatCell(result.ipv6?.[metric.key])}</td></tr>)}</tbody></table></div>
  </Card>
}

function StackSummary({ label, detail }: { label: string; detail?: WebsiteDetail }) {
  const ok = Boolean(detail?.is_reachable)
  return <div className={`stack-summary-item ${ok ? 'is-ok' : 'is-down'}`}><div><span className="stack-label">{label}</span><StatusTag ok={ok}>{ok ? '可达' : '不可达'}</StatusTag></div><strong>{detail?.total_time ? formatMs(detail.total_time) : '—'}</strong><small>{detail?.host_record || '未返回结果'}</small></div>
}

function SslPage() {
  const { addHistory } = useHistoryStoreFallback()
  const [value, setValue] = useState('https://example.com')
  const [result, setResult] = useState<SslResult | null>(null)
  const [loading, setLoading] = useState(false); const [error, setError] = useState('')
  const run = async () => { if (!value.trim()) { setError('请输入网站地址。'); return }; setLoading(true); setError(''); setResult(null); try { const { data } = await firstAvailable(sourceNodes.core, (node) => nodeApi.ssl(node, value)); setResult(data); addHistory({ label: 'SSL 检查', value, tool: '/ssl' }) } catch (err) { setError((err as Error).message) } finally { setLoading(false) } }
  return <>
    <QueryPanel onSubmit={() => void run()} loading={loading} submitLabel="检查证书"><Input value={value} onChange={setValue} placeholder="https://example.com" onEnter={() => void run()} /></QueryPanel>
    <ToolStatus loading={loading} error={error} />
    {!loading && !error && result && <SslResultView result={result} />}
    {!loading && !error && !result && <EmptyResult />}
  </>
}

function SslResultView({ result }: { result: SslResult }) {
  return <div className="result-stack-grid"><SslCard label="IPv4" detail={result.ipv4} /><SslCard label="IPv6" detail={result.ipv6} /></div>
}

function SslCard({ label, detail }: { label: string; detail?: SslDetail }) {
  if (!detail) return <Card className="result-card" bordered={false} title={label}><EmptyResult text="没有返回结果" /></Card>
  const days = Math.max(0, detail.cert_validity_days || 0)
  const healthy = detail.is_reachable && !detail.is_expired
  return <Card className="result-card ssl-card" bordered={false} title={<span>{label} <StatusTag ok={healthy}>{detail.is_expired ? '已过期或无效' : '有效'}</StatusTag></span>}>
    <div className="ssl-domain"><span>证书域名</span><strong>{detail.domain || detail.subject_common_name || '—'}</strong></div>
    <div className="ssl-days"><div><span>剩余天数</span><strong>{detail.cert_validity_days} 天</strong></div><Progress percentage={Math.round(Math.min(100, days / 365 * 100))} theme="line" status={healthy ? 'active' : 'error'} /></div>
    <dl className="detail-list"><dt>颁发者</dt><dd>{detail.issuer_organization?.join(', ') || detail.issuer_common_name || '—'}</dd><dt>生效时间</dt><dd>{formatDate(detail.cert_start_time)}</dd><dt>到期时间</dt><dd>{formatDate(detail.cert_end_time)}</dd><dt>HTTP 版本</dt><dd>{detail.http_version || '—'}</dd><dt>主机记录</dt><dd>{detail.host_record || '—'}</dd><dt>HTTPS 状态</dt><dd>{detail.https_status_code || '—'}</dd></dl>
  </Card>
}

const dnsOptions = ['a', 'aaaa', 'cname', 'mx', 'ns', 'ptr', 'srv', 'txt', 'caa'].map((value) => ({ label: value.toUpperCase(), value }))

function DnsPage() {
  const { addHistory } = useHistoryStoreFallback()
  const [domain, setDomain] = useState('example.com'); const [type, setType] = useState('a'); const [error, setError] = useState('')
  const { rows, running, runAll } = useNodeResults<DnsResult>(sourceNodes.dns)
  const run = async () => {
    if (!domain.trim()) { setError('请输入域名或 PTR 查询用的 IP。'); return }
    setError('')
    addHistory({ label: `DNS ${type.toUpperCase()}`, value: domain, tool: '/dns' })
    await runAll((node) => nodeApi.dns(node, type, domain))
  }
  return <>
    <QueryPanel onSubmit={() => void run()} loading={running} submitLabel="多节点解析"><Input value={domain} onChange={setDomain} placeholder={type === 'ptr' ? '例如：1.1.1.1' : '例如：example.com'} onEnter={() => void run()} /><Select value={type} options={dnsOptions} onChange={(value) => setType(String(value))} /></QueryPanel>
    <div className="dns-type-strip">{dnsOptions.map((item) => <button className={item.value === type ? 'is-active' : ''} key={item.value} onClick={() => setType(item.value)}>{item.label}</button>)}</div>
    {error && <ToolStatus loading={false} error={error} />}
    {!error && <DnsNodesResult rows={rows} type={type} />}
  </>
}

function DnsNodesResult({ rows, type }: { rows: NodeResult<DnsResult>[]; type: string }) {
  return <Card className="result-card node-result-card" bordered={false} title={`多节点 ${type.toUpperCase()} 记录`}>
    <div className="node-table-wrap"><table className="node-table"><thead><tr><th>解析节点</th><th>记录</th><th>记录数</th><th>TTL</th><th>耗时</th></tr></thead><tbody>
      {rows.map((row) => <tr key={row.id}>
        <th><span>{row.label}</span><small>{nodeStackLabel(row.stack)}</small></th>
        <td className="node-records">{row.status === 'loading' ? <Loading size="small" text="解析中" /> : row.status === 'error' ? <span className="node-error">{row.error}</span> : row.status === 'idle' ? '等待查询' : row.data?.record?.length ? row.data.record.slice(0, 5).map((record) => <code key={record}>{record}</code>) : '没有记录'}</td>
        <td>{row.status === 'success' ? row.data?.record?.length ?? 0 : '—'}</td>
        <td>{row.status === 'success' ? row.data?.ttl || '—' : '—'}</td>
        <td>{row.status === 'success' ? formatMs(row.data?.duration) : '—'}</td>
      </tr>)}
    </tbody></table></div>
  </Card>
}

function TcpingPage() {
  const { addHistory } = useHistoryStoreFallback()
  const [host, setHost] = useState('example.com'); const [port, setPort] = useState('443'); const [count, setCount] = useState('4'); const [version, setVersion] = useState<Stack>('v4'); const [error, setError] = useState('')
  const nodes = version === 'v4' ? sourceNodes.tcping.v4 : sourceNodes.tcping.v6
  const { rows, running, runAll } = useNodeResults<TcpingResult>(nodes)
  const run = async () => {
    const numericPort = Number(port); const numericCount = Number(count)
    if (!host.trim()) { setError('请输入主机名或 IP。'); return }
    if (!Number.isInteger(numericPort) || numericPort < 1 || numericPort > 65535) { setError('端口必须是 1 到 65535 之间的整数。'); return }
    if (!Number.isInteger(numericCount) || numericCount < 1 || numericCount > 20) { setError('次数必须是 1 到 20 之间的整数。'); return }
    setError('')
    addHistory({ label: `TCPing ${version}`, value: `${host}:${port}`, tool: '/tcping' })
    await runAll((node) => nodeApi.tcping(node, host, numericPort, numericCount))
  }
  return <>
    <QueryPanel onSubmit={() => void run()} loading={running} submitLabel="多节点测试"><Input value={host} onChange={setHost} placeholder="主机名或 IP" onEnter={() => void run()} /><Input value={port} onChange={setPort} placeholder="端口" type="number" /><Input value={count} onChange={setCount} placeholder="次数（1–20）" type="number" /><Select value={version} options={[{ label: 'IPv4', value: 'v4' }, { label: 'IPv6', value: 'v6' }]} onChange={(value) => setVersion(String(value) as Stack)} /></QueryPanel>
    {error && <ToolStatus loading={false} error={error} />}
    {!error && <TcpNodesResult rows={rows} version={version} />}
  </>
}

function TcpNodesResult({ rows, version }: { rows: NodeResult<TcpingResult>[]; version: Stack }) {
  return <Card className="result-card node-result-card" bordered={false} title={`${version.toUpperCase()} 多节点 TCPing`}>
    <div className="node-table-wrap"><table className="node-table tcp-node-table"><thead><tr><th>检测节点</th><th>解析 IP</th><th>发送 / 成功</th><th>丢包率</th><th>最低</th><th>平均</th><th>最高</th></tr></thead><tbody>
      {rows.map((row) => {
        const stats = row.data?.[version === 'v4' ? 'ipv4' : 'ipv6']
        return <tr key={row.id}>
          <th><span>{row.label}</span><small>{nodeStackLabel(row.stack)}</small></th>
          {row.status === 'loading' ? <td colSpan={6}><Loading size="small" text="测试中" /></td> : row.status === 'error' ? <td colSpan={6} className="node-error">{row.error}</td> : row.status === 'idle' ? <td colSpan={6}>等待测试</td> : !stats ? <td colSpan={6} className="node-error">节点未返回 {version.toUpperCase()} 数据</td> : <>
            <td><code>{stats.ip || '—'}</code></td><td>{stats.sent} / {stats.success}</td><td>{stats.loss_rate ?? '—'}%</td><td>{formatMs(stats.min_rtt)}</td><td>{formatMs(stats.avg_rtt)}</td><td>{formatMs(stats.max_rtt)}</td>
          </>}
        </tr>
      })}
    </tbody></table></div>
  </Card>
}

function SpeedPage() {
  const { addHistory } = useHistoryStoreFallback()
  const [url, setUrl] = useState('https://example.com'); const [version, setVersion] = useState<Stack>('v4'); const [error, setError] = useState('')
  const nodes = version === 'v4' ? sourceNodes.speed.v4 : sourceNodes.speed.v6
  const { rows, running, runAll } = useNodeResults<SpeedResult>(nodes)
  const run = async () => {
    if (!url.trim()) { setError('请输入网站地址。'); return }
    setError('')
    addHistory({ label: `测速 ${version}`, value: url, tool: '/speed' })
    await runAll((node) => nodeApi.speed(node, version, url))
  }
  return <>
    <QueryPanel onSubmit={() => void run()} loading={running} submitLabel="多节点测速"><Input value={url} onChange={setUrl} placeholder="https://example.com" onEnter={() => void run()} /><Select value={version} options={[{ label: 'IPv4', value: 'v4' }, { label: 'IPv6', value: 'v6' }]} onChange={(value) => setVersion(String(value) as Stack)} /></QueryPanel>
    {error && <ToolStatus loading={false} error={error} />}
    {!error && <SpeedNodesResult rows={rows} version={version} />}
  </>
}

function SpeedNodesResult({ rows, version }: { rows: NodeResult<SpeedResult>[]; version: Stack }) {
  return <Card className="result-card node-result-card" bordered={false} title={`${version.toUpperCase()} 多节点测速`}>
    <div className="node-table-wrap"><table className="node-table speed-node-table"><thead><tr><th>测速节点</th><th>解析 IP</th><th>HTTP</th><th>HTTPS</th><th>总耗时</th><th>DNS</th><th>首字节</th><th>页面大小</th><th>下载速度</th></tr></thead><tbody>
      {rows.map((row) => <tr key={row.id}>
        <th><span>{row.label}</span><small>{nodeStackLabel(row.stack)}</small></th>
        {row.status === 'loading' ? <td colSpan={8}><Loading size="small" text="测速中" /></td> : row.status === 'error' ? <td colSpan={8} className="node-error">{row.error}</td> : row.status === 'idle' ? <td colSpan={8}>等待测速</td> : !row.data ? <td colSpan={8} className="node-error">节点没有返回结果</td> : <>
          <td><code>{row.data.host_record || '—'}</code></td><td>{row.data.http_status_code || '—'}</td><td>{row.data.https_status_code || '—'}</td><td>{formatMs(row.data.total_time)}</td><td>{formatMs(row.data.dns_lookup_time)}</td><td>{formatMs(row.data.first_byte_time)}</td><td>{formatBytes(row.data.page_size)}</td><td>{formatSpeed(row.data.download_speed)}</td>
        </>}
      </tr>)}
    </tbody></table></div>
  </Card>
}

// ip2region 是竖线分隔字符串：国家|省|市|ISP|国家码
function formatIp2Region(raw: string) {
  const parts = raw.split('|').map((part) => part.trim()).filter((part) => part && part !== '0')
  if (parts.length === 0) return raw
  const seen = parts.filter((part, index, all) => all.indexOf(part) === index)
  return seen.join(' · ')
}

// 把归属地对象拼成一行可读文字，附带 ISP/ASN 等补充信息。
function formatLocationValue(record: Record<string, unknown>) {
  const text = (key: string) => String(record[key] ?? '').trim()
  const region = [text('country'), text('administrative_area'), text('city')]
    .filter(Boolean)
    .filter((part, index, all) => all.indexOf(part) === index)
    .join(' · ')

  const extras: string[] = []
  const isp = text('isp')
  if (isp) extras.push(isp)
  const asn = text('asn')
  const org = text('org')
  if (asn && org) extras.push(`${asn} ${org}`)
  else if (asn) extras.push(asn)
  else if (org) extras.push(org)

  const lat = text('latitude')
  const lon = text('longitude')
  const hasCoords = lat && lon && Number(lat) !== 0 && Number(lon) !== 0

  if (!region && extras.length === 0) return null
  return { region, extras, coords: hasCoords ? `${lat}, ${lon}` : '' }
}

function JsonValue({ value }: { value: unknown }) {
  if (typeof value === 'string') {
    const trimmed = value.trim()
    if (trimmed.startsWith('error:')) return <span className="value-error">{trimmed}</span>
    if (trimmed === 'not loaded' || trimmed === '') return <span className="value-muted">未加载</span>
    // ip2region 这类竖线分隔字符串按分隔符还原成地区层级
    if (trimmed.includes('|')) return <span className="location-region">{formatIp2Region(trimmed)}</span>
    return <span>{trimmed}</span>
  }

  if (value && typeof value === 'object' && !Array.isArray(value)) {
    const parsed = formatLocationValue(value as Record<string, unknown>)
    if (!parsed) return <span className="value-muted">无数据</span>
    return (
      <div className="location-value">
        {parsed.region && <span className="location-region">{parsed.region}</span>}
        {parsed.extras.length > 0 && <small>{parsed.extras.join(' · ')}</small>}
        {parsed.coords && <small className="location-coords">{parsed.coords}</small>}
      </div>
    )
  }

  if (value === null || value === undefined) return <span className="value-muted">无数据</span>
  return <span>{String(value)}</span>
}

function greeting() {
  const hour = new Date().getHours()
  if (hour < 6) return '深夜好'
  if (hour < 12) return '早上好'
  if (hour < 18) return '下午好'
  return '晚上好'
}

function formatLocationRegion(result: IpLocationResult | null) {
  if (!result) return '正在定位'
  const sources = ['geocn', 'dbip_city', 'qqwry', 'maxmind_city', 'bilibili']
  for (const source of sources) {
    const value = result[source]
    if (!value || typeof value !== 'object') continue
    const record = value as Record<string, unknown>
    const region = [record.country, record.administrative_area, record.city]
      .map((part) => String(part || '').trim())
      .filter(Boolean)
      .filter((part, index, parts) => parts.indexOf(part) === index)
      .join(' · ')
    if (region) return region
  }
  if (typeof result.ip2region === 'string') {
    const region = result.ip2region.split('|').map((part) => part.trim()).filter(Boolean).slice(0, 3).join(' · ')
    if (region) return region
  }
  return '地区未知'
}

function sourceLabel(source: string) {
  const labels: Record<string, string> = { ip2region: 'IP2Region', qqwry: '纯真 QQWry', maxmind_city: 'MaxMind City', maxmind_asn: 'MaxMind ASN', geocn: 'GeoCN', dbip_city: 'DB-IP City', bilibili: 'Bilibili' }
  return labels[source] || source
}

function formatCell(value: unknown) { return value === undefined || value === null || value === '' ? '—' : String(value) }
function formatMs(value: unknown) { const n = Number(value); return !Number.isFinite(n) || n < 0 ? '—' : `${n.toFixed(n < 10 ? 2 : 0)} ms` }
function formatBytes(value: unknown) { const n = Number(value); if (!Number.isFinite(n) || n <= 0) return '—'; if (n < 1024) return `${n} B`; if (n < 1024 ** 2) return `${(n / 1024).toFixed(1)} KB`; return `${(n / 1024 ** 2).toFixed(2)} MB` }
function formatSpeed(value: unknown) { const n = Number(value); return !Number.isFinite(n) || n <= 0 ? '—' : `${n.toFixed(n < 10 ? 2 : 1)} KB/s` }
function formatDate(value: unknown) { if (!value) return '—'; const date = new Date(String(value)); return Number.isNaN(date.getTime()) ? String(value) : date.toLocaleString('zh-CN', { hour12: false }) }
function relativeTime(value: number) { const delta = Math.max(0, Date.now() - value); if (delta < 60_000) return '刚刚'; if (delta < 3_600_000) return `${Math.floor(delta / 60_000)} 分钟前`; return `${Math.floor(delta / 3_600_000)} 小时前` }


export default App
