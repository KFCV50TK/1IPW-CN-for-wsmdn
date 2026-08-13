import Button from 'tdesign-react/es/button'
import Card from 'tdesign-react/es/card'
import Loading from 'tdesign-react/es/loading'
import Select from 'tdesign-react/es/select'
import Tag from 'tdesign-react/es/tag'
import { CheckCircleIcon, ErrorCircleIcon, ThunderIcon, UploadIcon, DownloadIcon } from 'tdesign-icons-react'
import { useCallback, useEffect, useRef, useState } from 'react'

interface SpeedTestNode {
  id: string
  label: string
  path: string
}

// 6 个自有节点，统一走主站同源反代路径（与侧边栏节点目录一致）。
const speedTestNodes: SpeedTestNode[] = [
  { id: 'shiyan', label: '中国 湖北 十堰 电信', path: '/shiyan-node/' },
  { id: 'hongkong2', label: '中国 香港 VpsQuan', path: '/hongkong2-node/' },
  { id: 'jdcloud', label: '中国 北京 京东云 三网BGP', path: '/jdcloud-node/' },
  { id: 'zaozhuang', label: '中国 山东 枣庄 移动/电信双线', path: '/manage-node/zaozhuang/' },
  { id: 'hongkong', label: '中国 香港 Cogent', path: '/manage-node/hongkong/' },
  { id: 'xian2', label: '中国 陕西 西安二 电信', path: '/xian2-node/' },
  { id: 'huawei', label: '中国 华为云 北京', path: '/huawei-node/' },
]

const TEST_DURATION_MS = 15_000 // 每阶段固定 15 秒
const DOWNLOAD_BYTES = 300 * 1024 * 1024 // 足够 15 秒高速下载的载荷
const UPLOAD_CHUNK = 64 * 1024 // crypto.getRandomValues 单次上限 64KB
const UPLOAD_SIZE = 256 * 1024 * 1024 // 256 MiB，供 15 秒高速上传
const GAUGE_RADIUS = 110
const GAUGE_CIRCUMFERENCE = 2 * Math.PI * GAUGE_RADIUS

interface Sample {
  t: number // 相对起点毫秒
  mbps: number
}

function nodeUrl(node: SpeedTestNode, path: string) {
  return `${node.path.replace(/\/$/, '')}${path}`
}

function formatMbps(mbps: number) {
  if (!Number.isFinite(mbps) || mbps <= 0) return '0'
  if (mbps >= 1000) return mbps.toFixed(0)
  if (mbps >= 100) return mbps.toFixed(1)
  return mbps.toFixed(2)
}

function formatMbPerSec(mbps: number) {
  if (!Number.isFinite(mbps) || mbps <= 0) return '0 MB/s'
  return `${(mbps / 8).toFixed(mbps >= 800 ? 0 : 2)} MB/s`
}

function randomBlob(size: number): Blob {
  // crypto.getRandomValues 单次最多 65536 字节，按 64KB 分片生成。
  const maxChunk = 64 * 1024
  const parts: BlobPart[] = []
  let remaining = size
  while (remaining > 0) {
    const n = Math.min(maxChunk, remaining)
    const chunk = new Uint8Array(n)
    crypto.getRandomValues(chunk)
    parts.push(chunk)
    remaining -= n
  }
  return new Blob(parts, { type: 'application/octet-stream' })
}

async function measureLatency(node: SpeedTestNode, timeoutMs = 6000): Promise<{ latency: number; ok: boolean }> {
  const controller = new AbortController()
  const timer = window.setTimeout(() => controller.abort(), timeoutMs)
  const start = performance.now()
  try {
    const response = await fetch(nodeUrl(node, '/'), { cache: 'no-store', signal: controller.signal })
    return { ok: response.ok, latency: performance.now() - start }
  } catch {
    return { ok: false, latency: Number.POSITIVE_INFINITY }
  } finally {
    window.clearTimeout(timer)
  }
}

type TestStatus = 'probing' | 'ready' | 'downloading' | 'uploading' | 'done' | 'error'

export function SpeedTestPage() {
  const [latencies, setLatencies] = useState<Record<string, number>>({})
  const [selectedId, setSelectedId] = useState<string>('auto')
  const [status, setStatus] = useState<TestStatus>('probing')
  const [elapsedMs, setElapsedMs] = useState(0)
  const [currentMbps, setCurrentMbps] = useState(0)
  const [downloadMbps, setDownloadMbps] = useState(0)
  const [uploadMbps, setUploadMbps] = useState(0)
  const [downloadSamples, setDownloadSamples] = useState<Sample[]>([])
  const [uploadSamples, setUploadSamples] = useState<Sample[]>([])
  const [error, setError] = useState('')
  const abortRef = useRef<AbortController | null>(null)

  const autoNode = useCallback((): SpeedTestNode | null => {
    let best: SpeedTestNode | null = null
    let bestLatency = Number.POSITIVE_INFINITY
    for (const node of speedTestNodes) {
      const latency = latencies[node.id]
      if (typeof latency === 'number' && Number.isFinite(latency) && latency < bestLatency) {
        bestLatency = latency
        best = node
      }
    }
    return best
  }, [latencies])

  const selectedNode = (() => {
    if (selectedId === 'auto') return autoNode()
    return speedTestNodes.find((node) => node.id === selectedId) || null
  })()

  const probe = useCallback(async () => {
    setStatus('probing')
    setError('')
    setDownloadMbps(0)
    setUploadMbps(0)
    setElapsedMs(0)
    setCurrentMbps(0)
    setDownloadSamples([])
    setUploadSamples([])
    const results = await Promise.all(speedTestNodes.map(async (node) => {
      const result = await measureLatency(node)
      return { id: node.id, ...result }
    }))
    const next: Record<string, number> = {}
    for (const result of results) {
      if (result.ok) next[result.id] = result.latency
    }
    setLatencies(next)
    if (Object.keys(next).length === 0) {
      setStatus('error')
      setError('无法连接任何测速节点，请稍后重试。')
      return
    }
    setStatus('ready')
  }, [])

  useEffect(() => {
    void probe()
    return () => {
      abortRef.current?.abort()
    }
  }, [probe])

  // 每秒采样：瞬时速度 = (本次采样增量) / 采样间隔
  const startSampler = useCallback((
    getCount: () => number,
    onSample: (mbps: number) => void,
    onDone: (samples: Sample[]) => void,
  ): { stop: () => void; samples: Sample[] } => {
    const samples: Sample[] = []
    const start = performance.now()
    let lastCount = 0
    let lastTime = start
    const timer = window.setInterval(() => {
      const now = performance.now()
      const count = getCount()
      const elapsed = now - start
      const deltaBytes = count - lastCount
      const deltaSec = (now - lastTime) / 1000
      const mbps = deltaSec > 0 ? (deltaBytes * 8) / 1e6 / deltaSec : 0
      samples.push({ t: elapsed, mbps })
      lastCount = count
      lastTime = now
      setElapsedMs(elapsed)
      setCurrentMbps(mbps)
      onSample(mbps)
      if (elapsed >= TEST_DURATION_MS) {
        window.clearInterval(timer)
        onDone(samples)
      }
    }, 1000)
    return {
      stop: () => window.clearInterval(timer),
      samples,
    }
  }, [])

  const runDownload = useCallback(async (node: SpeedTestNode) => {
    const controller = new AbortController()
    abortRef.current = controller
    let received = 0
    const start = performance.now()
    const sampler = startSampler(
      () => received,
      () => undefined,
      (samples) => setDownloadSamples([...samples]),
    )
    // 固定时长：15 秒内持续拉取载荷。高速节点提前传完一个载荷就继续拉下一个，
    // 直到 15 秒整（到时主动 abort）。
    const timer = window.setTimeout(() => controller.abort(), TEST_DURATION_MS)
    try {
      // eslint-disable-next-line no-constant-condition
      while (performance.now() - start < TEST_DURATION_MS) {
        const response = await fetch(nodeUrl(node, `/v1/speedtest-payload?bytes=${DOWNLOAD_BYTES}`), {
          cache: 'no-store',
          signal: controller.signal,
        })
        if (!response.ok || !response.body) {
          throw new Error(`下载测速请求失败（HTTP ${response.status}）`)
        }
        const reader = response.body.getReader()
        // eslint-disable-next-line no-constant-condition
        while (true) {
          const { done, value } = await reader.read()
          if (done) break
          received += value ? value.length : 0
        }
      }
    } catch (err) {
      // 15 秒到后主动中断下载流属于正常结束
      if (!controller.signal.aborted) {
        throw err
      }
    } finally {
      window.clearTimeout(timer)
      sampler.stop()
      controller.abort()
    }
    setCurrentMbps(0)
    return (received * 8) / 1e6 / (TEST_DURATION_MS / 1000)
  }, [startSampler])

  const runUpload = useCallback(async (node: SpeedTestNode) => {
    const controller = new AbortController()
    abortRef.current = controller
    const payload = randomBlob(UPLOAD_SIZE)
    const start = performance.now()
    let sent = 0
    const sampler = startSampler(
      () => sent,
      () => undefined,
      (samples) => setUploadSamples([...samples]),
    )
    // 固定时长：15 秒内持续上传。一份载荷传完（高速节点可能很快）就继续传下一份，
    // 直到 15 秒整（到时 abort 当前请求）。
    const currentXhrRef: { current: XMLHttpRequest | null } = { current: null }
    const timer = window.setTimeout(() => {
      try { currentXhrRef.current?.abort() } catch { /* ignore */ }
    }, TEST_DURATION_MS)
    try {
      // eslint-disable-next-line no-constant-condition
      while (performance.now() - start < TEST_DURATION_MS) {
        const baseSent = sent
        await new Promise<void>((resolve, reject) => {
          const xhr = new XMLHttpRequest()
          currentXhrRef.current = xhr
          xhr.open('POST', nodeUrl(node, '/v1/speedtest-upload'))
          xhr.setRequestHeader('Content-Type', 'application/octet-stream')
          xhr.upload.onprogress = (event) => {
            if (event.loaded > 0) sent = baseSent + event.loaded
          }
          xhr.onload = () => resolve()
          xhr.onabort = () => resolve() // 15 秒到主动终止，按已发送字节计算
          xhr.onerror = () => reject(new Error('上传测速请求失败'))
          try {
            xhr.send(payload)
          } catch (err) {
            reject(err instanceof Error ? err : new Error('上传测速请求失败'))
          }
        })
        sent = baseSent + payload.size
      }
    } finally {
      window.clearTimeout(timer)
      sampler.stop()
      try { currentXhrRef.current?.abort() } catch { /* ignore */ }
    }
    setCurrentMbps(0)
    return (sent * 8) / 1e6 / (TEST_DURATION_MS / 1000)
  }, [startSampler])

  const run = useCallback(async () => {
    const node = selectedNode
    if (!node) {
      setStatus('error')
      setError('没有可用节点，请先重测节点。')
      return
    }
    abortRef.current?.abort()
    setStatus('downloading')
    setError('')
    setElapsedMs(0)
    setCurrentMbps(0)
    setDownloadMbps(0)
    setUploadMbps(0)
    setDownloadSamples([])
    setUploadSamples([])
    try {
      const download = await runDownload(node)
      setDownloadMbps(download)
      setElapsedMs(0)
      setCurrentMbps(0)

      setStatus('uploading')
      const upload = await runUpload(node)
      setUploadMbps(upload)
      setElapsedMs(TEST_DURATION_MS)
      setStatus('done')
    } catch (err) {
      if (abortRef.current?.signal.aborted) return
      setStatus('error')
      setError(err instanceof Error ? err.message : '测速失败')
    }
  }, [selectedNode, runDownload, runUpload])

  const latency = selectedNode ? latencies[selectedNode.id] : undefined
  const progress = status === 'downloading' || status === 'uploading'
    ? Math.min(elapsedMs / TEST_DURATION_MS, 1)
    : status === 'done' ? 1 : 0
  const statusText = status === 'downloading' ? `下载测速中 ${Math.min(Math.ceil(elapsedMs / 1000), 15)}/15 秒`
    : status === 'uploading' ? `上传测速中 ${Math.min(Math.ceil(elapsedMs / 1000), 15)}/15 秒` : ''
  const liveSamples = status === 'downloading' ? downloadSamples : status === 'uploading' ? uploadSamples : []

  return (
    <Card className="section-card speedtest-card" bordered={false}>
      <div className="speedtest-head">
        <div>
          <h2 className="speedtest-title"><ThunderIcon /> 速度测试</h2>
          <p className="speedtest-subtitle">自动选择距离你最近的节点，测试下行与上行速度（每阶段固定 15 秒）。</p>
        </div>
        <div className="speedtest-actions">
          <Select
            value={selectedId}
            options={[
              { label: '自动选择最近节点', value: 'auto' },
              ...speedTestNodes.map((node) => ({ label: node.label, value: node.id })),
            ]}
            onChange={(value) => setSelectedId(String(value))}
            className="speedtest-node-select"
          />
        </div>
      </div>

      <div className="speedtest-stage">
        <div className="speedtest-gauge-wrap">
          <svg viewBox="0 0 260 260" className="speedtest-gauge" aria-hidden="true">
            <circle cx="130" cy="130" r={GAUGE_RADIUS} className="speedtest-gauge-track" />
            <circle
              cx="130"
              cy="130"
              r={GAUGE_RADIUS}
              className={`speedtest-gauge-arc${status === 'uploading' ? ' is-uploading' : ''}`}
              strokeDasharray={`${GAUGE_CIRCUMFERENCE}`}
              strokeDashoffset={GAUGE_CIRCUMFERENCE * (1 - progress)}
              transform="rotate(-90 130 130)"
            />
          </svg>
          <div className="speedtest-gauge-center">
            <strong>{status === 'probing' ? '—' : formatMbps(currentMbps)}</strong>
            <span>Mbps</span>
            {statusText && <small className="speedtest-live">{statusText}</small>}
          </div>
        </div>

        <div className="speedtest-meta">
          {status === 'probing' && (
            <div className="status-block"><Loading size="small" /> <span>正在探测就近节点…</span></div>
          )}
          {status === 'error' && (
            <div className="speedtest-error"><ErrorCircleIcon /> {error}</div>
          )}
          {status !== 'probing' && (
            <>
              <div className="speedtest-node-line">
                <span className="speedtest-meta-label">当前节点</span>
                <Tag theme="primary" variant="light-outline" icon={<ThunderIcon />}>
                  {selectedNode ? selectedNode.label : '无可用节点'}
                </Tag>
              </div>
              <div className="speedtest-node-line">
                <span className="speedtest-meta-label">节点延迟</span>
                <span className="speedtest-meta-value">{latency !== undefined ? `${Math.round(latency)} ms` : '—'}</span>
              </div>
              {status === 'downloading' || status === 'uploading' ? (
                <div className="speedtest-node-line">
                  <span className="speedtest-meta-label">实时速度</span>
                  <span className="speedtest-meta-value">{formatMbps(currentMbps)} Mbps</span>
                </div>
              ) : null}
              {status === 'done' && (
                <>
                  <div className="speedtest-node-line">
                    <span className="speedtest-meta-label"><DownloadIcon /> 平均下载</span>
                    <span className="speedtest-meta-value">{formatMbps(downloadMbps)} Mbps（{formatMbPerSec(downloadMbps)}）</span>
                  </div>
                  <div className="speedtest-node-line">
                    <span className="speedtest-meta-label"><UploadIcon /> 平均上传</span>
                    <span className="speedtest-meta-value">{formatMbps(uploadMbps)} Mbps（{formatMbPerSec(uploadMbps)}）</span>
                  </div>
                </>
              )}
            </>
          )}
        </div>
      </div>

      {(status === 'downloading' || status === 'uploading') && liveSamples.length >= 2 && (
        <div className="speedtest-chart-wrap">
          <SpeedChart
            samples={liveSamples}
            label={status === 'downloading' ? '下行波动' : '上行波动'}
            color={status === 'downloading' ? 'var(--td-brand-color)' : 'var(--td-success-color)'}
          />
        </div>
      )}

      {status === 'done' && (
        <div className="speedtest-charts">
          <SpeedChart samples={downloadSamples} label="下行波动" color="var(--td-brand-color)" />
          <SpeedChart samples={uploadSamples} label="上行波动" color="var(--td-success-color)" />
        </div>
      )}

      <div className="speedtest-footer">
        <Button
          theme="primary"
          size="large"
          loading={status === 'downloading' || status === 'uploading'}
          disabled={status === 'probing' || !selectedNode}
          onClick={() => void run()}
          icon={<ThunderIcon />}
        >
          {status === 'done' ? '重新测速' : status === 'downloading' || status === 'uploading' ? '测速中' : '开始测速'}
        </Button>
        {status === 'ready' || status === 'done' ? (
          <Button variant="text" onClick={() => void probe()}>重新探测节点</Button>
        ) : null}
        {status === 'done' && <CheckCircleIcon className="speedtest-ok" />}
      </div>
    </Card>
  )
}

function SpeedChart({ samples, label, color }: { samples: Sample[]; label: string; color: string }) {
  const width = 560
  const height = 170
  const padX = 34
  const padTop = 18
  const padBottom = 26
  const max = Math.max(1, ...samples.map((s) => s.mbps)) * 1.15
  const maxText = Math.max(1, ...samples.map((s) => s.mbps))
  const points = samples.map((s) => {
    const x = padX + (s.t / TEST_DURATION_MS) * (width - padX * 2)
    const y = height - padBottom - (s.mbps / max) * (height - padTop - padBottom)
    return `${x.toFixed(1)},${y.toFixed(1)}`
  }).join(' ')
  const area = points ? `${padX},${height - padBottom} ${points} ${width - padX},${height - padBottom}` : ''
  const avg = samples.length ? samples.reduce((sum, s) => sum + s.mbps, 0) / samples.length : 0

  return (
    <Card className="speedtest-chart-card" bordered={false}>
      <div className="speedtest-chart-head">
        <span className="speedtest-chart-label">{label}</span>
        <span className="speedtest-chart-stats">峰值 {formatMbps(maxText)} · 平均 {formatMbps(avg)} Mbps</span>
      </div>
      <svg viewBox={`0 0 ${width} ${height}`} className="speedtest-chart" role="img" aria-label={label}>
        <line x1={padX} y1={height - padBottom} x2={width - padX} y2={height - padBottom} className="speedtest-chart-axis" />
        <line x1={padX} y1={padTop} x2={padX} y2={height - padBottom} className="speedtest-chart-axis" />
        {[0.25, 0.5, 0.75].map((r) => (
          <line
            key={r}
            x1={padX}
            x2={width - padX}
            y1={padTop + r * (height - padTop - padBottom)}
            y2={padTop + r * (height - padTop - padBottom)}
            className="speedtest-chart-grid"
          />
        ))}
        {area ? <polygon points={area} className="speedtest-chart-area" style={{ fill: color, fillOpacity: 0.08 }} /> : null}
        {points ? <polyline points={points} className="speedtest-chart-line" style={{ stroke: color }} /> : null}
        <text x={padX} y={padTop - 4} className="speedtest-chart-text">{formatMbps(max)}</text>
        <text x={padX} y={height - 8} className="speedtest-chart-text">0</text>
        <text x={width - padX} y={height - 8} className="speedtest-chart-text" textAnchor="end">15s</text>
      </svg>
    </Card>
  )
}
