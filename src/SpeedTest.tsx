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
]

const DOWNLOAD_SIZE = 20 * 1024 * 1024 // 20 MiB
const UPLOAD_SIZE = 10 * 1024 * 1024 // 10 MiB
const GAUGE_RADIUS = 110
const GAUGE_CIRCUMFERENCE = 2 * Math.PI * GAUGE_RADIUS

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
  // crypto.getRandomValues only supports 65536 bytes per call.
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
  const [progress, setProgress] = useState(0)
  const [currentMbps, setCurrentMbps] = useState(0)
  const [downloadMbps, setDownloadMbps] = useState(0)
  const [uploadMbps, setUploadMbps] = useState(0)
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
    setProgress(0)
    setCurrentMbps(0)
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

  const runDownload = useCallback(async (node: SpeedTestNode) => {
    const controller = new AbortController()
    abortRef.current = controller
    const response = await fetch(nodeUrl(node, `/v1/speedtest-payload?bytes=${DOWNLOAD_SIZE}`), {
      cache: 'no-store',
      signal: controller.signal,
    })
    if (!response.ok || !response.body) {
      throw new Error(`下载测速请求失败（HTTP ${response.status}）`)
    }
    const reader = response.body.getReader()
    let received = 0
    const start = performance.now()
    // eslint-disable-next-line no-constant-condition
    while (true) {
      const { done, value } = await reader.read()
      if (done) break
      received += value ? value.length : 0
      const seconds = (performance.now() - start) / 1000
      const mbps = seconds > 0 ? (received * 8) / 1e6 / seconds : 0
      setCurrentMbps(mbps)
      setProgress(Math.min(received / DOWNLOAD_SIZE, 1))
    }
    const seconds = (performance.now() - start) / 1000
    return seconds > 0 ? (received * 8) / 1e6 / seconds : 0
  }, [])

  const runUpload = useCallback(async (node: SpeedTestNode) => {
    const controller = new AbortController()
    abortRef.current = controller
    const payload = randomBlob(UPLOAD_SIZE)
    const start = performance.now()
    const response = await fetch(nodeUrl(node, '/v1/speedtest-upload'), {
      method: 'POST',
      body: payload,
      cache: 'no-store',
      signal: controller.signal,
    })
    const seconds = (performance.now() - start) / 1000
    if (!response.ok) {
      throw new Error(`上传测速请求失败（HTTP ${response.status}）`)
    }
    return seconds > 0 ? (UPLOAD_SIZE * 8) / 1e6 / seconds : 0
  }, [])

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
    setProgress(0)
    setCurrentMbps(0)
    setDownloadMbps(0)
    setUploadMbps(0)
    try {
      const download = await runDownload(node)
      setDownloadMbps(download)
      setProgress(1)

      setStatus('uploading')
      setProgress(0)
      setCurrentMbps(0)
      const upload = await runUpload(node)
      setUploadMbps(upload)
      setProgress(1)
      setStatus('done')
    } catch (err) {
      if (abortRef.current?.signal.aborted) return
      setStatus('error')
      setError(err instanceof Error ? err.message : '测速失败')
    }
  }, [selectedNode, runDownload, runUpload])

  const latency = selectedNode ? latencies[selectedNode.id] : undefined
  const displayMbps = status === 'downloading' ? currentMbps : status === 'uploading' ? uploadMbps || 0 : status === 'done' ? downloadMbps : 0
  const statusText = status === 'downloading' ? '下载测速中…' : status === 'uploading' ? '上传测速中…' : ''

  return (
    <Card className="section-card speedtest-card" bordered={false}>
      <div className="speedtest-head">
        <div>
          <h2 className="speedtest-title"><ThunderIcon /> 速度测试</h2>
          <p className="speedtest-subtitle">自动选择距离你最近的节点，测试下行与上行速度。</p>
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
            <strong>{status === 'probing' ? '—' : formatMbps(displayMbps)}</strong>
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
              {status === 'done' && (
                <>
                  <div className="speedtest-node-line">
                    <span className="speedtest-meta-label"><DownloadIcon /> 下载速度</span>
                    <span className="speedtest-meta-value">{formatMbps(downloadMbps)} Mbps（{formatMbPerSec(downloadMbps)}）</span>
                  </div>
                  <div className="speedtest-node-line">
                    <span className="speedtest-meta-label"><UploadIcon /> 上传速度</span>
                    <span className="speedtest-meta-value">{formatMbps(uploadMbps)} Mbps（{formatMbPerSec(uploadMbps)}）</span>
                  </div>
                </>
              )}
            </>
          )}
        </div>
      </div>

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
