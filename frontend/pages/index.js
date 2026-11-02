import { useState, useEffect } from 'react'
import { Doughnut } from 'react-chartjs-2'
import { Chart as ChartJS, ArcElement, Tooltip, Legend, CategoryScale, LinearScale, BarElement } from 'chart.js'

export default function Home() {
  const [scans, setScans] = useState([])
  const [target, setTarget] = useState('')
  const [scanType, setScanType] = useState('audit') // 'audit' (Full Nmap + SSL + Headers) or 'scan' (Port Scan)
  const [logs, setLogs] = useState('')
  const [analysis, setAnalysis] = useState(null)
  const [alerts, setAlerts] = useState([])
  const [loading, setLoading] = useState(false)
  const [token, setToken] = useState('')
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [errorMsg, setErrorMsg] = useState('')
  const backend = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000'

  function getStoredToken() {
    if (typeof window === 'undefined') return ''
    return window.localStorage.getItem('aisca_token') || ''
  }

  async function loginAndSetToken(loginUsername, loginPassword) {
    const res = await fetch(`${backend}/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ username: loginUsername, password: loginPassword })
    })

    if (!res.ok) {
      throw new Error(`Login failed: ${res.status}`)
    }

    const data = await res.json()
    window.localStorage.setItem('aisca_token', data.access_token)
    setToken(data.access_token)
    setErrorMsg('')
    return data.access_token
  }

  async function fetchWithAuth(url, options = {}) {
    let currentToken = token || getStoredToken()
    if (!currentToken) {
      throw new Error('Please sign in to continue.')
    }
    const headers = {
      ...(options.headers || {}),
      Authorization: `Bearer ${currentToken}`
    }
    let res = await fetch(url, { ...options, headers })
    if (res.status === 401) {
      window.localStorage.removeItem('aisca_token')
      setToken('')
      setErrorMsg('Your session expired. Please sign in again.')
    }
    return res
  }

  useEffect(() => {
    if (typeof window !== 'undefined') {
      ChartJS.register(ArcElement, Tooltip, Legend, CategoryScale, LinearScale, BarElement)
      setToken(getStoredToken())
    }
  }, [])

  useEffect(() => {
    if (!token) return undefined

    fetchScans()
    fetchStats()

    const wsBase = backend.replace(/^http/, 'ws')
    const socket = new WebSocket(`${wsBase}/ws/alerts?token=${encodeURIComponent(token)}`)
    socket.onmessage = (event) => {
      try {
        const message = JSON.parse(event.data)
        setAlerts(prev => [message, ...prev].slice(0, 5))
      } catch (err) {
        console.error('alert socket parse error', err)
      }
    }

    return () => socket.close()
  }, [token])

  const [stats, setStats] = useState(null)

  async function fetchStats() {
    try {
      const res = await fetchWithAuth(`${backend}/stats`)
      if (res.ok) {
        const data = await res.json()
        setStats(data)
      }
    } catch (e) {
      console.error('stats error', e)
    }
  }

  async function fetchScans() {
    try {
      const res = await fetchWithAuth(`${backend}/scans`)
      if (res.ok) {
        const data = await res.json()
        setScans(data.scans || [])
      }
    } catch (e) {
      console.error(e)
    }
  }

  function computeCounts(result) {
    const nmap = result?.nmap ? result.nmap : result
    let high = 0, medium = 0, low = 0
    if (nmap && typeof nmap === 'object') {
      Object.values(nmap).forEach(host => {
        if (host && host.ports && Array.isArray(host.ports)) {
          host.ports.forEach(p => {
            const r = p.risk || 'low'
            if (r === 'high') high += 1
            else if (r === 'medium') medium += 1
            else low += 1
          })
        }
      })
    }
    return { high, medium, low }
  }

  async function handleAnalyzeLogs() {
    if (!logs.trim()) return
    try {
      const res = await fetchWithAuth(`${backend}/analyze-logs`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ logs: logs.split('\n').filter(Boolean) })
      })
      if (!res.ok) {
        const errText = await res.text()
        throw new Error(`HTTP ${res.status}: ${errText}`)
      }
      const data = await res.json()
      setAnalysis(data.result)
    } catch (err) {
      console.error(err)
      alert('Log analysis failed: ' + err)
    }
  }

  async function handleScan(e) {
    e.preventDefault()
    if (!target) return

    setLoading(true)
    setErrorMsg('')
    try {
      const payload = { target }
      if (logs.trim()) {
        payload.logs = logs.split('\n').filter(Boolean)
      }
      const endpoint = scanType === 'audit' ? `${backend}/audit` : `${backend}/scan`
      const res = await fetchWithAuth(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      })

      if (!res.ok) {
        const errText = await res.text()
        throw new Error(`HTTP ${res.status}: ${errText}`)
      }

      const data = await res.json()
      setScans(s => [{ id: data.result?.id || Date.now(), target: data.target, timestamp: Math.floor(Date.now()/1000), result: data.result }, ...s])
      setTarget('')
      setLogs('')
      fetchStats()
    } catch (err) {
      console.error(err)
      setErrorMsg('Scan/Audit failed: ' + err.message)
    } finally {
      setLoading(false)
    }
  }

  const ScoreDoughnut = ({ counts }) => {
    const data = {
      labels: ['High', 'Medium', 'Low'],
      datasets: [
        {
          data: [counts.high, counts.medium, counts.low],
          backgroundColor: ['#b91c1c', '#b45309', '#065f46'],
          hoverOffset: 4
        }
      ]
    }
    const options = {
      plugins: { legend: { display: false } },
      maintainAspectRatio: false
    }
    return (
      <div style={{ width: 120, height: 100 }}>
        <Doughnut data={data} options={options} />
      </div>
    )
  }

  async function handleDownloadPdf(scanId) {
    try {
      const currentToken = token || getStoredToken()
      const res = await fetch(`${backend}/report/${scanId}?lang=en`, {
        headers: { Authorization: `Bearer ${currentToken}` }
      })
      if (!res.ok) {
        alert('Could not download PDF report: HTTP ' + res.status)
        return
      }
      const blob = await res.blob()
      const url = window.URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `aisca_report_${scanId}.pdf`
      document.body.appendChild(a)
      a.click()
      a.remove()
    } catch (err) {
      alert('Error downloading PDF: ' + err)
    }
  }

  async function handleLogin(e) {
    e.preventDefault()
    try {
      await loginAndSetToken(username, password)
      setPassword('')
    } catch (err) {
      setErrorMsg(err.message)
    }
  }

  function handleLogout() {
    window.localStorage.removeItem('aisca_token')
    setToken('')
    setPassword('')
    setErrorMsg('')
  }

  if (!token) {
    return (
      <main style={{ padding: 24, fontFamily: 'Inter, Arial, sans-serif', maxWidth: 420, margin: '10vh auto' }}>
        <h1>AISCA</h1>
        <p>Sign in to access the security dashboard.</p>
        <form onSubmit={handleLogin} style={{ display: 'grid', gap: 12 }}>
          <input
            value={username}
            onChange={e => setUsername(e.target.value)}
            placeholder="Username"
            autoComplete="username"
            required
            style={{ padding: 10, borderRadius: 6, border: '1px solid #94a3b8' }}
          />
          <input
            value={password}
            onChange={e => setPassword(e.target.value)}
            placeholder="Password"
            type="password"
            autoComplete="current-password"
            required
            style={{ padding: 10, borderRadius: 6, border: '1px solid #94a3b8' }}
          />
          {errorMsg && <div role="alert" style={{ color: '#b91c1c' }}>{errorMsg}</div>}
          <button type="submit" style={{ padding: 10, borderRadius: 6, background: '#2563eb', color: '#fff', border: 0, cursor: 'pointer' }}>
            Sign in
          </button>
        </form>
      </main>
    )
  }

  return (
    <div style={{ padding: 24, fontFamily: 'Inter, Arial, sans-serif', maxWidth: 1100, margin: '0 auto' }}>
      <header style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 12, flexWrap: 'wrap' }}>
        <h1>AISCA — Network Scanner & BSI Compliance Auditor</h1>
        <button type="button" onClick={handleLogout} style={{ padding: '8px 12px', borderRadius: 6, cursor: 'pointer' }}>Sign out</button>
      </header>

      <form onSubmit={handleScan} style={{ marginBottom: 16, background: '#f1f5f9', padding: 16, borderRadius: 10, border: '1px solid #cbd5e1' }}>
        <div style={{ display: 'flex', gap: 12, alignItems: 'center', marginBottom: 10, flexWrap: 'wrap' }}>
          <input
            value={target}
            onChange={e => setTarget(e.target.value)}
            placeholder="Enter domain or IP (e.g. example.com or 8.8.8.8)"
            style={{ padding: '10px 12px', width: 340, borderRadius: 6, border: '1px solid #94a3b8', fontSize: 14 }}
          />
          <select
            value={scanType}
            onChange={e => setScanType(e.target.value)}
            style={{ padding: '10px 12px', borderRadius: 6, border: '1px solid #94a3b8', fontSize: 14, background: '#fff' }}
          >
            <option value="audit">Full Security Audit (Nmap + SSL + Headers)</option>
            <option value="scan">Quick Network Port Scan (Nmap)</option>
          </select>
          <button
            type="submit"
            style={{ padding: '10px 18px', borderRadius: 6, background: '#2563eb', color: '#fff', border: 'none', fontWeight: 600, cursor: 'pointer' }}
            disabled={loading}
          >
            {loading ? 'Scanning Target...' : 'Start Audit'}
          </button>
        </div>

        {loading && (
          <div style={{ color: '#1d4ed8', fontWeight: 600, fontSize: 13, display: 'flex', alignItems: 'center', gap: 8 }}>
            <span>⏳ Running Nmap port discovery, SSL certificate verification, and HTTP security audit...</span>
          </div>
        )}

        {errorMsg && (
          <div style={{ marginTop: 10, padding: 10, background: '#fef2f2', border: '1px solid #fca5a5', color: '#991b1b', borderRadius: 6, fontSize: 13 }}>
            ⚠️ {errorMsg}
          </div>
        )}
      </form>

      <div style={{ marginBottom: 18, border: '1px solid #dfe5ef', borderRadius: 10, padding: 12, background: '#f8fafc' }}>
        <div style={{ fontWeight: 700, marginBottom: 8 }}>Rule-Based Log Anomaly Analysis</div>
        <textarea
          value={logs}
          onChange={e => setLogs(e.target.value)}
          rows={4}
          placeholder="Paste Nginx/Linux auth logs here to detect suspicious activity..."
          style={{ width: '100%', boxSizing: 'border-box', padding: 8, resize: 'vertical', fontFamily: 'monospace', fontSize: 13 }}
        />
        <div style={{ marginTop: 8 }}>
          <button type="button" onClick={handleAnalyzeLogs} style={{ padding: '8px 12px', cursor: 'pointer', borderRadius: 6, border: '1px solid #94a3b8' }}>
            Analyze Logs
          </button>
          {analysis && (
            <span style={{ marginLeft: 10, fontWeight: 700, color: analysis.risk_level === 'high' ? '#b91c1c' : '#0f172a' }}>
              Risk score: {analysis.overall_score}/100 ({analysis.risk_level})
            </span>
          )}
        </div>
      </div>

      <div style={{ marginBottom: 18, border: '1px solid #fbbf24', borderRadius: 10, padding: 12, background: '#fff7ed' }}>
        <div style={{ fontWeight: 700, marginBottom: 8 }}>Live Real-Time Security Alerts</div>
        {alerts.length === 0 ? <div style={{ fontSize: 13, color: '#64748b' }}>No live alerts.</div> : alerts.map((alert, idx) => (
          <div key={`${alert.timestamp}-${idx}`} style={{ padding: '6px 0', color: alert.level === 'high' ? '#b91c1c' : '#92400e', borderBottom: idx < alerts.length - 1 ? '1px solid #fed7aa' : 'none', fontSize: 13 }}>
            [{new Date(alert.timestamp * 1000).toLocaleTimeString()}] {alert.level.toUpperCase()}: {alert.message}
          </div>
        ))}
      </div>

      <h2>Dashboard</h2>
      <div style={{ display: 'flex', gap: 16, marginBottom: 18, flexWrap: 'wrap' }}>
        <div style={{ width: 260, border: '1px solid #ddd', padding: 12, borderRadius: 8, background: '#fff' }}>
          <h3 style={{ margin: 0, fontSize: 14 }}>Overall Risk Distribution</h3>
          <div id="overall-donut" style={{ marginTop: 12 }}>
            {stats ? (
              <Doughnut data={{ labels: ['High','Medium','Low'], datasets: [{ data: [stats.total.high, stats.total.medium, stats.total.low], backgroundColor: ['#b91c1c','#b45309','#065f46'] }] }} options={{ plugins: { legend: { display: false } }, maintainAspectRatio: false }} />
            ) : <div style={{ height: 100 }}>Loading...</div>}
          </div>
        </div>

        <div style={{ flex: 1, border: '1px solid #ddd', padding: 12, borderRadius: 8, background: '#fff' }}>
          <h3 style={{ margin: 0, fontSize: 14 }}>Security Posture Score</h3>
          <div style={{ fontSize: 32, fontWeight: 700, marginTop: 12, color: (scans[0]?.result?.security_score ?? 100) < 50 ? '#b91c1c' : '#15803d' }}>
            {scans[0]?.result?.security_score ?? stats?.time_series?.[stats.time_series.length - 1]?.score ?? 100}/100
          </div>
          <div style={{ marginTop: 8, color: '#475569', fontSize: 13 }}>
            {scans[0]?.result?.ai_anomaly?.risk_level ? `Log Anomaly Risk: ${scans[0].result.ai_anomaly.risk_level}` : 'No log-anomaly findings yet'}
          </div>
        </div>
      </div>

      <h2>Recent Scans & Audits</h2>
      {scans.length === 0 && <div>No scans yet.</div>}
      <ul style={{ listStyle: 'none', paddingLeft: 0 }}>
        {scans.map(s => {
          const counts = computeCounts(s.result)
          const score = s.result?.security_score ?? computeScore(counts)
          const sslAudit = s.result?.ssl_audit
          const cert = sslAudit?.cert
          const headers = sslAudit?.headers

          return (
            <li key={s.id} style={{ marginBottom: 16, border: '1px solid #cbd5e1', borderRadius: 8, padding: 16, background: '#fff', boxShadow: '0 1px 3px rgba(0,0,0,0.05)' }}>
              <div style={{ display: 'flex', gap: 16, alignItems: 'flex-start', flexWrap: 'wrap' }}>
                <div style={{ flex: '0 0 160px' }}>
                  <div style={{ fontSize: 16, fontWeight: 700 }}>{s.target}</div>
                  <div style={{ fontSize: 12, color: '#64748b' }}>{new Date((s.timestamp || 0) * 1000).toLocaleString()}</div>
                  <div style={{ marginTop: 8, fontSize: 14 }}><strong>Score:</strong> <span style={{ color: score < 50 ? '#b91c1c' : '#15803d', fontWeight: 700 }}>{score}/100</span></div>

                  {s.id && (
                    <button
                      onClick={() => handleDownloadPdf(s.id)}
                      style={{ marginTop: 12, padding: '6px 10px', fontSize: 12, borderRadius: 4, border: '1px solid #2563eb', background: '#eff6ff', color: '#1d4ed8', cursor: 'pointer', fontWeight: 600 }}
                    >
                      📄 BSI / GDPR PDF
                    </button>
                  )}
                </div>

                <div style={{ flex: '0 0 120px' }}>
                  <ScoreDoughnut counts={counts} />
                </div>

                <div style={{ flex: 1, minWidth: 280 }}>
                  {sslAudit && (
                    <div style={{ marginBottom: 10, padding: 10, background: '#f8fafc', borderRadius: 6, border: '1px solid #e2e8f0', fontSize: 13 }}>
                      <div style={{ fontWeight: 600, marginBottom: 4 }}>Web & SSL Compliance Summary:</div>
                      <div>
                        🔒 <strong>SSL Certificate:</strong> {cert?.valid ? <span style={{ color: '#15803d' }}>Valid (Expires in {cert.days_left ?? 'N/A'} days)</span> : <span style={{ color: '#b91c1c' }}>Invalid or Not Found</span>}
                      </div>
                      {headers?.missing_headers && headers.missing_headers.length > 0 ? (
                        <div style={{ marginTop: 4, color: '#b45309' }}>
                          ⚠️ <strong>Missing Headers (BSI Grundschutz / GDPR):</strong> {headers.missing_headers.join(', ')}
                        </div>
                      ) : (
                        <div style={{ marginTop: 4, color: '#15803d' }}>
                          ✅ All key HTTP security headers present (HSTS, CSP, X-Frame-Options)
                        </div>
                      )}
                      {sslAudit?.tls?.supported_versions && (
                        <div style={{ marginTop: 4, fontSize: 12, color: '#64748b' }}>
                          TLS Versions: {sslAudit.tls.supported_versions.join(', ') || 'None detected'}
                        </div>
                      )}
                    </div>
                  )}

                  <details style={{ fontSize: 13 }}>
                    <summary style={{ cursor: 'pointer', fontWeight: 600, color: '#475569' }}>Inspect Full Raw Scan JSON</summary>
                    <pre style={{ whiteSpace: 'pre-wrap', marginTop: 8, background: '#0f172a', color: '#f8fafc', padding: 12, borderRadius: 6, overflowX: 'auto', fontSize: 12 }}>
                      {JSON.stringify(s.result, null, 2)}
                    </pre>
                  </details>
                </div>
              </div>
            </li>
          )
        })}
      </ul>

    </div>
  )
}
