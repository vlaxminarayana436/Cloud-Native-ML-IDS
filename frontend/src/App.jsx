import React, { useCallback, useEffect, useRef, useState } from 'react'
import {
  Activity, ArrowRight, BrainCircuit, Check, ChevronDown, CircleHelp,
  Cpu, Database, Download, Eye, FileUp, Filter, Globe2, LayoutDashboard,
  LockKeyhole, Network, Plus, Radio, RefreshCw, Search, Shield,
  ShieldAlert, ShieldCheck, ShieldOff, SlidersHorizontal, Trash2, TriangleAlert, X,
} from 'lucide-react'

const API = '/api/v1'
const sources = [
  ['all', 'All sources'], ['capture', 'Live capture'], ['synthetic', 'Synthetic'],
  ['pcap', 'Offline PCAP'], ['unknown', 'Unspecified'],
]
const nav = [
  { id: 'overview', label: 'Overview', icon: LayoutDashboard },
  { id: 'traffic', label: 'Traffic analysis', icon: Activity },
  { id: 'alerts', label: 'Alert feed', icon: ShieldAlert },
  { id: 'pcap', label: 'PCAP analysis', icon: FileUp },
  { id: 'policy', label: 'Access policy', icon: Network },
  { id: 'adaptive', label: 'Adaptive learning', icon: BrainCircuit },
  { id: 'model', label: 'Model & health', icon: Cpu },
]
const sourceLabel = (source) => ({ capture: 'Live capture', synthetic: 'Synthetic', pcap: 'Offline PCAP', unknown: 'Unspecified', manual: 'Manual' }[source] || source)
const human = (value) => String(value || 'Unknown').replaceAll('_', ' ')
const count = (value) => Number(value || 0).toLocaleString()
const percent = (value) => value == null || !Number.isFinite(Number(value)) ? '—' : `${(Number(value) * 100).toFixed(1)}%`
const clock = (seconds) => seconds ? new Date(seconds * 1000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : '—'
const relative = (seconds) => {
  if (!seconds) return 'Not yet seen'
  const diff = Math.max(0, Math.floor(Date.now() / 1000 - seconds))
  if (diff < 60) return `${diff}s ago`
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`
  return new Date(seconds * 1000).toLocaleDateString()
}

let memoryApiKey = ''
let apiKeyVersion = 0
function getApiKey() {
  try { return sessionStorage.getItem('commander-api-key') || memoryApiKey } catch { return memoryApiKey }
}
function rememberApiKey(key) {
  memoryApiKey = key
  apiKeyVersion += 1
  try { sessionStorage.setItem('commander-api-key', key) } catch { /* keep it in memory for this tab */ }
}
function forgetApiKey() {
  memoryApiKey = ''
  apiKeyVersion += 1
  try { sessionStorage.removeItem('commander-api-key') } catch { /* storage can be unavailable */ }
}

async function api(path, options = {}) {
  const headers = { ...(options.headers || {}) }
  const key = getApiKey()
  const requestKeyVersion = apiKeyVersion
  const method = (options.method || 'GET').toUpperCase()
  if (key && !['GET', 'HEAD', 'OPTIONS'].includes(method)) headers['X-API-Key'] = key
  if (options.body && !(options.body instanceof FormData)) headers['Content-Type'] = 'application/json'
  const response = await fetch(path, { ...options, headers })
  if (!response.ok) {
    let detail = `${response.status} ${response.statusText}`
    try {
      const body = await response.json()
      if (typeof body.detail === 'string') detail = body.detail
      else if (Array.isArray(body.detail)) detail = body.detail.map((item) => item.msg).join('; ')
    } catch { /* keep status */ }
    const error = new Error(detail)
    error.status = response.status
    error.keyVersion = requestKeyVersion
    throw error
  }
  return response.json()
}
const json = (method, body) => ({ method, ...(body !== undefined ? { body: JSON.stringify(body) } : {}) })

function BrandMark({ size = 34 }) {
  return <span className="brand-mark" style={{ width: size, height: size }} aria-hidden="true"><Shield size={size * .67} strokeWidth={1.7} /><span className="brand-dot" /></span>
}

function Sidebar({ active, goTo, connected }) {
  const navigationRef = useRef(null)
  useEffect(() => {
    if (window.innerWidth > 760) return
    const strip = navigationRef.current; const selected = strip?.querySelector('[aria-current="page"]')
    if (!strip || !selected) return
    const container = strip.getBoundingClientRect(); const item = selected.getBoundingClientRect()
    const shift = item.left < container.left ? item.left - container.left : item.right > container.right ? item.right - container.right : 0
    if (shift) strip.scrollTo({ left: strip.scrollLeft + shift, behavior: 'smooth' })
  }, [active])
  return <aside className="sidebar" aria-label="Main navigation">
    <div className="brand">
      <BrandMark />
      <div className="brand-copy"><strong>Cloud-Native</strong><span>ML-IDS <i> / </i> CONSOLE</span></div>
    </div>
    <div className="sidebar-main">
      <p className="nav-caption">WORKSPACE</p>
      <nav className="navigation" ref={navigationRef}>
        {nav.map(({ id, label, icon: Icon }) => <button type="button" key={id} onClick={() => goTo(id)} className={`nav-link ${active === id ? 'active' : ''}`} aria-current={active === id ? 'page' : undefined}>
          <Icon size={18} strokeWidth={1.7} /><span>{label}</span><span className="nav-marker" />
        </button>)}
      </nav>
    </div>
    <div className="sidebar-footer">
      <div className="sidebar-status"><span className={`status-dot ${connected ? 'ok' : 'offline'}`} /><div><strong>{connected ? 'Commander connected' : 'Commander unavailable'}</strong><small>Local control plane</small></div></div>
    </div>
  </aside>
}

function KeyRequestDialog({ invalid, onSubmit, onCancel }) {
  const [value, setValue] = useState('')
  const inputRef = useRef(null)
  const formRef = useRef(null)
  useEffect(() => {
    const previous = document.activeElement
    inputRef.current?.focus()
    return () => previous?.focus?.()
  }, [])
  const handleKeyDown = (event) => {
    if (event.key === 'Escape') { event.preventDefault(); onCancel(); return }
    if (event.key !== 'Tab') return
    const controls = [...formRef.current.querySelectorAll('input, button:not(:disabled)')]
    if (event.shiftKey && document.activeElement === controls[0]) { event.preventDefault(); controls.at(-1)?.focus() }
    else if (!event.shiftKey && document.activeElement === controls.at(-1)) { event.preventDefault(); controls[0]?.focus() }
  }
  return <div className="auth-backdrop"><form ref={formRef} className="auth-dialog" role="dialog" aria-modal="true" aria-labelledby="auth-title" aria-describedby="auth-description" onKeyDown={handleKeyDown} onSubmit={(event) => { event.preventDefault(); onSubmit(value.trim()) }}>
    <h2 id="auth-title">Authentication required</h2>
    <p id="auth-description">This action is protected. Enter the Commander API key to continue.</p>
    <label htmlFor="commander-key">API key</label>
    <input ref={inputRef} id="commander-key" type="password" autoComplete="off" required value={value} onChange={(event) => setValue(event.target.value)} />
    {invalid && <p className="auth-error" role="alert">The key was not accepted. Try again.</p>}
    <div className="auth-actions"><button className="button secondary" type="button" onClick={onCancel}>Cancel</button><button className="button primary" type="submit" disabled={!value.trim()}>Continue</button></div>
    <small>The key is kept only in this browser tab.</small>
  </form></div>
}

function SectionHeading({ eyebrow, title, text, action }) {
  return <div className="section-heading"><div><div className="eyebrow">{eyebrow}</div><h2>{title}</h2>{text && <p>{text}</p>}</div>{action}</div>
}
function PanelHead({ title, description, right, icon: Icon }) {
  return <div className="panel-head"><div className="panel-title-wrap">{Icon && <span className="panel-icon"><Icon size={17} /></span>}<div><h3>{title}</h3>{description && <p>{description}</p>}</div></div>{right}</div>
}
function Metric({ icon: Icon, tone, label, value, note }) {
  return <div className="metric card"><div className="metric-top"><span>{label}</span><span className={`metric-icon ${tone}`}><Icon size={18} strokeWidth={1.8} /></span></div><div className="metric-number">{value}</div><div className="metric-note">{note}</div></div>
}
function Empty({ icon: Icon = CircleHelp, title, detail }) {
  return <div className="empty"><span className="empty-icon"><Icon size={19} /></span><strong>{title}</strong><p>{detail}</p></div>
}
function Badge({ children, tone = 'neutral' }) { return <span className={`badge ${tone}`}>{children}</span> }
function SourceSelect({ source, setSource }) {
  return <label className="source-select"><Filter size={15} /><span className="sr-only">Traffic source</span><select aria-label="Traffic source" value={source} onChange={(e) => setSource(e.target.value)}>{sources.map(([value, label]) => <option key={value} value={value}>{label}</option>)}</select><ChevronDown size={15} className="select-chevron" /></label>
}

function Overview({ data, source, setSource }) {
  const s = data.summary || {}; const model = data.model || {}; const health = data.health || {}
  const metricValue = (value) => value == null ? '—' : count(value)
  const selected = sources.find(([v]) => v === source)?.[1] || 'All sources'
  return <section id="overview" className="overview section-anchor">
    <div className="page-heading"><div><div className="eyebrow"><span className="eyebrow-line" /> NETWORK SECURITY</div><h1>Security overview</h1><p>Network traffic, detections and response activity.</p></div><SourceSelect source={source} setSource={setSource} /></div>
    <div className="overview-context"><span className="context-dot" /> Viewing <strong>{selected.toLowerCase()}</strong><span className="context-divider" /> Counts reflect stored flow records, not individual packets.</div>
    <div className="metrics-grid">
      <Metric icon={Activity} tone="blue" label="Flows observed" value={metricValue(s.totalEvents)} note="Records in selected source" />
      <Metric icon={ShieldAlert} tone="coral" label="Alerts generated" value={metricValue(s.totalAlerts)} note={s.totalAlerts == null ? 'Awaiting data' : `${count(s.mlAlerts)} ML · ${count(s.policyOnly)} policy-only`} />
      <Metric icon={ShieldOff} tone="amber" label="Active block entries" value={metricValue(s.activeBlocks)} note="Simulated unless separately enforced" />
      <Metric icon={Radio} tone="green" label="Active sensors" value={metricValue(s.activeAgents)} note={s.activeAgents == null ? 'Awaiting data' : s.activeAgents ? 'Heartbeat in the last 20 seconds' : 'No sensors reporting'} />
    </div>
    <div className="pipeline card"><div className="pipeline-label"><span className="pipeline-label-icon"><Globe2 size={18} /></span><div><strong>Monitoring pipeline</strong><small>Collection · detection · response</small></div></div><div className="pipeline-steps">
      <div className="pipeline-step"><span className="step-number">01</span><div><strong>Collect</strong><small>{s.activeAgents == null ? 'Unavailable' : `${count(s.activeAgents)} active sensor${Number(s.activeAgents) === 1 ? '' : 's'}`}</small></div></div><ArrowRight className="step-arrow" size={15} />
      <div className="pipeline-step"><span className="step-number">02</span><div><strong>Detect</strong><small>{model.loaded ? 'Model loaded' : 'Model unavailable'}</small></div></div><ArrowRight className="step-arrow" size={15} />
      <div className="pipeline-step"><span className="step-number">03</span><div><strong>Respond</strong><small>{!health.firewall_mode ? 'Unavailable' : health.firewall_mode === 'ALERT_ONLY' ? 'Alert only' : 'Simulated blocks'}</small></div></div>
    </div></div>
  </section>
}

function Timeline({ timeline = [] }) {
  const width = 640, height = 190, left = 12, right = 8, top = 14, bottom = 25
  const values = timeline.length ? timeline : Array.from({ length: 12 }, () => ({ normal: 0, alerts: 0 }))
  const max = Math.max(4, ...values.map((x) => Math.max(x.normal || 0, x.alerts || 0)))
  const x = (i) => left + i * (width - left - right) / Math.max(1, values.length - 1)
  const y = (n) => top + (height - top - bottom) * (1 - n / max)
  const path = (key) => values.map((v, i) => `${i ? 'L' : 'M'} ${x(i).toFixed(1)} ${y(v[key] || 0).toFixed(1)}`).join(' ')
  const area = `${path('normal')} L ${x(values.length - 1)} ${height - bottom} L ${left} ${height - bottom} Z`
  return <div className="chart-wrap"><svg viewBox={`0 0 ${width} ${height}`} preserveAspectRatio="none" className="chart" role="img" aria-label="Flow counts by minute over the last twelve minutes">
    <defs><linearGradient id="traffic-fill" x1="0" x2="0" y1="0" y2="1"><stop offset="0%" stopColor="#5578ec" stopOpacity=".19" /><stop offset="100%" stopColor="#5578ec" stopOpacity="0" /></linearGradient></defs>
    {[0, 1, 2, 3].map((i) => <line key={i} x1={left} x2={width - right} y1={top + i * (height - top - bottom) / 3} y2={top + i * (height - top - bottom) / 3} stroke="#e9edf3" strokeDasharray={i === 3 ? undefined : '4 5'} />)}
    <path d={area} fill="url(#traffic-fill)" /><path d={path('normal')} fill="none" stroke="#5578ec" strokeWidth="2.5" vectorEffect="non-scaling-stroke" strokeLinejoin="round" /><path d={path('alerts')} fill="none" stroke="#e99b6d" strokeWidth="2.5" vectorEffect="non-scaling-stroke" strokeLinejoin="round" />
    {[0, 3, 6, 9, 11].map((i) => <text key={i} x={x(Math.min(i, values.length - 1))} y={height - 2} textAnchor={i === 0 ? 'start' : i === 11 ? 'end' : 'middle'} fill="#98a3b3" fontSize="11">{clock(values[Math.min(i, values.length - 1)]?.timestamp)}</text>)}
  </svg>{!values.some((value) => value.normal || value.alerts) && <span className="chart-empty">No flows in this interval</span>}</div>
}
function Traffic({ data, onAction }) {
  const s = data.summary || {}; const blocks = (data.blocks || []).filter((b) => b.active); const attacks = Object.entries(s.attackTypes || {}).slice(0, 3); const totalAttacks = Object.values(s.attackTypes || {}).reduce((a, b) => a + b, 0)
  const [adding, setAdding] = useState(false); const [ip, setIp] = useState(''); const [reason, setReason] = useState('Manual review')
  const add = async (event) => { event.preventDefault(); if (await onAction('Block entry added', `${API}/blocklist`, json('POST', { ip, reason }))) { setIp(''); setReason('Manual review'); setAdding(false) } }
  const remove = (address) => { if (window.confirm(`Remove ${address} from the blocklist?`)) onAction('Block entry removed', `${API}/blocklist/${encodeURIComponent(address)}`, { method: 'DELETE' }) }
  return <section id="traffic" className="section-anchor section-block"><SectionHeading eyebrow="NETWORK ACTIVITY" title="Traffic analysis" text="Flow volume and active block entries." />
    <div className="traffic-grid">
      <div className="card chart-card"><PanelHead title="Traffic over time" description="Flow records by minute · last 12 minutes" right={<div className="chart-legend"><span><i className="legend-blue" /> Normal</span><span><i className="legend-orange" /> Alerts</span></div>} />
        <Timeline timeline={s.timeline} />
        <div className="chart-bottom"><div><small>Normal flows</small><strong>{count(s.normalEvents)}</strong></div><div><small>ML alerts</small><strong>{count(s.mlAlerts)}</strong></div><div><small>Policy-only alerts</small><strong>{count(s.policyOnly)}</strong></div><div className="chart-bottom-note">Selected source<br />all stored records</div></div>
      </div>
      <div className="card block-card"><PanelHead title="Blocklist" description="Active response entries" icon={ShieldOff} right={<button className="icon-button" type="button" aria-label={adding ? 'Close add block form' : 'Add block entry'} onClick={() => setAdding(!adding)}>{adding ? <X size={17} /> : <Plus size={17} />}</button>} />
        <p className="inline-notice"><Shield size={14} /> Recorded here; eligible entries require an enabled on-path enforcer to block traffic.</p>
        {adding && <form className="compact-form" onSubmit={add}><label>IP address<input required value={ip} onChange={(e) => setIp(e.target.value)} placeholder="IP address" /></label><label>Reason<input required value={reason} maxLength={160} onChange={(e) => setReason(e.target.value)} /></label><button className="button primary small" type="submit">Add entry</button></form>}
        {blocks.length ? <div className="block-list">{blocks.map((block) => <div className="block-row" key={block.ip}><span className="block-avatar"><ShieldOff size={15} /></span><div className="block-details"><strong>{block.ip}</strong><small>{human(block.reason)} · {sourceLabel(block.traffic_source)}</small></div><button className="icon-button ghost" type="button" aria-label={`Remove ${block.ip}`} title="Remove entry" onClick={() => remove(block.ip)}><X size={15} /></button></div>)}</div> : <Empty icon={ShieldCheck} title="No active block entries" detail="Entries appear here when a response is recorded." />}
      </div>
    </div>
    <div className="threat-strip card"><div><span className="eyebrow">DETECTION MIX</span><strong>Alert categories</strong></div><div className="threat-items">{attacks.length ? attacks.map(([name, n]) => <span className="threat-item" key={name}><i />{human(name)} <b>{count(n)}</b><small>{totalAttacks ? Math.round(n / totalAttacks * 100) : 0}%</small></span>) : <span className="threat-placeholder">No alerts in this view yet</span>}</div><span className="threat-note">of selected-source alerts</span></div>
  </section>
}

function downloadAlerts(events) {
  const fields = ['id', 'timestamp', 'agent_id', 'traffic_source', 'src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol', 'classification', 'attack_type', 'confidence', 'anomaly_score', 'detection_source', 'policy_action', 'policy_reason', 'action']
  const cell = (raw) => {
    let value = String(raw ?? '')
    // Prevent spreadsheet applications from interpreting untrusted text as a formula.
    if (/^[\s]*[=+\-@]/.test(value)) value = `'${value}`
    return `"${value.replaceAll('"', '""')}"`
  }
  const csv = [fields.join(','), ...events.map((event) => fields.map((field) => cell(event[field])).join(','))].join('\r\n') + '\r\n'
  const url = URL.createObjectURL(new Blob([csv], { type: 'text/csv;charset=utf-8' }))
  const link = document.createElement('a'); link.href = url; link.download = 'alerts.csv'
  document.body.appendChild(link); link.click(); link.remove()
  setTimeout(() => URL.revokeObjectURL(url), 1000)
}

function Alerts({ data }) {
  const [query, setQuery] = useState(''); const [kind, setKind] = useState('all')
  const term = query.trim().toLowerCase()
  const alerts = (data.alerts || []).filter((event) => (kind === 'all' || (kind === 'ml' ? event.classification === 'Malicious' : event.classification === 'Policy_Denied')) && [event.src_ip, event.dst_ip, human(event.attack_type), event.agent_id].some((v) => String(v ?? '').toLowerCase().includes(term)))
  return <section id="alerts" className="section-anchor section-block"><SectionHeading eyebrow="INVESTIGATION" title="Alert feed" text="ML detections and access-policy decisions." action={<button className="button secondary" type="button" disabled={!alerts.length} onClick={() => downloadAlerts(alerts)}><Download size={15} /> Export CSV</button>} />
    <div className="card table-card"><div className="table-toolbar"><div><h3>Recent alerts</h3><p>Most recent 100 alerts · filters apply to export</p></div><div className="table-filters"><label className="search-input"><Search size={15} /><span className="sr-only">Search alerts</span><input value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Search IP, type or sensor" /></label><label className="mini-select"><span className="sr-only">Alert type</span><select value={kind} onChange={(e) => setKind(e.target.value)}><option value="all">All types</option><option value="ml">ML detection</option><option value="policy">Policy only</option></select><ChevronDown size={14} /></label></div></div>
      {alerts.length ? <div className="table-scroll alert-table-scroll"><table><thead><tr><th>TIME</th><th>DETECTION</th><th>SOURCE → DESTINATION</th><th>ORIGIN</th><th>RESPONSE</th><th>SCORE</th></tr></thead><tbody>{alerts.map((event) => <tr key={event.id}><td className="muted nowrap" title={new Date(event.timestamp * 1000).toLocaleString()}>{relative(event.timestamp)}</td><td><strong>{human(event.attack_type)}</strong><small>{event.classification === 'Policy_Denied' ? 'Policy decision' : human(event.detection_source)}</small></td><td className="address-cell"><strong>{event.src_ip}</strong><small>→ {event.dst_ip}{event.dst_port ? `:${event.dst_port}` : ''}</small></td><td><Badge>{sourceLabel(event.traffic_source)}</Badge></td><td><Badge tone={event.action === 'BLOCKED_SIMULATED' ? 'amber' : event.action === 'POLICY_DENY_RECORDED' ? 'purple' : 'neutral'}>{human(event.action)}</Badge></td><td>{['access_policy', 'learned_pattern'].includes(event.detection_source) ? '—' : percent(event.confidence)}</td></tr>)}</tbody></table></div> : <div className="alert-table-empty"><Empty icon={Eye} title="Nothing to review here" detail={query || kind !== 'all' ? 'Try a different filter.' : 'Alerts will appear as suspicious activity is recorded.'} /></div>}
      <div className="table-foot"><span>Showing {count(alerts.length)} of {count((data.alerts || []).length)} loaded alerts</span><span>Scores are uncalibrated, not accuracy</span></div>
    </div>
  </section>
}

function Pcap({ onAction, onViewAlerts }) {
  const [file, setFile] = useState(null); const [result, setResult] = useState(null); const [busy, setBusy] = useState(false); const fileRef = useRef(null)
  const upload = async (event) => {
    event.preventDefault(); if (!file) return
    setBusy(true); const form = new FormData(); form.append('file', file)
    const response = await onAction('Offline analysis completed', `${API}/pcap/analyze`, { method: 'POST', body: form }, true)
    if (response) setResult(response)
    setBusy(false)
  }
  return <section id="pcap" className="section-anchor section-block"><SectionHeading eyebrow="OFFLINE INVESTIGATION" title="PCAP analysis" text="Analyze captures without affecting live responses." />
    <div className="pcap-card card"><div className="pcap-intro"><span className="large-icon"><FileUp size={23} /></span><div><h3>Analyze a capture</h3><p>Aggregate IPv4 TCP/UDP packets into flows and run the current detection pipeline.</p><div className="pcap-limits"><span>PCAP / PCAPNG / CAP</span><span>25 MB maximum</span><span>Up to 5,000 flows</span></div></div></div>
      <form className="upload-form" onSubmit={upload}><input ref={fileRef} className="sr-only" id="pcap-file" type="file" accept=".pcap,.pcapng,.cap" onChange={(e) => { setFile(e.target.files?.[0] || null); setResult(null) }} /><label className="file-choice" htmlFor="pcap-file"><FileUp size={16} /><span>{file ? file.name : 'Choose capture file'}</span></label><button className="button primary" type="submit" disabled={!file || busy}>{busy ? 'Analyzing…' : 'Analyze capture'} <ArrowRight size={15} /></button></form>
      {result && <div className="pcap-result" role="status"><Check size={16} /><span><strong>{result.filename}</strong> · {count(result.total_flows)} flow{result.total_flows === 1 ? '' : 's'} analyzed · {count(result.malicious_flows)} ML alert{result.malicious_flows === 1 ? '' : 's'} · {count(result.policy_only_flows)} policy-only. Offline analysis does not create firewall blocks.</span><button className="text-button pcap-view" type="button" onClick={onViewAlerts}>View PCAP alerts <ArrowRight size={14} /></button></div>}
    </div>
  </section>
}

function Policy({ data, onAction }) {
  const bundle = data.policy || {}; const settings = bundle.settings || {}; const networks = bundle.trusted_networks || []; const resources = bundle.resources || []
  const [editing, setEditing] = useState(false); const [draft, setDraft] = useState({}); const [egress, setEgress] = useState(''); const [showNetwork, setShowNetwork] = useState(false); const [showResource, setShowResource] = useState(false)
  const [network, setNetwork] = useState({ label: '', cidr: '', kind: 'office' }); const [resource, setResource] = useState({ name: '', destination_cidr: '', protocol: 'TCP', ports: '' })
  const beginEdit = () => { setDraft({ enabled: !!settings.enabled, mode: settings.mode || 'monitor', egress_enabled: !!settings.egress_enabled }); setEgress((settings.egress_cidrs || []).join(', ')); setEditing(true) }
  const saveSettings = async (e) => { e.preventDefault(); const payload = { ...draft, egress_cidrs: egress.split(',').map((s) => s.trim()).filter(Boolean) }; if (await onAction('Policy settings saved', `${API}/access-policy/settings`, json('PUT', payload))) setEditing(false) }
  const addNetwork = async (e) => { e.preventDefault(); if (await onAction('Trusted network added', `${API}/access-policy/networks`, json('POST', network))) { setNetwork({ label: '', cidr: '', kind: 'office' }); setShowNetwork(false) } }
  const addResource = async (e) => { e.preventDefault(); if (await onAction('Protected service added', `${API}/access-policy/resources`, json('POST', resource))) { setResource({ name: '', destination_cidr: '', protocol: 'TCP', ports: '' }); setShowResource(false) } }
  const toggle = (kind, item) => onAction('Entry updated', `${API}/access-policy/${kind}/${item.id}`, json('PATCH', { enabled: !item.enabled }))
  const remove = (kind, item) => { if (window.confirm(`Remove ${item.label || item.name}?`)) onAction('Entry removed', `${API}/access-policy/${kind}/${item.id}`, { method: 'DELETE' }) }
  return <section id="policy" className="section-anchor section-block"><SectionHeading eyebrow="ACCESS GOVERNANCE" title="Trusted access policy" text="Configure trusted networks and protected services." />
    <div className="policy-banner"><LockKeyhole size={18} /><div><strong>Network location is not identity.</strong> Use VPN and MFA for authentication. Trusted traffic remains inspected; policy decisions are separate from ML detections.</div></div>
    <div className="policy-grid"><div className="card policy-settings"><PanelHead title="Policy posture" description="Evaluate protected services and optional egress" icon={SlidersHorizontal} right={!editing && <button className="text-button" type="button" onClick={beginEdit}>Edit settings</button>} />
      {editing ? <form className="settings-form" onSubmit={saveSettings}><label className="check-label"><input type="checkbox" checked={!!draft.enabled} onChange={(e) => setDraft({ ...draft, enabled: e.target.checked })} /> Enable policy evaluation</label><label>Policy mode<select value={draft.mode} onChange={(e) => setDraft({ ...draft, mode: e.target.value })}><option value="monitor">Monitor (record only)</option><option value="enforce">Deny decision (requires enforcer)</option></select></label><label className="check-label"><input type="checkbox" checked={!!draft.egress_enabled} onChange={(e) => setDraft({ ...draft, egress_enabled: e.target.checked })} /> Enable managed egress guard</label><label>Managed source CIDRs <small>(comma-separated)</small><input value={egress} onChange={(e) => setEgress(e.target.value)} placeholder="CIDR ranges" /></label><p className="form-help">Enforcement is not performed by the API. Only an explicitly enabled IPv4 enforcer on the traffic path can apply supported rules.</p><div className="button-row"><button className="button primary small">Save settings</button><button className="button secondary small" type="button" onClick={() => setEditing(false)}>Cancel</button></div></form> : <div className="setting-list"><div><span>Evaluation</span><Badge tone={settings.enabled ? 'green' : 'neutral'}>{settings.enabled ? 'Enabled' : 'Disabled'}</Badge></div><div><span>Policy mode</span><strong>{settings.mode === 'enforce' ? 'Deny decision' : 'Monitor only'}</strong></div><div><span>Managed egress</span><strong>{settings.egress_enabled ? 'Enabled' : 'Off'}</strong></div><div><span>Protected services</span><strong>{count(resources.filter((item) => item.enabled).length)}</strong></div><div><span>Recent policy decisions</span><strong>{count((bundle.attempts || []).length)}</strong></div><p>Configure only the networks and services you are authorized to protect.</p></div>}
    </div><div className="card policy-entries"><PanelHead title="Network boundaries" description="Trusted sources and protected internal services" icon={Network} />
      <div className="boundary-group"><div className="boundary-heading"><strong>Trusted networks</strong><button className="text-button" type="button" onClick={() => setShowNetwork(!showNetwork)}><Plus size={14} /> Add network</button></div>
        {showNetwork && <form className="boundary-form" onSubmit={addNetwork}><label>Label<input required value={network.label} onChange={(e) => setNetwork({ ...network, label: e.target.value })} placeholder="Network label" /></label><label>CIDR<input required value={network.cidr} onChange={(e) => setNetwork({ ...network, cidr: e.target.value })} placeholder="Network CIDR" /></label><label>Type<select value={network.kind} onChange={(e) => setNetwork({ ...network, kind: e.target.value })}><option value="office">Office</option><option value="vpn">VPN</option><option value="employee">Employee network</option><option value="partner">Partner</option><option value="other">Other</option></select></label><div className="button-row"><button className="button primary small">Add</button><button type="button" className="button secondary small" onClick={() => setShowNetwork(false)}>Cancel</button></div></form>}
        {networks.length ? networks.map((item) => <div className="boundary-row" key={item.id}><div><strong>{item.label}</strong><small>{item.cidr} · {item.kind}</small></div><button type="button" className="toggle-link" onClick={() => toggle('networks', item)} aria-label={`${item.enabled ? 'Disable' : 'Enable'} ${item.label}`}><Badge tone={item.enabled ? 'green' : 'neutral'}>{item.enabled ? 'Enabled' : 'Disabled'}</Badge></button><button type="button" className="icon-button ghost" aria-label={`Remove ${item.label}`} onClick={() => remove('networks', item)}><Trash2 size={15} /></button></div>) : <p className="more-note">No trusted networks configured.</p>}
      </div>
      <div className="boundary-group"><div className="boundary-heading"><strong>Protected services</strong><button className="text-button" type="button" onClick={() => setShowResource(!showResource)}><Plus size={14} /> Add service</button></div>
        {showResource && <form className="boundary-form" onSubmit={addResource}><label>Name<input required value={resource.name} onChange={(e) => setResource({ ...resource, name: e.target.value })} placeholder="Service name" /></label><label>Private destination CIDR<input required value={resource.destination_cidr} onChange={(e) => setResource({ ...resource, destination_cidr: e.target.value })} placeholder="Destination CIDR" /></label><label>Protocol<select value={resource.protocol} onChange={(e) => setResource({ ...resource, protocol: e.target.value })}><option>TCP</option><option>UDP</option><option>ANY</option></select></label><label>Ports<input required value={resource.ports} onChange={(e) => setResource({ ...resource, ports: e.target.value })} placeholder="Ports or ranges" /></label><div className="button-row"><button className="button primary small">Add</button><button type="button" className="button secondary small" onClick={() => setShowResource(false)}>Cancel</button></div></form>}
        {resources.length ? resources.map((item) => <div className="boundary-row" key={item.id}><div><strong>{item.name}</strong><small>{item.destination_cidr} · {item.protocol} {item.ports.join(', ')}</small></div><button type="button" className="toggle-link" onClick={() => toggle('resources', item)} aria-label={`${item.enabled ? 'Disable' : 'Enable'} ${item.name}`}><Badge tone={item.enabled ? 'green' : 'neutral'}>{item.enabled ? 'Enabled' : 'Disabled'}</Badge></button><button type="button" className="icon-button ghost" aria-label={`Remove ${item.name}`} onClick={() => remove('resources', item)}><Trash2 size={15} /></button></div>) : <p className="more-note">No protected services configured.</p>}
      </div>
    </div></div>
  </section>
}

function Adaptive({ data, source, onAction }) {
  const s = data.summary || {}; const patterns = data.patterns || []; const pending = patterns.filter((p) => p.status === 'pending'); const [reviewId, setReviewId] = useState(null); const [label, setLabel] = useState('');
  const approve = async (e, id) => { e.preventDefault(); if (await onAction('Pattern approved and rule created', `${API}/patterns/${id}/approve`, json('POST', { label }))) { setReviewId(null); setLabel('') } }
  const reject = (item) => { if (window.confirm('Reject this pattern and disable its learned rule?')) onAction('Pattern rejected', `${API}/patterns/${item.id}/reject`, { method: 'POST' }) }
  return <section id="adaptive" className="section-anchor section-block"><SectionHeading eyebrow="ANALYST WORKFLOW" title="Adaptive learning" text="Review anomalies and manage feedback." />
    <div className="adaptive-grid"><div className="card patterns-card"><PanelHead title="Patterns for review" description="Anomaly candidates in the selected source" icon={BrainCircuit} right={<Badge tone="purple">{count(pending.length)} pending</Badge>} />
      {pending.length ? <div className="pattern-list">{pending.map((item) => <div className="pattern" key={item.id} data-pattern-id={item.id}><div className="pattern-top"><div><div className="pattern-heading"><span className="pattern-icon"><Activity size={16} /></span><strong>{item.title}</strong></div><p>{item.explanation.join(' · ')}</p></div><Badge>{sourceLabel(item.traffic_source)}</Badge></div><div className="pattern-meta"><span>{count(item.occurrences)} occurrence{item.occurrences === 1 ? '' : 's'}</span><span>Anomaly score {percent(item.anomaly_score)}</span><span>{relative(item.last_seen)}</span></div>{reviewId === item.id ? <form className="review-form" onSubmit={(e) => approve(e, item.id)}><label className="sr-only" htmlFor={`label-${item.id}`}>Pattern label</label><input id={`label-${item.id}`} value={label} onChange={(e) => setLabel(e.target.value)} placeholder="Analyst label" required minLength={2} maxLength={80} /><button className="button primary small">Approve</button><button type="button" className="button secondary small" onClick={() => setReviewId(null)}>Cancel</button></form> : <div className="pattern-actions"><button className="text-button" type="button" onClick={() => { setReviewId(item.id); setLabel('') }}>Review & approve <ArrowRight size={14} /></button><button className="text-button muted-button" type="button" onClick={() => reject(item)}>Reject</button></div>}</div>)}</div> : <Empty icon={BrainCircuit} title="No patterns awaiting review" detail="Unknown anomalies can be reviewed here as they are observed." />}
    </div><div className="card learning-card"><PanelHead title="Learning lifecycle" description="Human-reviewed, source-specific feedback" icon={RefreshCw} /><div className="learning-stats"><div><span>Approved patterns</span><strong>{count(s.approvedPatterns)}</strong></div><div><span>Active learned rules</span><strong>{count(s.activeRules)}</strong></div><div><span>Feedback records</span><strong>{count(s.feedbackExamples)}</strong></div></div><p>Train and review a candidate using approved feedback. Rules remain scoped to their traffic source.</p><button className="button secondary full" type="button" disabled={!s.feedbackExamples || data.training?.state === 'running'} onClick={() => onAction('Candidate training started', `${API}/model/retrain?source=${encodeURIComponent(source)}`, { method: 'POST' })}><RefreshCw size={15} /> {data.training?.state === 'running' ? 'Training candidate…' : 'Train candidate model'}</button><div className="training-state">{data.training?.state === 'failed' ? `Training failed: ${data.training.error}` : data.training?.state === 'ready' ? 'Candidate ready for review in Model & health.' : 'Training uses synthetic baseline plus approved feedback.'}</div></div></div>
  </section>
}

function ModelHealth({ data, onAction }) {
  const model = data.model || {}; const metrics = model.metrics || {}; const candidate = model.candidate_metrics; const evaluationLabel = metrics.source === 'synthetic' ? 'synthetic data only' : metrics.source ? 'synthetic + feedback' : 'not available'; const s = data.summary || {}; const importance = Object.entries(model.feature_importance || {}).sort((a, b) => b[1] - a[1]).slice(0, 5); const maxImportance = Math.max(...importance.map(([, value]) => value), .01)
  return <section id="model" className="section-anchor section-block"><SectionHeading eyebrow="MODEL GOVERNANCE" title="Model & health" text="Model scores, evaluation and lifecycle." />
    <div className="model-grid"><div className="card confidence-card"><PanelHead title="Detection confidence" description="Average score for supervised ML alerts in this view" icon={Cpu} /><div className="confidence-main"><strong>{percent(s.modelScores?.average)}</strong><div><span>Average model score</span><small>Across {count(s.modelScores?.count)} supervised or hybrid ML alerts</small></div></div><div className="confidence-track"><span style={{ width: `${Math.max(0, Math.min(100, (s.modelScores?.average || 0) * 100))}%` }} /></div><p className="explanation">Scores are uncalibrated, may span model versions and do not measure real-world accuracy.</p><div className="synthetic-metrics"><div><span>Held-out accuracy</span><strong>{percent(metrics.accuracy)}</strong><small>{evaluationLabel}</small></div><div><span>Weighted F1</span><strong>{percent(metrics.weighted_f1)}</strong><small>{evaluationLabel}</small></div><div><span>Evaluation records</span><strong>{count(metrics.test_rows)}</strong><small>held-out records</small></div></div>{metrics.source && metrics.source !== 'synthetic' && <p className="explanation">Active evaluation: {metrics.source}. Augmented feedback may overlap training and test partitions.</p>}{metrics.anomaly && <div className="anomaly-metrics"><strong>Isolation forest · {evaluationLabel}</strong><span>Normal false flags <b>{percent(metrics.anomaly.normal_false_flag_rate)}</b></span><span>Known attack flags <b>{percent(metrics.anomaly.attack_flag_rate)}</b></span><small>These describe the anomaly component only, not real-world performance or detection of every unknown attack.</small></div>}</div>
      <div className="card feature-card"><PanelHead title="Model signals" description="Top importances · bars scaled to the strongest signal" icon={Database} />{importance.length ? <div className="feature-list">{importance.map(([name, value]) => <div className="feature" key={name}><div><span>{human(name)}</span><strong>{percent(value)}</strong></div><div className="feature-track"><span style={{ width: `${value / maxImportance * 100}%` }} /></div></div>)}</div> : <Empty icon={Cpu} title="No model details" detail="Start Commander with a trained model to see features." />}{model.candidate_available && <div className="candidate-review"><strong>Candidate evaluation</strong>{candidate ? <><span>{candidate.source}</span><div><span>Held-out accuracy <b>{percent(candidate.accuracy)}</b></span><span>Reference F1 <b>{percent(candidate.reference_f1)}</b></span><span>Test rows <b>{count(candidate.test_rows)}</b></span></div><small>Includes synthetic data and augmented feedback; near-duplicate feedback can make results optimistic. Validate separately.</small></> : <span>Metrics unavailable; inspect the candidate before activation.</span>}</div>}<div className="model-controls"><div><strong>Model lifecycle</strong><small>{model.candidate_available ? 'Candidate available' : 'No candidate available'} · {model.rollback_available ? 'Rollback available' : 'No rollback available'}</small></div><div className="button-row"><button className="button secondary small" disabled={!model.candidate_available} type="button" onClick={() => { if (window.confirm('Activate the candidate model? Review its synthetic metrics first.')) onAction('Candidate activated', `${API}/model/activate`, { method: 'POST' }) }}>Activate</button><button className="button secondary small" disabled={!model.rollback_available} type="button" onClick={() => { if (window.confirm('Restore the previous model?')) onAction('Previous model restored', `${API}/model/rollback`, { method: 'POST' }) }}>Rollback</button></div></div></div>
    </div><div className="safety-note"><TriangleAlert size={17} /><span><strong>Validation required:</strong> Evaluate this experimental model on labeled traffic before relying on alerts or enabling blocking.</span></div>
  </section>
}

export default function App() {
  const [data, setData] = useState({}); const [connected, setConnected] = useState(false); const [source, setSource] = useState('all'); const [active, setActive] = useState('overview')
  const [toast, setToast] = useState(null); const [keyPrompt, setKeyPrompt] = useState(null)
  const requestId = useRef(0); const scrollAnimation = useRef(null); const scrollTarget = useRef(false); const scrollStartedAt = useRef(0); const refreshRef = useRef(() => {}); const keyWaiters = useRef([])
  const requestApiKey = (invalid) => new Promise((resolve) => { keyWaiters.current.push(resolve); setKeyPrompt((current) => ({ invalid: current?.invalid || invalid })) })
  const resolveApiKey = (key) => {
    if (key) rememberApiKey(key)
    setKeyPrompt(null)
    const pending = keyWaiters.current.splice(0)
    pending.forEach((resolve) => resolve(Boolean(key)))
  }
  useEffect(() => () => { keyWaiters.current.splice(0).forEach((resolve) => resolve(false)) }, [])
  const refresh = useCallback(async () => {
    const id = ++requestId.current; const q = `?source=${encodeURIComponent(source)}`
    try {
      const [summary, alerts, blocks, policy, patterns, model, health, training] = await Promise.all([
        api(`${API}/summary${q}`), api(`${API}/alerts${q}&limit=100`), api(`${API}/blocklist${q}`), api(`${API}/access-policy${q}`), api(`${API}/patterns${q}`), api(`${API}/model/info`), api('/health'), api(`${API}/model/retrain/status`),
      ])
      if (id === requestId.current) { setData({ summary, alerts, blocks, policy, patterns, model, health, training }); setConnected(true) }
    } catch {
      if (id === requestId.current) setConnected(false)
    }
  }, [source])
  refreshRef.current = refresh
  useEffect(() => {
    let closed = false; let socket; let reconnect; let debounce
    const open = () => {
      if (closed) return
      socket = new WebSocket(`${location.protocol === 'https:' ? 'wss:' : 'ws:'}//${location.host}/ws/alerts`)
      socket.onmessage = () => { clearTimeout(debounce); debounce = setTimeout(() => refreshRef.current(), 500) }
      socket.onclose = () => { if (!closed) reconnect = setTimeout(open, 4000) }
      socket.onerror = () => socket.close()
    }
    refresh(); const timer = setInterval(refresh, 5000); open()
    return () => { closed = true; ++requestId.current; clearInterval(timer); clearTimeout(reconnect); clearTimeout(debounce); socket?.close() }
  }, [refresh])
  useEffect(() => { if (!toast) return; const timer = setTimeout(() => setToast(null), 5500); return () => clearTimeout(timer) }, [toast])
  useEffect(() => {
    let ticking = false
    const update = () => {
      if (ticking || scrollTarget.current) return
      ticking = true; requestAnimationFrame(() => {
        const offset = window.innerWidth <= 760 ? 180 : 120
        let current = 'overview'
        for (const item of nav) { const element = document.getElementById(item.id); if (element && element.getBoundingClientRect().top <= offset) current = item.id }
        if (window.innerHeight + window.scrollY >= document.documentElement.scrollHeight - 8) current = 'model'
        setActive(current); ticking = false
      })
    }
    window.addEventListener('scroll', update, { passive: true }); update(); return () => window.removeEventListener('scroll', update)
  }, [])
  const goTo = (id) => {
    const element = document.getElementById(id)
    if (!element) return
    if (scrollAnimation.current) cancelAnimationFrame(scrollAnimation.current)
    scrollAnimation.current = null
    const start = window.scrollY
    const targetPosition = () => {
      const sidebar = document.querySelector('.sidebar')
      const offset = window.innerWidth <= 760 ? (sidebar?.getBoundingClientRect().height || 100) + 20 : 24
      return Math.max(0, Math.min(document.documentElement.scrollHeight - window.innerHeight, element.getBoundingClientRect().top + window.scrollY - offset))
    }
    const target = targetPosition()
    setActive(id)
    if (Math.abs(target - start) < 2) {
      scrollTarget.current = false
      window.scrollTo(0, target)
      return
    }
    // Animate the document itself, not an inner panel. Re-measure the target so
    // a changing alert list cannot leave navigation short of its destination.
    scrollTarget.current = true
    const started = performance.now(); scrollStartedAt.current = started
    const duration = 900
    const animate = (now) => {
      const progress = Math.min(1, (now - started) / duration)
      const eased = progress < .5 ? 2 * progress * progress : 1 - (-2 * progress + 2) ** 2 / 2
      window.scrollTo(0, start + (targetPosition() - start) * eased)
      if (progress < 1) scrollAnimation.current = requestAnimationFrame(animate)
      else { scrollAnimation.current = null; scrollTarget.current = false }
    }
    scrollAnimation.current = requestAnimationFrame(animate)
  }
  useEffect(() => {
    const cancel = (event) => {
      // Ignore residual trackpad momentum immediately after a navigation click.
      if (event?.type === 'wheel' && performance.now() - scrollStartedAt.current < 250) return
      if (scrollAnimation.current) { cancelAnimationFrame(scrollAnimation.current); scrollAnimation.current = null; scrollTarget.current = false }
    }
    const cancelOnKey = (event) => { if (['ArrowUp', 'ArrowDown', 'PageUp', 'PageDown', 'Home', 'End', 'Escape', ' '].includes(event.key)) cancel(event) }
    window.addEventListener('wheel', cancel, { passive: true }); window.addEventListener('touchstart', cancel, { passive: true }); window.addEventListener('keydown', cancelOnKey)
    return () => { window.removeEventListener('wheel', cancel); window.removeEventListener('touchstart', cancel); window.removeEventListener('keydown', cancelOnKey); cancel() }
  }, [])
  const onAction = async (success, path, options, returnData = false) => {
    for (;;) {
      try { const result = await api(path, options); setToast({ ok: true, text: success }); await refreshRef.current(); return returnData ? result : true }
      catch (error) {
        if (error.status === 401) {
          // Another protected action may already have obtained a key while this request was in flight.
          if (error.keyVersion !== apiKeyVersion) continue
          const invalid = Boolean(getApiKey())
          if (invalid) forgetApiKey()
          if (await requestApiKey(invalid)) continue
          return false
        }
        setToast({ ok: false, text: error.message || 'Request failed' }); return false
      }
    }
  }
  return <div className="app-shell"><Sidebar active={active} goTo={goTo} connected={connected} /><main className="main"><div className="content">
    {!connected && <div className="connection-warning" role="status"><TriangleAlert size={16} /> Commander is unavailable. Start the API to load current data.</div>}
    <Overview data={data} source={source} setSource={setSource} /><Traffic data={data} onAction={onAction} /><Alerts data={data} /><Pcap onAction={onAction} onViewAlerts={() => { setSource('pcap'); goTo('alerts') }} /><Policy data={data} onAction={onAction} /><Adaptive data={data} source={source} onAction={onAction} /><ModelHealth data={data} onAction={onAction} />
    <footer className="page-footer"><span>Cloud-Based Network Packet Sniffer with Integrated Machine Learning and Firewall Security</span></footer>
  </div></main>{toast && <div className={`toast ${toast.ok ? 'success' : 'error'}`} role="status">{toast.ok ? <Check size={17} /> : <TriangleAlert size={17} />}<span>{toast.text}</span><button type="button" aria-label="Dismiss notification" onClick={() => setToast(null)}><X size={15} /></button></div>}{keyPrompt && <KeyRequestDialog invalid={keyPrompt.invalid} onSubmit={resolveApiKey} onCancel={() => resolveApiKey('')} />}</div>
}
