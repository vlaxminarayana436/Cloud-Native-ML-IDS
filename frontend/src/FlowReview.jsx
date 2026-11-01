import React, { useCallback, useEffect, useRef, useState } from 'react'
import { Check, ChevronDown, ClipboardCheck, Download, RefreshCw, ShieldCheck, TriangleAlert, X } from 'lucide-react'

const API = '/api/v1'
const sourceNames = { all: 'All sources', capture: 'Live capture', synthetic: 'Synthetic', pcap: 'Offline PCAP', unknown: 'Unspecified' }
const labels = { benign: 'Benign', malicious: 'Malicious', unsure: 'Unsure' }
const labelTones = { benign: 'green', malicious: 'amber', unsure: 'purple' }
const count = (value) => value == null ? '—' : Number(value).toLocaleString()
const human = (value) => String(value || 'Unknown').replaceAll('_', ' ')
const address = (ip, port) => {
  const value = ip || 'Unknown'
  return port == null ? value : `${value.includes(':') ? `[${value}]` : value}:${port}`
}
const prediction = (event) => event.classification === 'Normal' ? 'Normal' : event.classification === 'Policy_Denied' ? 'Policy decision' : human(event.attack_type)
const shownTime = (seconds) => seconds ? new Date(seconds * 1000).toLocaleString() : 'Time unavailable'
const json = (method, body) => ({ method, ...(body === undefined ? {} : { body: JSON.stringify(body) }) })

function ReviewDialog({ event, onAction, onClose, onSaved }) {
  const [label, setLabel] = useState(event.review?.label || '')
  const [note, setNote] = useState(event.review?.note || '')
  const [busy, setBusy] = useState(false)
  const formRef = useRef(null)
  useEffect(() => {
    const previous = document.activeElement
    formRef.current?.querySelector('input[type="radio"]')?.focus()
    return () => previous?.focus?.()
  }, [])
  const handleKeyDown = (e) => {
    if (e.key === 'Escape' && !busy) { e.preventDefault(); onClose(); return }
    if (e.key !== 'Tab') return
    const controls = [...formRef.current.querySelectorAll('input:not(:disabled), textarea:not(:disabled), button:not(:disabled)')]
    if (e.shiftKey && document.activeElement === controls[0]) { e.preventDefault(); controls.at(-1)?.focus() }
    else if (!e.shiftKey && document.activeElement === controls.at(-1)) { e.preventDefault(); controls[0]?.focus() }
  }
  const save = async (e) => {
    e.preventDefault()
    if (!label || busy) return
    setBusy(true)
    const saved = await onAction('Flow review saved. Detection and firewall unchanged.', `${API}/events/${event.id}/review`, json('PUT', { label, note }))
    setBusy(false)
    if (saved) onSaved()
  }
  const clear = async () => {
    if (busy || !window.confirm('Remove this assessment and return the flow to Unreviewed?')) return
    setBusy(true)
    const removed = await onAction('Flow review removed.', `${API}/events/${event.id}/review`, { method: 'DELETE' })
    setBusy(false)
    if (removed) onSaved()
  }
  const f = event.features || {}
  return <div className="flow-review-backdrop"><form ref={formRef} className="flow-review-dialog" role="dialog" aria-modal="true" aria-labelledby="flow-review-dialog-title" aria-describedby="flow-review-dialog-description" onSubmit={save} onKeyDown={handleKeyDown}>
    <div className="flow-dialog-title"><div><span className="eyebrow">ANALYST ASSESSMENT</span><h2 id="flow-review-dialog-title">Review flow #{event.id}</h2></div><button className="icon-button ghost" type="button" aria-label="Close flow review" disabled={busy} onClick={onClose}><X size={18} /></button></div>
    <p id="flow-review-dialog-description" className="flow-dialog-intro">A flow summary alone cannot prove an attack or identify a website. Use trusted context, and choose <strong>Unsure</strong> if you cannot verify it.</p>
    <div className="flow-evidence"><div><span>Recorded result</span><strong>{prediction(event)}</strong></div><div><span>Origin</span><strong>{sourceNames[event.traffic_source] || 'Unspecified'} · {event.protocol}</strong></div><div className="flow-evidence-wide"><span>Source → destination</span><strong>{address(event.src_ip, event.src_port)} → {address(event.dst_ip, event.dst_port)}</strong></div><div className="flow-evidence-wide"><span>Flow details</span><strong>{count(f.packet_count)} packets · {count(f.byte_count)} bytes · {shownTime(event.timestamp)}</strong></div></div>
    <fieldset className="assessment-fieldset"><legend>Assessment</legend><div className="assessment-options">{[
      ['benign', 'Legitimate, based on evidence'], ['malicious', 'Malicious, based on evidence'], ['unsure', 'Not enough evidence yet'],
    ].map(([value, detail]) => <label className={`assessment-option ${label === value ? 'selected' : ''}`} key={value}><input type="radio" name="assessment" value={value} checked={label === value} disabled={busy} onChange={() => setLabel(value)} /><span><strong>{labels[value]}</strong><small>{detail}</small></span></label>)}</div></fieldset>
    <label className="review-note-label" htmlFor="flow-review-note">Evidence note <span>optional</span></label><textarea id="flow-review-note" rows="3" maxLength={500} disabled={busy} value={note} onChange={(e) => setNote(e.target.value)} placeholder="How did you verify this? Avoid personal or sensitive information." />
    <p className="review-safety"><ShieldCheck size={16} /><span>Saving does not change the model, create a rule, or block traffic. A review is an assessment, not automatically verified ground truth.</span></p>
    <div className="flow-dialog-actions">{event.review && <button className="button secondary small clear-review" type="button" disabled={busy} onClick={clear}>Clear review</button>}<button className="button secondary" type="button" disabled={busy} onClick={onClose}>Cancel</button><button className="button primary" type="submit" disabled={!label || busy}>{busy ? 'Saving…' : 'Save review'}</button></div>
  </form></div>
}

export default function FlowReview({ source, onAction }) {
  const [detection, setDetection] = useState('alerts')
  const [status, setStatus] = useState('unreviewed')
  const [pages, setPages] = useState([null])
  const [page, setPage] = useState(null)
  const [selected, setSelected] = useState(null)
  const [loading, setLoading] = useState(false)
  const [exporting, setExporting] = useState(false)
  const [error, setError] = useState('')
  const [exportNotice, setExportNotice] = useState('')
  const requestId = useRef(0)
  const cursor = pages.at(-1)
  const parameters = useCallback(() => new URLSearchParams({ source, detection, status }), [source, detection, status])
  const load = useCallback(async () => {
    const id = ++requestId.current
    setLoading(true); setError(''); setExportNotice('')
    try {
      const params = parameters(); params.set('limit', '20')
      if (cursor != null) params.set('before_id', String(cursor))
      const response = await fetch(`${API}/reviews?${params}`)
      if (!response.ok) throw new Error('Could not load reviews. Make sure Commander is running the updated project.')
      const result = await response.json()
      if (id === requestId.current) setPage(result)
    } catch (err) {
      if (id === requestId.current) setError(err.message || 'Could not load flow reviews.')
    } finally {
      if (id === requestId.current) setLoading(false)
    }
  }, [parameters, cursor])
  useEffect(() => { load(); return () => { requestId.current += 1 } }, [load])
  const resetFilters = (setter, value) => { setPage(null); setPages([null]); setter(value) }
  const refresh = () => { if (pages.length > 1) { setPage(null); setPages([null]) } else load() }
  const download = async () => {
    setExporting(true); setExportNotice(''); setError('')
    try {
      const response = await fetch(`${API}/reviews/export.csv?${parameters()}`)
      if (!response.ok) throw new Error('Could not export flow features.')
      const blob = await response.blob(); const url = URL.createObjectURL(blob)
      const link = document.createElement('a'); link.href = url; link.download = 'flow-features.csv'
      document.body.appendChild(link); link.click(); link.remove(); setTimeout(() => URL.revokeObjectURL(url), 1000)
      setExportNotice(response.headers.get('X-Export-Truncated') === 'true' ? 'Downloaded the newest 1,000 matching records; additional records were not included.' : 'Feature export downloaded for the selected source and filters.')
    } catch (err) { setError(err.message || 'Could not export flow features.') }
    finally { setExporting(false) }
  }
  const stats = page?.summary || {}
  const items = page?.items || []
  return <section id="review" className="section-anchor section-block">
    <div className="section-heading"><div><div className="eyebrow">ANALYST WORKFLOW</div><h2>Flow review</h2><p>Assess individual flows without changing detection or blocking.</p></div><button className="button secondary" type="button" onClick={download} disabled={loading || exporting || !items.length}><Download size={15} /> {exporting ? 'Exporting…' : 'Export features'}</button></div>
    <div className="card flow-review-card">
      <div className="review-overview-head"><div className="review-heading-icon"><ClipboardCheck size={18} /></div><div><h3>Review queue</h3><p>Assessments for <strong>{sourceNames[source] || 'All sources'}</strong> · counts cover this entire source</p></div></div>
      <div className="flow-review-stats">{[['unreviewed', 'Not reviewed'], ['benign', 'Benign'], ['malicious', 'Malicious'], ['unsure', 'Unsure']].map(([key, title]) => <div key={key}><span>{title}</span><strong>{count(stats[key])}</strong></div>)}</div>
      <div className="review-queue-toolbar"><div className="review-filter-group"><label>Model result<select aria-label="Review model result" value={detection} onChange={(e) => resetFilters(setDetection, e.target.value)}><option value="alerts">Alerts and policy decisions</option><option value="normal">Normal predictions</option><option value="all">All results</option></select><ChevronDown size={14} /></label><label>Review status<select aria-label="Review status" value={status} onChange={(e) => resetFilters(setStatus, e.target.value)}><option value="unreviewed">Not reviewed</option><option value="reviewed">All reviewed</option><option value="benign">Benign</option><option value="malicious">Malicious</option><option value="unsure">Unsure</option><option value="all">All statuses</option></select><ChevronDown size={14} /></label></div><button className="button secondary small" type="button" onClick={refresh} disabled={loading}><RefreshCw size={14} /> Refresh list</button></div>
      <div className="review-snapshot-note">List is a snapshot, so it won’t move while you review. Refresh for newer flows.</div>
      {error && <div className="flow-review-error" role="alert"><TriangleAlert size={15} />{error}</div>}
      <div className="flow-review-list" aria-busy={loading}>
        {loading ? <div className="flow-review-empty"><RefreshCw size={18} /><strong>Loading flow records…</strong></div> : !items.length ? <div className="flow-review-empty"><ClipboardCheck size={19} /><strong>No flows in this view</strong><span>Try another result or review filter, or refresh the list.</span></div> : items.map((event) => {
          const f = event.features || {}
          return <article className="flow-review-row" key={event.id} data-review-event-id={event.id}><div className="flow-row-main"><div className="flow-row-title"><strong>{prediction(event)}</strong><span className={`badge ${event.review ? labelTones[event.review.label] : 'neutral'}`}>{event.review ? labels[event.review.label] : 'Not reviewed'}</span></div><div className="flow-row-address">{address(event.src_ip, event.src_port)} <span>→</span> {address(event.dst_ip, event.dst_port)}</div><div className="flow-row-meta"><span>{sourceNames[event.traffic_source] || 'Unspecified'}</span><span>{event.protocol}</span><span>{count(f.packet_count)} packets</span><span>{shownTime(event.timestamp)}</span></div></div><button className="button secondary small" type="button" aria-label={`${event.review ? 'Edit review for' : 'Review'} flow ${event.id}`} onClick={() => setSelected(event)}>{event.review ? 'Edit review' : 'Review'}</button></article>
        })}
      </div>
      <div className="review-list-footer"><span>Page {pages.length} · {count(items.length)} records loaded</span><div><button className="button secondary small" type="button" disabled={loading || pages.length <= 1} onClick={() => { setPage(null); setPages((current) => current.slice(0, -1)) }}>Newer</button><button className="button secondary small" type="button" disabled={loading || !page?.has_more} onClick={() => { setPage(null); setPages((current) => [...current, page.next_before_id]) }}>Older</button></div></div>
      <div className="review-privacy-note"><ShieldCheck size={15} /><span>Feature export includes up to the newest 1,000 matching flows, not just this page. It omits IP addresses, raw ports, IDs, times and notes, but traffic metadata can still be sensitive. Assessments are not automatically verified labels.</span></div>
      {exportNotice && <div className="review-export-notice" role="status"><Check size={15} />{exportNotice}</div>}
    </div>
    {selected && <ReviewDialog event={selected} onAction={onAction} onClose={() => setSelected(null)} onSaved={() => { setSelected(null); load() }} />}
  </section>
}
