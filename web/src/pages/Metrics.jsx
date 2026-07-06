import React, { useCallback } from 'react'
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
} from 'recharts'
import { Activity, Radio, Users, Cpu, XCircle, RefreshCw } from 'lucide-react'
import StatCard from '../components/StatCard.jsx'
import Spinner from '../components/Spinner.jsx'
import { usePoller } from '../hooks/usePoller.js'
import { getPrometheusText, parsePrometheusText, sumMetric } from '../api/client.js'

const CustomTooltip = ({ active, payload, label }) => {
  if (!active || !payload || !payload.length) return null
  return (
    <div style={{
      background: 'var(--bg-elevated)', border: '1px solid var(--border)',
      borderRadius: 'var(--radius-sm)', padding: '8px 12px', fontSize: '0.75rem',
    }}>
      <div style={{ color: 'var(--text-muted)', marginBottom: 4, fontFamily: 'var(--font-mono)', fontSize: '0.7rem' }}>
        {label}
      </div>
      {payload.map(p => (
        <div key={p.dataKey} style={{ color: p.fill || p.color }}>
          {p.name}: <strong>{p.value}</strong>
        </div>
      ))}
    </div>
  )
}

function buildS1APData(metrics) {
  const m = metrics['mme_s1ap_messages_total']
  if (!m) return []
  const byProc = {}
  for (const s of m.samples) {
    const proc = s.labels.procedure || '?'
    byProc[proc] = (byProc[proc] || 0) + (isNaN(s.value) ? 0 : s.value)
  }
  return Object.entries(byProc)
    .map(([procedure, total]) => ({ procedure, total }))
    .sort((a, b) => b.total - a.total)
}

function buildMMEMetricsTable(metrics) {
  return Object.values(metrics)
    .filter(m => m.name.startsWith('mme_'))
    .map(m => {
      const total = m.samples.reduce((acc, s) => acc + (isNaN(s.value) ? 0 : s.value), 0)
      return { name: m.name, help: m.help, type: m.type, total }
    })
    .sort((a, b) => a.name.localeCompare(b.name))
}

export default function Metrics() {
  const fetchFn = useCallback(getPrometheusText, [])
  const { data: rawText, error, loading, refresh } = usePoller(fetchFn, 10000)

  if (loading) {
    return (
      <div className="loading-center">
        <Spinner size="lg" />
        <span>Loading metrics...</span>
      </div>
    )
  }

  if (error && !rawText) {
    return (
      <div className="error-state">
        <XCircle size={32} className="error-icon" />
        <div>{error}</div>
        <button className="btn btn-ghost mt-12" onClick={refresh}>
          <RefreshCw size={14} /> Retry
        </button>
      </div>
    )
  }

  const metrics     = parsePrometheusText(rawText || '')
  const s1apTotal   = sumMetric(metrics, 'mme_s1ap_messages_total')
  const connENBs    = sumMetric(metrics, 'mme_s1ap_connected_enbs')
  const nasTotal    = sumMetric(metrics, 'mme_nas_procedures_total')
  const s6aTotal    = sumMetric(metrics, 'mme_s6a_requests_total')
  const s1apData    = buildS1APData(metrics)
  const mmeMetrics  = buildMMEMetricsTable(metrics)

  return (
    <div>
      <div className="page-header">
        <div>
          <div className="page-title">Metrics</div>
          <div className="page-subtitle">Prometheus metrics — 10s polling</div>
        </div>
        <button className="btn btn-ghost" onClick={refresh}>
          <RefreshCw size={14} /> Refresh
        </button>
      </div>

      <div className="stats-grid">
        <StatCard title="S1AP Messages"     value={s1apTotal.toLocaleString()}  icon={<Activity size={18} />} color="var(--accent)"  />
        <StatCard title="Connected eNodeBs" value={connENBs.toLocaleString()}   icon={<Radio size={18} />}    color="var(--success)" />
        <StatCard title="NAS Procedures"    value={nasTotal.toLocaleString()}    icon={<Users size={18} />}    color="var(--warning)" />
        <StatCard title="S6a Requests"      value={s6aTotal.toLocaleString()}    icon={<Cpu size={18} />}      color="var(--info)"    />
      </div>

      {s1apData.length > 0 && (
        <div className="chart-card mb-16">
          <div className="chart-title">S1AP Messages by Procedure</div>
          <ResponsiveContainer width="100%" height={220}>
            <BarChart data={s1apData} margin={{ top: 4, right: 8, left: 0, bottom: 0 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="var(--border-subtle)" />
              <XAxis
                dataKey="procedure"
                tick={{ fontSize: 11, fill: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}
              />
              <YAxis tick={{ fontSize: 10, fill: 'var(--text-muted)' }} width={52} allowDecimals={false} />
              <Tooltip content={<CustomTooltip />} />
              <Bar dataKey="total" name="Total" fill="var(--accent)" radius={[3, 3, 0, 0]} maxBarSize={48} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      )}

      <div className="section-title mt-20">All MME Metrics</div>
      {mmeMetrics.length === 0 ? (
        <div className="empty-state">No mme_ metrics available yet.</div>
      ) : (
        <div className="table-container">
          <table>
            <thead>
              <tr>
                <th>Metric</th>
                <th>Type</th>
                <th>Total / Sum</th>
                <th>Help</th>
              </tr>
            </thead>
            <tbody>
              {mmeMetrics.map(m => (
                <tr key={m.name}>
                  <td className="mono" style={{ fontSize: '0.78rem', color: 'var(--accent)' }}>{m.name}</td>
                  <td style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>{m.type}</td>
                  <td className="mono" style={{ fontSize: '0.82rem' }}>{m.total.toLocaleString()}</td>
                  <td style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>{m.help || '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
