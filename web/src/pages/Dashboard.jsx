import React, { useState, useEffect, useRef, useCallback } from 'react'
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
} from 'recharts'
import { Users, Radio, Activity, Cpu, Clock, XCircle } from 'lucide-react'
import StatCard from '../components/StatCard.jsx'
import Spinner from '../components/Spinner.jsx'
import {
  getHealth, getPrometheusText, parsePrometheusText, sumMetric,
} from '../api/client.js'

function formatUptime(s) {
  if (s == null || isNaN(s)) return '—'
  const d = Math.floor(s / 86400)
  const h = Math.floor((s % 86400) / 3600)
  const m = Math.floor((s % 3600) / 60)
  const sec = Math.floor(s % 60)
  if (d > 0) return `${d}d ${h}h ${m}m`
  if (h > 0) return `${h}h ${m}m ${sec}s`
  if (m > 0) return `${m}m ${sec}s`
  return `${sec}s`
}

const CustomTooltip = ({ active, payload, label }) => {
  if (!active || !payload || !payload.length) return null
  return (
    <div style={{
      background: 'var(--bg-elevated)', border: '1px solid var(--border)',
      borderRadius: 'var(--radius-sm)', padding: '8px 12px', fontSize: '0.75rem',
    }}>
      <div style={{ color: 'var(--text-muted)', marginBottom: 4, fontFamily: 'var(--font-mono)', fontSize: '0.7rem' }}>{label}</div>
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

export default function Dashboard() {
  const [health, setHealth] = useState(null)
  const [metrics, setMetrics] = useState({})
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const timerRef = useRef(null)
  const mountedRef = useRef(true)

  const fetchAll = useCallback(async () => {
    try {
      const [healthData, promText] = await Promise.all([
        getHealth().catch(() => null),
        getPrometheusText().catch(() => ''),
      ])
      if (!mountedRef.current) return
      setHealth(healthData)
      setMetrics(parsePrometheusText(promText || ''))
      setError(null)
      setLoading(false)
    } catch (err) {
      if (!mountedRef.current) return
      setError(err.message || 'Failed to load data')
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    mountedRef.current = true
    fetchAll()
    timerRef.current = setInterval(fetchAll, 5000)
    return () => {
      mountedRef.current = false
      clearInterval(timerRef.current)
    }
  }, [fetchAll])

  if (loading) {
    return (
      <div className="loading-center">
        <Spinner size="lg" />
        <span>Loading dashboard...</span>
      </div>
    )
  }

  if (error && !health) {
    return (
      <div className="error-state">
        <XCircle size={32} className="error-icon" />
        <div>{error}</div>
        <button className="btn btn-ghost mt-12" onClick={fetchAll}>Retry</button>
      </div>
    )
  }

  const attachedUEs    = sumMetric(metrics, 'mme_ue_attached_total')
  const connectedENBs  = sumMetric(metrics, 'mme_s1ap_connected_enbs')
  const s1apTotal      = sumMetric(metrics, 'mme_s1ap_messages_total')
  const s6aTotal       = sumMetric(metrics, 'mme_s6a_requests_total')
  const s1apData       = buildS1APData(metrics)

  return (
    <div>
      <div className="page-header">
        <div>
          <div className="page-title">Dashboard</div>
          <div className="page-subtitle">Mobility Management Entity — real-time overview</div>
        </div>
      </div>

      <div className="stats-grid">
        <StatCard title="Attached UEs"      value={(health?.attached_ues ?? attachedUEs).toLocaleString()} icon={<Users size={18} />}    color="var(--accent)"  />
        <StatCard title="Connected eNodeBs" value={(health?.connected_enbs ?? connectedENBs).toLocaleString()} icon={<Radio size={18} />}    color="var(--success)" />
        <StatCard title="S1AP Messages"     value={s1apTotal.toLocaleString()}  icon={<Activity size={18} />} color="var(--warning)" />
        <StatCard title="S6a Requests"      value={s6aTotal.toLocaleString()}   icon={<Cpu size={18} />}      color="var(--info)"    />
      </div>

      <div className="stats-grid" style={{ marginTop: 0 }}>
        <StatCard
          title="Uptime"
          value={formatUptime(health?.uptime_seconds)}
          icon={<Clock size={18} />}
          color="var(--text-muted)"
        />
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
              <YAxis tick={{ fontSize: 10, fill: 'var(--text-muted)' }} width={48} allowDecimals={false} />
              <Tooltip content={<CustomTooltip />} />
              <Bar dataKey="total" name="Total" fill="var(--accent)" radius={[3, 3, 0, 0]} maxBarSize={48} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      )}
    </div>
  )
}
