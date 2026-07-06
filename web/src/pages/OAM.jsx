import React, { useState, useCallback, useEffect, useRef } from 'react'
import { RefreshCw, CheckCircle, XCircle, Activity, Shield, Wifi } from 'lucide-react'
import Spinner from '../components/Spinner.jsx'
import { usePoller } from '../hooks/usePoller.js'
import { getVersion, getHealth } from '../api/client.js'

function formatUptime(seconds) {
  if (!seconds && seconds !== 0) return '—'
  const d = Math.floor(seconds / 86400)
  const h = Math.floor((seconds % 86400) / 3600)
  const m = Math.floor((seconds % 3600) / 60)
  const s = Math.floor(seconds % 60)
  if (d > 0) return `${d}d ${h}h ${m}m ${s}s`
  if (h > 0) return `${h}h ${m}m ${s}s`
  if (m > 0) return `${m}m ${s}s`
  return `${s}s`
}

export default function OAM() {
  const fetchFn = useCallback(getVersion, [])
  const { data: version, error: versionError, loading, refresh } = usePoller(fetchFn, 5000)

  const [health, setHealth] = useState(null)
  const [healthError, setHealthError] = useState(null)
  const healthTimerRef = useRef(null)
  const mountedRef = useRef(true)

  const fetchHealth = useCallback(async () => {
    try {
      const h = await getHealth()
      if (mountedRef.current) { setHealth(h); setHealthError(null) }
    } catch (err) {
      if (mountedRef.current) { setHealth(null); setHealthError(err.message || 'Health check failed') }
    }
  }, [])

  useEffect(() => {
    mountedRef.current = true
    fetchHealth()
    healthTimerRef.current = setInterval(fetchHealth, 5000)
    return () => {
      mountedRef.current = false
      clearInterval(healthTimerRef.current)
    }
  }, [fetchHealth])

  if (loading && !version) {
    return <div className="loading-center"><Spinner size="lg" /><span>Loading OAM...</span></div>
  }

  return (
    <div>
      <div className="page-header">
        <div>
          <div className="page-title">OAM</div>
          <div className="page-subtitle">Operations, administration, and maintenance</div>
        </div>
        <button className="btn btn-ghost" onClick={() => { refresh(); fetchHealth() }}>
          <RefreshCw size={14} /> Refresh
        </button>
      </div>

      {/* System Identity */}
      <div className="oam-section">
        <div className="flex items-center gap-8 mb-16">
          <Shield size={16} style={{ color: 'var(--accent)' }} />
          <h3 className="card-title">System Identity</h3>
        </div>
        {versionError && !version ? (
          <div className="error-state" style={{ padding: '20px 0' }}>
            <XCircle size={20} className="error-icon" /><div>{versionError}</div>
          </div>
        ) : (
          <div className="detail-grid">
            {[
              ['Application',   version?.app_name    || 'VectorCore MME'],
              ['App Version',   version?.app_version || '—'],
              ['Origin Host',   version?.origin_host  || '—'],
              ['Origin Realm',  version?.origin_realm || '—'],
              ['MCC',           version?.mcc          || '—'],
              ['MNC',           version?.mnc          || '—'],
              ['MMEGI',         version?.mmegi != null ? String(version.mmegi) : '—'],
              ['MMEC',          version?.mmec  != null ? String(version.mmec)  : '—'],
            ].map(([label, val]) => (
              <div key={label} className="detail-row">
                <span className="detail-label">{label}</span>
                <span className="detail-value mono">{val}</span>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Health */}
      <div className="oam-section">
        <div className="flex items-center gap-8 mb-16">
          <Activity size={16} style={{ color: healthError ? 'var(--danger)' : 'var(--success)' }} />
          <h3 className="card-title">Health</h3>
          <button className="btn-icon btn-sm" onClick={fetchHealth} title="Refresh health">
            <RefreshCw size={12} />
          </button>
        </div>

        <div className="flex items-center gap-12" style={{ marginBottom: health ? 16 : 0 }}>
          {healthError ? (
            <><XCircle size={20} style={{ color: 'var(--danger)' }} />
              <div>
                <div style={{ fontWeight: 600, color: 'var(--danger)' }}>UNHEALTHY</div>
                <div className="text-muted text-sm">{healthError}</div>
              </div></>
          ) : health ? (
            <><CheckCircle size={20} style={{ color: 'var(--success)' }} />
              <div>
                <div style={{ fontWeight: 600, color: 'var(--success)' }}>{health.status?.toUpperCase() || 'OK'}</div>
              </div></>
          ) : (
            <div className="flex items-center gap-8 text-muted text-sm"><Spinner size="sm" /> Checking...</div>
          )}
        </div>

        {health && (
          <div className="detail-grid">
            {[
              ['Uptime',          formatUptime(health.uptime_seconds)],
              ['Attached UEs',    health.attached_ues  != null ? String(health.attached_ues)   : '—'],
              ['Connected eNBs',  health.connected_enbs != null ? String(health.connected_enbs) : '—'],
            ].map(([label, val]) => (
              <div key={label} className="detail-row">
                <span className="detail-label">{label}</span>
                <span className="detail-value mono">{val}</span>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* S6a Connection */}
      <div className="oam-section">
        <div className="flex items-center gap-8 mb-16">
          <Wifi size={16} style={{ color: 'var(--accent)' }} />
          <h3 className="card-title">S6a Connection (Diameter)</h3>
        </div>
        <div className="flex items-center gap-8">
          {health == null ? (
            <div className="flex items-center gap-8 text-muted text-sm"><Spinner size="sm" /> Checking...</div>
          ) : health.s6a_connected ? (
            <><CheckCircle size={18} style={{ color: 'var(--success)' }} />
              <span style={{ color: 'var(--success)', fontWeight: 600 }}>Peer connected</span></>
          ) : (
            <><XCircle size={18} style={{ color: 'var(--warning)' }} />
              <span style={{ color: 'var(--warning)', fontWeight: 600 }}>No peer connected</span>
              <span className="text-muted text-sm" style={{ marginLeft: 4 }}>
                — DRA/HSS has not established a Diameter connection on {version?.origin_host ?? ''}:3868
              </span></>
          )}
        </div>
      </div>
    </div>
  )
}
