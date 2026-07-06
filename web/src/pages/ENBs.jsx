import React, { useCallback } from 'react'
import { Radio, RefreshCw, XCircle } from 'lucide-react'
import Spinner from '../components/Spinner.jsx'
import { usePoller } from '../hooks/usePoller.js'
import { getENBs } from '../api/client.js'

function formatTs(ts) {
  if (!ts) return '—'
  try { return new Date(ts).toLocaleString() } catch { return String(ts) }
}

export default function ENBs() {
  const fetchFn = useCallback(getENBs, [])
  const { data: enbs, error, loading, refresh } = usePoller(fetchFn, 5000)

  const rows = Array.isArray(enbs) ? enbs : []

  if (loading) {
    return (
      <div className="loading-center">
        <Spinner size="lg" />
        <span>Loading eNodeBs...</span>
      </div>
    )
  }

  if (error && rows.length === 0) {
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

  return (
    <div>
      <div className="page-header">
        <div>
          <div className="page-title">eNodeBs</div>
          <div className="page-subtitle">Connected base stations — 5s polling</div>
        </div>
        <button className="btn btn-ghost" onClick={refresh}>
          <RefreshCw size={14} /> Refresh
        </button>
      </div>

      {rows.length === 0 ? (
        <div className="empty-state">
          <Radio size={32} style={{ opacity: 0.3, marginBottom: 8 }} />
          <div>No eNodeBs currently connected.</div>
        </div>
      ) : (
        <div className="table-container">
          <table>
            <thead>
              <tr>
                <th>Global eNB ID</th>
                <th>Name</th>
                <th>Remote Address</th>
                <th>Transport</th>
                <th>Supported TAs</th>
                <th>Connected At</th>
                <th>Last Seen</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((enb, i) => (
                <tr key={enb.global_enb_id || i}>
                  <td className="mono" style={{ fontSize: '0.8rem', color: 'var(--accent)', fontWeight: 600 }}>
                    {enb.global_enb_id || '—'}
                  </td>
                  <td style={{ fontSize: '0.82rem' }}>{enb.enb_name || '—'}</td>
                  <td className="mono" style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>
                    {enb.remote_addr || '—'}
                  </td>
                  <td style={{ fontSize: '0.78rem' }}>
                    {enb.transport ? (
                      <span style={{
                        background: 'color-mix(in srgb, var(--accent) 12%, transparent)',
                        color: 'var(--accent)',
                        padding: '2px 8px',
                        borderRadius: 999,
                        fontWeight: 600,
                        fontSize: '0.72rem',
                      }}>
                        {enb.transport}
                      </span>
                    ) : '—'}
                  </td>
                  <td style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                    {enb.supported_tas || '—'}
                  </td>
                  <td style={{ fontSize: '0.75rem', color: 'var(--text-muted)', whiteSpace: 'nowrap' }}>
                    {formatTs(enb.connected_at)}
                  </td>
                  <td style={{ fontSize: '0.75rem', color: 'var(--text-muted)', whiteSpace: 'nowrap' }}>
                    {formatTs(enb.last_seen)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
