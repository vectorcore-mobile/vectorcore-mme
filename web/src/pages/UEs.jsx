import React, { useState, useCallback } from 'react'
import { Users, RefreshCw, XCircle, ChevronDown, ChevronRight } from 'lucide-react'
import Spinner from '../components/Spinner.jsx'
import { usePoller } from '../hooks/usePoller.js'
import { getUEs } from '../api/client.js'

const EMM_STATE_COLORS = {
  'EMM-REGISTERED':       { color: 'var(--success)', bg: 'color-mix(in srgb, var(--success) 12%, transparent)' },
  'EMM-DEREGISTERED':     { color: 'var(--text-muted)', bg: 'var(--bg-elevated)' },
  'EMM-COMMON-PROCEDURE': { color: 'var(--warning)', bg: 'color-mix(in srgb, var(--warning) 12%, transparent)' },
}

function emmStateBadge(state) {
  const style = EMM_STATE_COLORS[state] || { color: 'var(--text-muted)', bg: 'var(--bg-elevated)' }
  return (
    <span style={{
      background: style.bg,
      color: style.color,
      padding: '2px 8px',
      borderRadius: 999,
      fontWeight: 600,
      fontSize: '0.7rem',
      whiteSpace: 'nowrap',
    }}>
      {state || '—'}
    </span>
  )
}

function UEDetailRow({ ue }) {
  return (
    <tr>
      <td colSpan={6} style={{ padding: 0, background: 'var(--bg-elevated)', borderBottom: '1px solid var(--border)' }}>
        <div style={{ padding: '12px 32px', display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(220px, 1fr))', gap: '8px 24px' }}>
          {[
            ['MME UE S1AP ID', ue.mme_ue_s1ap_id],
            ['eNB UE S1AP ID', ue.enb_ue_s1ap_id],
            ['eNB Global ID',  ue.enb_global_id],
            ['GUTI',           ue.guti],
            ['TAI',            ue.tai],
            ['Integrity Alg',  ue.int_alg != null ? `EIA${ue.int_alg}` : null],
            ['Ciphering Alg',  ue.enc_alg != null ? `EEA${ue.enc_alg}` : null],
            ['MSISDN',         ue.msisdn],
            ['APN',            ue.apn],
            ['Last Modified',  ue.last_modified],
          ].map(([label, val]) => (
            <div key={label} style={{ fontSize: '0.75rem' }}>
              <span style={{ color: 'var(--text-muted)', marginRight: 6 }}>{label}:</span>
              <span className="mono" style={{ color: 'var(--text-primary)' }}>{val || '—'}</span>
            </div>
          ))}
        </div>
      </td>
    </tr>
  )
}

export default function UEs() {
  const [expanded, setExpanded] = useState(new Set())
  const fetchFn = useCallback(getUEs, [])
  const { data: ues, error, loading, refresh } = usePoller(fetchFn, 5000)

  const rows = Array.isArray(ues) ? ues : []

  function toggle(imsi) {
    setExpanded(prev => {
      const next = new Set(prev)
      next.has(imsi) ? next.delete(imsi) : next.add(imsi)
      return next
    })
  }

  if (loading) {
    return (
      <div className="loading-center">
        <Spinner size="lg" />
        <span>Loading UEs...</span>
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
          <div className="page-title">UEs</div>
          <div className="page-subtitle">Attached user equipment — 5s polling</div>
        </div>
        <button className="btn btn-ghost" onClick={refresh}>
          <RefreshCw size={14} /> Refresh
        </button>
      </div>

      {rows.length === 0 ? (
        <div className="empty-state">
          <Users size={32} style={{ opacity: 0.3, marginBottom: 8 }} />
          <div>No UEs currently attached.</div>
        </div>
      ) : (
        <div className="table-container">
          <table>
            <thead>
              <tr>
                <th style={{ width: 24 }}></th>
                <th>IMSI</th>
                <th>EMM State</th>
                <th>GUTI</th>
                <th>eNB</th>
                <th>MSISDN</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((ue, i) => {
                const imsi = ue.imsi || String(i)
                const isOpen = expanded.has(imsi)
                return (
                  <React.Fragment key={imsi}>
                    <tr
                      onClick={() => toggle(imsi)}
                      style={{ cursor: 'pointer' }}
                    >
                      <td style={{ color: 'var(--text-muted)', padding: '0 4px 0 8px' }}>
                        {isOpen ? <ChevronDown size={13} /> : <ChevronRight size={13} />}
                      </td>
                      <td className="mono" style={{ fontSize: '0.82rem', fontWeight: 600, color: 'var(--accent)' }}>
                        {ue.imsi || '—'}
                      </td>
                      <td>{emmStateBadge(ue.emm_state)}</td>
                      <td className="mono" style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                        {ue.guti || '—'}
                      </td>
                      <td className="mono" style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>
                        {ue.enb_global_id || '—'}
                      </td>
                      <td className="mono" style={{ fontSize: '0.78rem' }}>
                        {ue.msisdn || '—'}
                      </td>
                    </tr>
                    {isOpen && <UEDetailRow ue={ue} />}
                  </React.Fragment>
                )
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
