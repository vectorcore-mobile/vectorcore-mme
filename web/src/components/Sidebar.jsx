import React from 'react'
import { NavLink } from 'react-router-dom'
import { LayoutDashboard, Radio, Users, BarChart2, Settings } from 'lucide-react'

const NAV_ITEMS = [
  { to: '/dashboard', label: 'Dashboard',  icon: <LayoutDashboard size={16} /> },
  { to: '/enodebs',   label: 'eNodeBs',    icon: <Radio size={16} /> },
  { to: '/ues',       label: 'UEs',         icon: <Users size={16} /> },
  { to: '/metrics',   label: 'Metrics',     icon: <BarChart2 size={16} /> },
  { to: '/oam',       label: 'OAM',         icon: <Settings size={16} /> },
]

export default function Sidebar() {
  return (
    <aside className="sidebar">
      <div className="sidebar-header" style={{ textAlign: 'center' }}>
        <div className="sidebar-logo">VectorCore</div>
        <div className="sidebar-logo-sub">Mobility Management Entity</div>
        <div style={{ fontSize: '0.65rem', color: 'var(--text-muted)', marginTop: 2, letterSpacing: '0.04em' }}>
          LTE EPC S1-MME S6a S11
        </div>
      </div>

      <nav className="sidebar-nav" aria-label="Primary navigation">
        {NAV_ITEMS.map(({ to, label, icon }) => (
          <NavLink
            key={to}
            to={to}
            className={({ isActive }) => `nav-item${isActive ? ' active' : ''}`}
          >
            {icon}
            {label}
          </NavLink>
        ))}
      </nav>
    </aside>
  )
}
