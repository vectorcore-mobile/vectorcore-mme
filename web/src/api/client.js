const BASE = '/api/v1'

async function request(method, path, body) {
  const opts = { method, headers: {} }
  if (body !== undefined) {
    opts.headers['Content-Type'] = 'application/json'
    opts.body = JSON.stringify(body)
  }
  const res = await fetch(`${BASE}${path}`, opts)
  if (res.status === 204) return null
  if (!res.ok) {
    let msg = `HTTP ${res.status}`
    try {
      const data = await res.json()
      msg = data.detail || data.message || data.error || msg
      if (data.errors && data.errors.length > 0) {
        msg += ': ' + data.errors.map(e => `${e.path || e.location || '?'} — ${e.message}`).join('; ')
      }
    } catch {}
    throw new Error(msg)
  }
  return res.json()
}

// eNodeBs
export const getENBs = () => request('GET', '/enodeb').then(r => r?.enbs ?? [])

// UEs
export const getUEs = () => request('GET', '/ue').then(r => r?.ues ?? [])
export const getUEByIMSI = (imsi) => request('GET', `/ue/${encodeURIComponent(imsi)}`)

// OAM
export const getVersion = () => request('GET', '/oam/version')
export const getHealth = () => request('GET', '/oam/health')
export const getInterfaces = () => request('GET', '/oam/interfaces').then(r => r?.interfaces ?? [])
export const getDNSCache = () => request('GET', '/oam/dns-cache').then(r => r?.entries ?? [])
export const flushDNSCache = () => request('POST', '/oam/dns-cache/flush')

// Raw Prometheus
export async function getPrometheusText() {
  const res = await fetch('/metrics')
  if (!res.ok) throw new Error(`HTTP ${res.status}`)
  return res.text()
}

// Prometheus text parser
export function parsePrometheusText(text) {
  const metrics = {}
  if (!text) return metrics
  const lines = text.split('\n')
  const currentHelp = {}
  const currentType = {}
  for (const raw of lines) {
    const line = raw.trim()
    if (!line || line.startsWith('#')) {
      if (line.startsWith('# HELP ')) {
        const rest = line.slice(7)
        const sp = rest.indexOf(' ')
        currentHelp[rest.slice(0, sp)] = rest.slice(sp + 1)
      } else if (line.startsWith('# TYPE ')) {
        const parts = line.slice(7).split(' ')
        currentType[parts[0]] = parts[1]
      }
      continue
    }
    const braceOpen = line.indexOf('{')
    const spaceIdx = line.lastIndexOf(' ')
    let name, labelsStr, value
    if (braceOpen !== -1) {
      const braceClose = line.indexOf('}')
      name = line.slice(0, braceOpen)
      labelsStr = line.slice(braceOpen + 1, braceClose)
      const rest = line.slice(braceClose + 1).trim()
      value = parseFloat(rest.split(' ')[0])
    } else {
      name = line.slice(0, spaceIdx)
      labelsStr = ''
      value = parseFloat(line.slice(spaceIdx + 1).split(' ')[0])
    }
    const labels = {}
    if (labelsStr) {
      const re = /(\w+)="([^"]*)"/g
      let m
      while ((m = re.exec(labelsStr)) !== null) labels[m[1]] = m[2]
    }
    if (!metrics[name]) {
      metrics[name] = { name, help: currentHelp[name] || '', type: currentType[name] || 'untyped', samples: [] }
    }
    metrics[name].samples.push({ labels, value })
  }
  return metrics
}

export function sumMetric(metrics, name) {
  const m = metrics[name]
  if (!m) return 0
  return m.samples.reduce((acc, s) => acc + (isNaN(s.value) ? 0 : s.value), 0)
}

export function getMetricValue(metrics, name) {
  const m = metrics[name]
  if (!m || m.samples.length === 0) return null
  return m.samples[0].value
}
