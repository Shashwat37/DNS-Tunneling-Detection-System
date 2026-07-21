import { useEffect, useState, useCallback } from 'react'
import { useParams, Link } from 'react-router-dom'
import {
  PieChart, Pie, Cell, Tooltip, ResponsiveContainer, Legend,
  BarChart, Bar, XAxis, YAxis, CartesianGrid,
  AreaChart, Area,
} from 'recharts'
import { getStoredToken } from '../context/AuthContext'

// ── Types ──────────────────────────────────────────────────────────────────

interface Summary {
  filename: string
  uploaded_at: string
  detected_format?: string
  total: number
  suspicious: number
  normal: number
  suspicious_pct: number
  top_suspicious_domains: { domain: string; count: number }[]
  entropy_distribution: { range: string; count: number }[]
  volume_over_time: { time: string; count: number }[]
  query_type_distribution: { type: string; count: number }[]
}

interface ResultRow {
  domain: string
  timestamp: string
  query_type: string
  query_length: number
  subdomain_count: number
  response_size: number
  score: number
  label: 'Normal' | 'Suspicious'
  if_anomaly: boolean
  feat_subdomain_entropy: number
}

interface ApiResponse {
  summary: Summary
  pagination: { page: number; page_size: number; total: number; total_pages: number }
  rows: ResultRow[]
}

// ── Colours ────────────────────────────────────────────────────────────────

const COLORS = { Suspicious: '#f43f5e', Normal: '#10b981' }

// ── Sub-components ─────────────────────────────────────────────────────────

function StatCard({ label, value, sub, accent }: { label: string; value: string | number; sub?: string; accent?: string }) {
  return (
    <div className="card flex flex-col gap-1">
      <p className="text-xs uppercase tracking-widest text-gray-500">{label}</p>
      <p className={`text-3xl font-bold ${accent ?? 'text-white'}`}>{value}</p>
      {sub && <p className="text-xs text-gray-500">{sub}</p>}
    </div>
  )
}

const CustomTooltip = ({ active, payload, label }: any) => {
  if (!active || !payload?.length) return null
  return (
    <div className="bg-surface-elevated border border-surface-border rounded-lg px-3 py-2 text-xs shadow-xl">
      {label && <p className="text-gray-400 mb-1">{label}</p>}
      {payload.map((p: any) => (
        <p key={p.name} style={{ color: p.color ?? '#fff' }}>
          {p.name ?? ''}: <span className="font-semibold">{p.value}</span>
        </p>
      ))}
    </div>
  )
}

// ── Main component ─────────────────────────────────────────────────────────

export default function Results() {
  const { id } = useParams<{ id: string }>()
  const [data, setData] = useState<ApiResponse | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [page, setPage] = useState(1)
  const [labelFilter, setLabelFilter] = useState('')
  const [sortCol, setSortCol] = useState<'score' | 'domain' | 'timestamp'>('score')
  const [sortDir, setSortDir] = useState<'asc' | 'desc'>('desc')

  const fetchResults = useCallback(async (p: number, filter: string) => {
    setLoading(true)
    setError('')
    try {
      const params = new URLSearchParams({ page: String(p), page_size: '50' })
      if (filter) params.set('label_filter', filter)
      const res = await fetch(`/api/results/${id}?${params}`, {
        headers: { Authorization: `Bearer ${getStoredToken()}` },
      })
      if (!res.ok) {
        const d = await res.json()
        throw new Error(d.detail || 'Failed to load results')
      }
      setData(await res.json())
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Unknown error')
    } finally {
      setLoading(false)
    }
  }, [id])

  useEffect(() => { fetchResults(page, labelFilter) }, [fetchResults, page, labelFilter])

  const handleSort = (col: typeof sortCol) => {
    if (col === sortCol) setSortDir(d => d === 'asc' ? 'desc' : 'asc')
    else { setSortCol(col); setSortDir('desc') }
  }

  const handleExport = () => {
    const a = document.createElement('a')
    a.href = `/api/results/${id}/export`
    const token = getStoredToken()
    // Trigger via fetch to include auth header, then blob URL
    fetch(`/api/results/${id}/export`, { headers: { Authorization: `Bearer ${token}` } })
      .then(r => r.blob())
      .then(blob => {
        const url = URL.createObjectURL(blob)
        a.href = url
        a.download = `results_${id}.csv`
        a.click()
        URL.revokeObjectURL(url)
      })
  }

  const sortedRows = data ? [...data.rows].sort((a, b) => {
    const av = a[sortCol] ?? '', bv = b[sortCol] ?? ''
    const cmp = typeof av === 'number' ? av - (bv as number) : String(av).localeCompare(String(bv))
    return sortDir === 'asc' ? cmp : -cmp
  }) : []

  // ── Render ───────────────────────────────────────────────────────────────

  if (loading && !data) return (
    <div className="min-h-screen pt-20 flex items-center justify-center">
      <div className="flex flex-col items-center gap-4">
        <svg className="w-10 h-10 text-accent animate-spin" viewBox="0 0 24 24" fill="none">
          <circle className="opacity-20" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="3" />
          <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v4a4 4 0 00-4 4H4z" />
        </svg>
        <p className="text-gray-400 text-sm">Running analysis…</p>
      </div>
    </div>
  )

  if (error) return (
    <div className="min-h-screen pt-20 flex items-center justify-center px-4">
      <div className="card text-center max-w-md">
        <p className="text-red-400 font-semibold mb-2">Failed to load results</p>
        <p className="text-gray-500 text-sm">{error}</p>
        <Link to="/upload" className="btn-primary mt-4 inline-flex">← Upload another file</Link>
      </div>
    </div>
  )

  const s = data!.summary
  const pieData = [
    { name: 'Suspicious', value: s.suspicious },
    { name: 'Normal', value: s.normal },
  ]

  return (
    <div className="min-h-screen pt-20 pb-16 px-4 md:px-8">
      {/* Glow */}
      <div className="fixed inset-0 overflow-hidden pointer-events-none">
        <div className="absolute top-0 right-1/4 w-[500px] h-[500px] bg-rose-500/5 rounded-full blur-3xl" />
        <div className="absolute bottom-0 left-1/4 w-[400px] h-[400px] bg-accent/5 rounded-full blur-3xl" />
      </div>

      <div className="relative z-10 max-w-7xl mx-auto flex flex-col gap-8">

        {/* Header */}
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div>
            <h1 className="text-2xl font-bold text-white">{s.filename}</h1>
            <div className="flex flex-wrap items-center gap-2 mt-1">
              <p className="text-gray-500 text-sm">
                Uploaded {new Date(s.uploaded_at).toLocaleString()} · {s.total.toLocaleString()} rows analyzed
              </p>
              {s.detected_format && (
                <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-accent/15 text-accent border border-accent/20">
                  {s.detected_format}
                </span>
              )}
            </div>
          </div>
          <div className="flex gap-2">
            <Link to="/upload" className="btn-secondary text-sm">← New Upload</Link>
            <button id="export-csv-btn" onClick={handleExport} className="btn-primary text-sm">
              ↓ Export CSV
            </button>
          </div>
        </div>

        {/* Summary cards */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
          <StatCard label="Total Queries" value={s.total.toLocaleString()} />
          <StatCard label="Suspicious" value={s.suspicious.toLocaleString()} accent="text-rose-400" sub={`${s.suspicious_pct}% of total`} />
          <StatCard label="Normal" value={s.normal.toLocaleString()} accent="text-emerald-400" />
          <StatCard label="Threat Rate" value={`${s.suspicious_pct}%`} accent={s.suspicious_pct > 20 ? 'text-rose-400' : 'text-emerald-400'} />
        </div>

        {/* Charts row 1 */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">

          {/* Pie */}
          <div className="card">
            <p className="text-sm font-semibold text-gray-300 mb-4">Classification Split</p>
            <ResponsiveContainer width="100%" height={270}>
              <PieChart margin={{ top: 24, right: 24, bottom: 0, left: 24 }}>
                <Pie
                  data={pieData}
                  cx="50%"
                  cy="50%"
                  innerRadius={58}
                  outerRadius={88}
                  paddingAngle={3}
                  dataKey="value"
                  labelLine={false}
                  label={({ cx, cy, midAngle, outerRadius, percent, name }) => {
                    const RADIAN = Math.PI / 180
                    const radius = outerRadius + 28
                    const x = cx + radius * Math.cos(-midAngle * RADIAN)
                    const y = cy + radius * Math.sin(-midAngle * RADIAN)
                    return (
                      <text
                        x={x}
                        y={y}
                        fill={COLORS[name as keyof typeof COLORS]}
                        textAnchor={x > cx ? 'start' : 'end'}
                        dominantBaseline="central"
                        fontSize={12}
                        fontWeight={600}
                      >
                        {`${name} ${(percent * 100).toFixed(0)}%`}
                      </text>
                    )
                  }}
                >
                  {pieData.map((entry) => (
                    <Cell key={entry.name} fill={COLORS[entry.name as keyof typeof COLORS]} />
                  ))}
                </Pie>
                <Tooltip content={<CustomTooltip />} />
                <Legend formatter={(v) => <span className="text-xs text-gray-400">{v}</span>} />
              </PieChart>
            </ResponsiveContainer>
          </div>

          {/* Query type distribution */}
          <div className="card">
            <p className="text-sm font-semibold text-gray-300 mb-4">Query Type Distribution</p>
            <ResponsiveContainer width="100%" height={240}>
              <BarChart data={s.query_type_distribution} layout="vertical" margin={{ left: 8, right: 16 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#2a2a45" horizontal={false} />
                <XAxis type="number" tick={{ fill: '#6b7280', fontSize: 11 }} />
                <YAxis type="category" dataKey="type" tick={{ fill: '#9ca3af', fontSize: 12 }} width={40} />
                <Tooltip content={<CustomTooltip />} />
                <Bar dataKey="count" fill="#6366f1" radius={[0, 4, 4, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Charts row 2 */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">

          {/* Top suspicious domains */}
          <div className="card">
            <p className="text-sm font-semibold text-gray-300 mb-4">Top Suspicious Domains</p>
            {s.top_suspicious_domains.length === 0 ? (
              <p className="text-gray-500 text-sm text-center py-8">No suspicious domains detected 🎉</p>
            ) : (
              <ResponsiveContainer width="100%" height={240}>
                <BarChart data={s.top_suspicious_domains} layout="vertical" margin={{ left: 8, right: 16 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#2a2a45" horizontal={false} />
                  <XAxis type="number" tick={{ fill: '#6b7280', fontSize: 11 }} />
                  <YAxis type="category" dataKey="domain" tick={{ fill: '#9ca3af', fontSize: 10 }} width={120}
                    tickFormatter={(v: string) => v.length > 18 ? `…${v.slice(-16)}` : v} />
                  <Tooltip content={<CustomTooltip />} />
                  <Bar dataKey="count" fill="#f43f5e" radius={[0, 4, 4, 0]} />
                </BarChart>
              </ResponsiveContainer>
            )}
          </div>

          {/* Entropy distribution histogram */}
          <div className="card">
            <p className="text-sm font-semibold text-gray-300 mb-4">Subdomain Entropy Distribution</p>
            <ResponsiveContainer width="100%" height={240}>
              <BarChart data={s.entropy_distribution} margin={{ left: 0, right: 8 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#2a2a45" vertical={false} />
                <XAxis dataKey="range" tick={{ fill: '#9ca3af', fontSize: 12 }} />
                <YAxis tick={{ fill: '#6b7280', fontSize: 11 }} />
                <Tooltip content={<CustomTooltip />} />
                <Bar dataKey="count" fill="#8b5cf6" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
            <p className="text-xs text-gray-600 mt-2">Higher entropy (3+) strongly correlates with tunneling</p>
          </div>
        </div>

        {/* Volume over time */}
        <div className="card">
          <p className="text-sm font-semibold text-gray-300 mb-4">Query Volume Over Time</p>
          <ResponsiveContainer width="100%" height={200}>
            <AreaChart data={s.volume_over_time} margin={{ left: 0, right: 8 }}>
              <defs>
                <linearGradient id="volumeGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#6366f1" stopOpacity={0.3} />
                  <stop offset="95%" stopColor="#6366f1" stopOpacity={0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="#2a2a45" vertical={false} />
              <XAxis dataKey="time" tick={{ fill: '#6b7280', fontSize: 10 }}
                tickFormatter={(v: string) => v.slice(11) || v.slice(5)} />
              <YAxis tick={{ fill: '#6b7280', fontSize: 11 }} />
              <Tooltip content={<CustomTooltip />} />
              <Area type="monotone" dataKey="count" stroke="#6366f1" strokeWidth={2}
                fill="url(#volumeGrad)" name="Queries" />
            </AreaChart>
          </ResponsiveContainer>
        </div>

        {/* Results table */}
        <div className="card">
          {/* Table controls */}
          <div className="flex flex-wrap items-center justify-between gap-4 mb-5">
            <p className="text-sm font-semibold text-gray-300">
              Results
              <span className="text-gray-500 font-normal ml-2">
                {data!.pagination.total.toLocaleString()} rows
                {labelFilter ? ` · filtered: ${labelFilter}` : ''}
              </span>
            </p>
            <div className="flex gap-2">
              {(['', 'Suspicious', 'Normal'] as const).map(f => (
                <button
                  key={f}
                  id={`filter-${f || 'all'}`}
                  onClick={() => { setLabelFilter(f); setPage(1) }}
                  className={`text-xs px-3 py-1.5 rounded-lg border transition-colors ${
                    labelFilter === f
                      ? 'bg-accent border-accent text-white font-semibold'
                      : 'border-surface-border text-gray-400 hover:border-accent/50 hover:text-white'
                  }`}
                >
                  {f || 'All'}
                </button>
              ))}
            </div>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-surface-border text-left">
                  {[
                    { key: 'domain', label: 'Domain' },
                    { key: 'timestamp', label: 'Time' },
                    { key: 'score', label: 'Score' },
                  ].map(col => (
                    <th
                      key={col.key}
                      onClick={() => handleSort(col.key as typeof sortCol)}
                      className="pb-3 pr-4 text-xs uppercase tracking-wider text-gray-500 cursor-pointer hover:text-white transition-colors select-none"
                    >
                      {col.label}
                      {sortCol === col.key && <span className="ml-1">{sortDir === 'asc' ? '↑' : '↓'}</span>}
                    </th>
                  ))}
                  <th className="pb-3 pr-4 text-xs uppercase tracking-wider text-gray-500">Type</th>
                  <th className="pb-3 pr-4 text-xs uppercase tracking-wider text-gray-500">Entropy</th>
                  <th className="pb-3 text-xs uppercase tracking-wider text-gray-500">Label</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-surface-border/50">
                {sortedRows.map((row, i) => (
                  <tr key={i} className="hover:bg-surface-elevated/50 transition-colors">
                    <td className="py-3 pr-4 font-mono text-xs text-gray-300 max-w-[200px] truncate"
                      title={row.domain}>{row.domain}</td>
                    <td className="py-3 pr-4 text-xs text-gray-500 whitespace-nowrap">
                      {row.timestamp.slice(0, 19).replace('T', ' ')}
                    </td>
                    <td className="py-3 pr-4">
                      <div className="flex items-center gap-2">
                        <div className="w-16 bg-surface-border rounded-full h-1.5 overflow-hidden">
                          <div
                            className={`h-full rounded-full ${row.score >= 40 ? 'bg-rose-500' : 'bg-emerald-500'}`}
                            style={{ width: `${row.score}%` }}
                          />
                        </div>
                        <span className={`text-xs font-semibold ${row.score >= 40 ? 'text-rose-400' : 'text-gray-400'}`}>
                          {row.score}
                        </span>
                      </div>
                    </td>
                    <td className="py-3 pr-4">
                      <span className={`text-xs px-2 py-0.5 rounded font-mono ${
                        ['TXT', 'NULL', 'ANY'].includes(row.query_type)
                          ? 'bg-rose-500/15 text-rose-400'
                          : 'bg-surface-elevated text-gray-400'
                      }`}>{row.query_type}</span>
                    </td>
                    <td className="py-3 pr-4 text-xs text-gray-400 font-mono">
                      {row.feat_subdomain_entropy.toFixed(2)}
                    </td>
                    <td className="py-3">
                      <span className={`text-xs px-2.5 py-1 rounded-full font-semibold ${
                        row.label === 'Suspicious'
                          ? 'bg-rose-500/15 text-rose-400'
                          : 'bg-emerald-500/15 text-emerald-400'
                      }`}>
                        {row.label}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {/* Pagination */}
          {data!.pagination.total_pages > 1 && (
            <div className="flex items-center justify-between mt-5 pt-4 border-t border-surface-border">
              <p className="text-xs text-gray-500">
                Page {data!.pagination.page} of {data!.pagination.total_pages}
              </p>
              <div className="flex gap-2">
                <button
                  id="prev-page"
                  onClick={() => setPage(p => Math.max(1, p - 1))}
                  disabled={page === 1}
                  className="btn-secondary text-xs px-3 py-1.5 disabled:opacity-40"
                >
                  ← Prev
                </button>
                <button
                  id="next-page"
                  onClick={() => setPage(p => Math.min(data!.pagination.total_pages, p + 1))}
                  disabled={page === data!.pagination.total_pages}
                  className="btn-secondary text-xs px-3 py-1.5 disabled:opacity-40"
                >
                  Next →
                </button>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
