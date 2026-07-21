import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { getStoredToken } from '../context/AuthContext'

interface UploadRecord {
  upload_id: string
  filename: string
  row_count: number
  status: string
  uploaded_at: string | null
}

export default function History() {
  const [uploads, setUploads] = useState<UploadRecord[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  useEffect(() => {
    fetch('/api/uploads', {
      headers: { Authorization: `Bearer ${getStoredToken()}` },
    })
      .then(r => {
        if (!r.ok) throw new Error('Failed to load history')
        return r.json()
      })
      .then(setUploads)
      .catch(e => setError(e.message))
      .finally(() => setLoading(false))
  }, [])

  const formatDate = (iso: string | null) => {
    if (!iso) return '—'
    return new Date(iso).toLocaleString()
  }

  const statusBadge = (status: string) => {
    const map: Record<string, string> = {
      done: 'bg-emerald-500/15 text-emerald-400',
      pending: 'bg-yellow-500/15 text-yellow-400',
      error: 'bg-red-500/15 text-red-400',
    }
    return map[status] ?? 'bg-surface-elevated text-gray-400'
  }

  return (
    <div className="min-h-screen pt-20 pb-16 px-4 md:px-8">
      {/* Glow */}
      <div className="absolute inset-0 overflow-hidden pointer-events-none">
        <div className="absolute top-1/4 left-1/2 -translate-x-1/2 w-[500px] h-[500px] bg-accent/6 rounded-full blur-3xl" />
      </div>

      <div className="relative z-10 max-w-4xl mx-auto flex flex-col gap-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold text-white">Upload History</h1>
            <p className="text-gray-400 text-sm mt-1">All your past DNS log analyses</p>
          </div>
          <Link to="/upload" className="btn-primary text-sm">+ New Upload</Link>
        </div>

        {/* Content */}
        {loading && (
          <div className="flex justify-center py-16">
            <svg className="w-8 h-8 text-accent animate-spin" viewBox="0 0 24 24" fill="none">
              <circle className="opacity-20" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="3" />
              <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v4a4 4 0 00-4 4H4z" />
            </svg>
          </div>
        )}

        {error && (
          <div className="card text-center py-10">
            <p className="text-red-400 text-sm">{error}</p>
          </div>
        )}

        {!loading && !error && uploads.length === 0 && (
          <div className="card text-center py-16">
            <div className="w-14 h-14 rounded-2xl bg-surface-elevated border border-surface-border flex items-center justify-center mx-auto mb-4">
              <svg className="w-7 h-7 text-gray-600" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M3 16.5v2.25A2.25 2.25 0 005.25 21h13.5A2.25 2.25 0 0021 18.75V16.5m-13.5-9L12 3m0 0l4.5 4.5M12 3v13.5" />
              </svg>
            </div>
            <p className="text-gray-400 font-semibold mb-2">No uploads yet</p>
            <p className="text-gray-600 text-sm mb-5">Upload your first DNS log CSV to get started.</p>
            <Link to="/upload" className="btn-primary">Upload CSV</Link>
          </div>
        )}

        {!loading && uploads.length > 0 && (
          <div className="card overflow-hidden p-0">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-surface-border">
                  <th className="text-left text-xs uppercase tracking-wider text-gray-500 px-6 py-4">File</th>
                  <th className="text-left text-xs uppercase tracking-wider text-gray-500 px-4 py-4">Rows</th>
                  <th className="text-left text-xs uppercase tracking-wider text-gray-500 px-4 py-4">Status</th>
                  <th className="text-left text-xs uppercase tracking-wider text-gray-500 px-4 py-4">Uploaded</th>
                  <th className="px-6 py-4" />
                </tr>
              </thead>
              <tbody className="divide-y divide-surface-border/50">
                {uploads.map(u => (
                  <tr key={u.upload_id} className="hover:bg-surface-elevated/40 transition-colors">
                    <td className="px-6 py-4">
                      <div className="flex items-center gap-3">
                        <div className="w-8 h-8 rounded-lg bg-accent/10 border border-accent/20 flex items-center justify-center shrink-0">
                          <svg className="w-4 h-4 text-accent" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                            <path strokeLinecap="round" strokeLinejoin="round" d="M19.5 14.25v-2.625a3.375 3.375 0 00-3.375-3.375h-1.5A1.125 1.125 0 0113.5 7.125v-1.5a3.375 3.375 0 00-3.375-3.375H8.25m2.25 0H5.625c-.621 0-1.125.504-1.125 1.125v17.25c0 .621.504 1.125 1.125 1.125h12.75c.621 0 1.125-.504 1.125-1.125V11.25a9 9 0 00-9-9z" />
                          </svg>
                        </div>
                        <span className="font-medium text-gray-200 truncate max-w-[200px]" title={u.filename}>
                          {u.filename}
                        </span>
                      </div>
                    </td>
                    <td className="px-4 py-4 text-gray-400 tabular-nums">
                      {u.row_count.toLocaleString()}
                    </td>
                    <td className="px-4 py-4">
                      <span className={`text-xs px-2.5 py-1 rounded-full font-semibold capitalize ${statusBadge(u.status)}`}>
                        {u.status}
                      </span>
                    </td>
                    <td className="px-4 py-4 text-gray-500 text-xs whitespace-nowrap">
                      {formatDate(u.uploaded_at)}
                    </td>
                    <td className="px-6 py-4 text-right">
                      <Link
                        to={`/results/${u.upload_id}`}
                        id={`view-results-${u.upload_id}`}
                        className="text-xs text-accent hover:text-accent-light transition-colors font-semibold"
                      >
                        View Results →
                      </Link>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  )
}
