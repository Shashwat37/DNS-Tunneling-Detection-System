import { useRef, useState, type DragEvent, type ChangeEvent } from 'react'
import { useNavigate } from 'react-router-dom'
import { useAuth } from '../context/AuthContext'
import { getStoredToken } from '../context/AuthContext'

const ACCEPTED_EXTENSIONS = ['.csv', '.log', '.json', '.txt', '.tsv']

const SUPPORTED_FORMATS = [
  { name: 'DTDS CSV', tag: 'Native', desc: 'Our own 6-column format', ext: '.csv' },
  { name: 'Zeek dns.log', tag: 'IDS', desc: 'TSV with #fields header', ext: '.log .tsv' },
  { name: 'Suricata eve.json', tag: 'IDS', desc: 'JSON lines, event_type=dns', ext: '.json' },
  { name: 'AWS Route53', tag: 'Cloud', desc: 'CloudWatch DNS query logs', ext: '.csv' },
  { name: 'Windows DNS Debug', tag: 'Windows', desc: 'Server debug mode log', ext: '.log .txt' },
  { name: 'dnsmasq log', tag: 'Linux', desc: 'Syslog-style query[TYPE]', ext: '.log .txt' },
  { name: 'BIND named log', tag: 'Linux', desc: 'ISC BIND query lines', ext: '.log .txt' },
  { name: 'Generic CSV/TSV', tag: 'Auto', desc: 'Any CSV with recognized columns', ext: '.csv .tsv' },
]

type UploadState = 'idle' | 'dragging' | 'uploading' | 'error'

export default function Upload() {
  const { user } = useAuth()
  const navigate = useNavigate()
  const fileRef = useRef<HTMLInputElement>(null)

  const [uploadState, setUploadState] = useState<UploadState>('idle')
  const [error, setError] = useState('')
  const [selectedFile, setSelectedFile] = useState<File | null>(null)
  const [progress, setProgress] = useState(0)

  // ── Drag-and-drop ──────────────────────────────────────────────────────────
  const handleDragOver = (e: DragEvent) => { e.preventDefault(); setUploadState('dragging') }
  const handleDragLeave = () => setUploadState('idle')
  const handleDrop = (e: DragEvent) => {
    e.preventDefault()
    const file = e.dataTransfer.files[0]
    if (file) validateAndSet(file)
  }

  const validateAndSet = (file: File) => {
    setError('')
    const ext = '.' + file.name.split('.').pop()?.toLowerCase()
    if (!ACCEPTED_EXTENSIONS.includes(ext)) {
      setError(`Unsupported file type '${ext}'. Accepted: ${ACCEPTED_EXTENSIONS.join(', ')}`)
      setUploadState('error')
      return
    }
    if (file.size === 0) {
      setError('File is empty.')
      setUploadState('error')
      return
    }
    if (file.size > 50 * 1024 * 1024) {
      setError('File exceeds the 50 MB limit.')
      setUploadState('error')
      return
    }
    setSelectedFile(file)
    setUploadState('idle')
  }

  const handleFileChange = (e: ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (file) validateAndSet(file)
  }

  // ── Upload ─────────────────────────────────────────────────────────────────
  const handleUpload = async () => {
    if (!selectedFile) return
    setUploadState('uploading')
    setError('')

    // Animate progress (XHR not available through fetch, fake progression)
    const ticker = setInterval(() => setProgress(p => Math.min(p + 6, 88)), 200)

    try {
      const formData = new FormData()
      formData.append('file', selectedFile)

      const res = await fetch('/api/uploads', {
        method: 'POST',
        headers: { Authorization: `Bearer ${getStoredToken()}` },
        body: formData,
      })

      clearInterval(ticker)
      setProgress(100)

      const data = await res.json()
      if (!res.ok) throw new Error(data.detail || 'Upload failed')

      // Brief pause so user sees 100%
      await new Promise(r => setTimeout(r, 400))
      navigate(`/results/${data.upload_id}`)
    } catch (err: unknown) {
      clearInterval(ticker)
      setProgress(0)
      setUploadState('error')
      setError(err instanceof Error ? err.message : 'Upload failed')
    }
  }

  const reset = () => {
    setSelectedFile(null)
    setUploadState('idle')
    setError('')
    setProgress(0)
    if (fileRef.current) fileRef.current.value = ''
  }

  const isUploading = uploadState === 'uploading'

  return (
    <div className="min-h-screen pt-20 pb-12 flex flex-col items-center px-4">
      {/* Glow */}
      <div className="absolute inset-0 overflow-hidden pointer-events-none">
        <div className="absolute top-1/4 left-1/2 -translate-x-1/2 w-[600px] h-[600px] bg-accent/8 rounded-full blur-3xl" />
      </div>

      <div className="relative z-10 w-full max-w-2xl flex flex-col gap-6">
        {/* Header */}
        <div>
          <h1 className="text-2xl font-bold text-white">Upload DNS Logs</h1>
          <p className="text-gray-400 text-sm mt-1">
            Welcome back, <span className="text-accent font-semibold">{user?.name}</span>. Upload a CSV to run analysis.
          </p>
        </div>

        {/* Drop zone */}
        <div
          onDragOver={handleDragOver}
          onDragLeave={handleDragLeave}
          onDrop={handleDrop}
          onClick={() => !isUploading && fileRef.current?.click()}
          className={`
            card relative flex flex-col items-center justify-center gap-4 py-14 cursor-pointer
            border-2 border-dashed transition-all duration-200
            ${uploadState === 'dragging' ? 'border-accent bg-accent/10 scale-[1.01]' : ''}
            ${uploadState === 'error' ? 'border-red-500/50' : ''}
            ${uploadState === 'idle' && !selectedFile ? 'border-surface-border hover:border-accent/50 hover:bg-surface-elevated/50' : ''}
            ${selectedFile && uploadState !== 'error' ? 'border-accent/40 bg-accent/5' : ''}
            ${isUploading ? 'cursor-not-allowed pointer-events-none' : ''}
          `}
        >
          <input
            ref={fileRef}
            type="file"
            accept={ACCEPTED_EXTENSIONS.join(',')}
            className="hidden"
            onChange={handleFileChange}
            id="csv-file-input"
          />

          {isUploading ? (
            <div className="flex flex-col items-center gap-4 w-full px-8">
              <svg className="w-10 h-10 text-accent animate-spin" viewBox="0 0 24 24" fill="none">
                <circle className="opacity-20" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="3" />
                <path className="opacity-80" fill="currentColor" d="M4 12a8 8 0 018-8v4a4 4 0 00-4 4H4z" />
              </svg>
              <p className="text-sm font-semibold text-gray-300">Uploading & analyzing…</p>
              <div className="w-full bg-surface-border rounded-full h-2 overflow-hidden">
                <div
                  className="h-full bg-accent rounded-full transition-all duration-300"
                  style={{ width: `${progress}%` }}
                />
              </div>
              <p className="text-xs text-gray-500">{progress}%</p>
            </div>
          ) : selectedFile ? (
            <div className="flex flex-col items-center gap-3">
              <div className="w-12 h-12 rounded-xl bg-emerald-500/15 border border-emerald-500/30 flex items-center justify-center">
                <svg className="w-6 h-6 text-emerald-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M19.5 14.25v-2.625a3.375 3.375 0 00-3.375-3.375h-1.5A1.125 1.125 0 0113.5 7.125v-1.5a3.375 3.375 0 00-3.375-3.375H8.25m2.25 0H5.625c-.621 0-1.125.504-1.125 1.125v17.25c0 .621.504 1.125 1.125 1.125h12.75c.621 0 1.125-.504 1.125-1.125V11.25a9 9 0 00-9-9z" />
                </svg>
              </div>
              <div className="text-center">
                <p className="text-sm font-semibold text-gray-200">{selectedFile.name}</p>
                <p className="text-xs text-gray-500 mt-0.5">{(selectedFile.size / 1024).toFixed(1)} KB</p>
              </div>
              <button
                onClick={e => { e.stopPropagation(); reset() }}
                className="text-xs text-gray-500 hover:text-red-400 transition-colors mt-1"
              >
                Remove
              </button>
            </div>
          ) : (
            <>
              <div className="w-14 h-14 rounded-2xl bg-surface-elevated border border-surface-border flex items-center justify-center">
                <svg className="w-7 h-7 text-gray-500" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M3 16.5v2.25A2.25 2.25 0 005.25 21h13.5A2.25 2.25 0 0021 18.75V16.5m-13.5-9L12 3m0 0l4.5 4.5M12 3v13.5" />
                </svg>
              </div>
              <div className="text-center">
                <p className="text-sm font-semibold text-gray-300">Drop your CSV here, or <span className="text-accent">browse</span></p>
                <p className="text-xs text-gray-500 mt-1">Max 50 MB · .csv only</p>
              </div>
            </>
          )}
        </div>

        {/* Error banner */}
        {error && (
          <div className="flex items-start gap-3 p-4 rounded-xl bg-red-500/10 border border-red-500/20 text-red-400 text-sm">
            <svg className="w-4 h-4 mt-0.5 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3.75m9-.75a9 9 0 11-18 0 9 9 0 0118 0zm-9 3.75h.008v.008H12v-.008z" />
            </svg>
            <span>{error}</span>
          </div>
        )}

        {/* Upload button */}
        {selectedFile && !isUploading && (
          <button id="upload-btn" onClick={handleUpload} className="btn-primary w-full py-3 text-base">
            <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M9 12.75L11.25 15 15 9.75M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
            Analyze {selectedFile.name}
          </button>
        )}

        {/* Supported formats panel */}
        <div className="card">
          <p className="text-xs font-semibold uppercase tracking-widest text-gray-500 mb-3">Supported Formats</p>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
            {SUPPORTED_FORMATS.map(f => (
              <div key={f.name} className="flex items-start gap-2.5 p-2.5 rounded-lg bg-surface-elevated/50 border border-surface-border/50">
                <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded shrink-0 mt-0.5 ${
                  f.tag === 'Native' ? 'bg-accent/20 text-accent' :
                  f.tag === 'IDS' ? 'bg-rose-500/15 text-rose-400' :
                  f.tag === 'Cloud' ? 'bg-sky-500/15 text-sky-400' :
                  f.tag === 'Windows' ? 'bg-blue-500/15 text-blue-400' :
                  f.tag === 'Auto' ? 'bg-emerald-500/15 text-emerald-400' :
                  'bg-purple-500/15 text-purple-400'
                }`}>{f.tag}</span>
                <div className="min-w-0">
                  <p className="text-xs font-semibold text-gray-200">{f.name}</p>
                  <p className="text-xs text-gray-500 mt-0.5">{f.desc} · <code className="font-mono text-gray-600">{f.ext}</code></p>
                </div>
              </div>
            ))}
          </div>
          <p className="text-xs text-gray-600 mt-3">Format is detected automatically — no configuration needed.</p>
        </div>
      </div>
    </div>
  )
}
