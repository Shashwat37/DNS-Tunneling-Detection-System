import { useEffect, useState } from 'react'

type HealthStatus = 'loading' | 'ok' | 'error'

interface HealthResponse {
  status: string
  version: string
  environment: string
}

export default function Home() {
  const [healthStatus, setHealthStatus] = useState<HealthStatus>('loading')
  const [healthData, setHealthData] = useState<HealthResponse | null>(null)

  useEffect(() => {
    fetch('/api/health')
      .then((res) => {
        if (!res.ok) throw new Error(`HTTP ${res.status}`)
        return res.json()
      })
      .then((data: HealthResponse) => {
        setHealthData(data)
        setHealthStatus('ok')
      })
      .catch(() => {
        setHealthStatus('error')
      })
  }, [])

  return (
    <div className="min-h-screen flex flex-col items-center justify-center px-4">
      {/* Background glow */}
      <div className="absolute inset-0 overflow-hidden pointer-events-none">
        <div className="absolute top-1/4 left-1/2 -translate-x-1/2 w-[600px] h-[600px] bg-accent/10 rounded-full blur-3xl" />
      </div>

      <div className="relative z-10 flex flex-col items-center gap-8 max-w-2xl w-full text-center">
        {/* Logo / title */}
        <div className="flex flex-col items-center gap-3">
          <div className="w-16 h-16 rounded-2xl bg-accent/20 border border-accent/30 flex items-center justify-center">
            <svg className="w-8 h-8 text-accent" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
              <path strokeLinecap="round" strokeLinejoin="round"
                d="M9 17.25v1.007a3 3 0 01-.879 2.122L7.5 21h9l-.621-.621A3 3 0 0115 18.257V17.25m6-12V15a2.25 2.25 0 01-2.25 2.25H5.25A2.25 2.25 0 013 15V5.25m18 0A2.25 2.25 0 0018.75 3H5.25A2.25 2.25 0 003 5.25m18 0H3" />
            </svg>
          </div>
          <h1 className="text-4xl font-bold tracking-tight text-white">
            DNS Tunneling Detection
          </h1>
          <p className="text-gray-400 text-lg leading-relaxed">
            Upload DNS query logs to detect suspicious tunneling activity using
            rule-based heuristics and machine learning.
          </p>
        </div>

        {/* Backend health check card */}
        <div className="card w-full">
          <p className="text-xs font-semibold uppercase tracking-widest text-gray-500 mb-4">
            System Status
          </p>

          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div
                className={`w-2.5 h-2.5 rounded-full ${
                  healthStatus === 'loading'
                    ? 'bg-yellow-400 animate-pulse'
                    : healthStatus === 'ok'
                    ? 'bg-emerald-400'
                    : 'bg-red-500'
                }`}
              />
              <span className="text-sm font-medium text-gray-300">
                Backend API
              </span>
            </div>

            <span
              className={`text-sm font-semibold ${
                healthStatus === 'loading'
                  ? 'text-yellow-400'
                  : healthStatus === 'ok'
                  ? 'text-emerald-400'
                  : 'text-red-400'
              }`}
            >
              {healthStatus === 'loading' && 'Connecting…'}
              {healthStatus === 'ok' && '✓ Online'}
              {healthStatus === 'error' && '✗ Unreachable'}
            </span>
          </div>

          {healthData && (
            <div className="mt-4 pt-4 border-t border-surface-border grid grid-cols-3 gap-4 text-center">
              <div>
                <p className="text-xs text-gray-500 uppercase tracking-wider">Status</p>
                <p className="text-sm font-semibold text-emerald-400 mt-1 capitalize">{healthData.status}</p>
              </div>
              <div>
                <p className="text-xs text-gray-500 uppercase tracking-wider">Version</p>
                <p className="text-sm font-semibold text-white mt-1">v{healthData.version}</p>
              </div>
              <div>
                <p className="text-xs text-gray-500 uppercase tracking-wider">Env</p>
                <p className="text-sm font-semibold text-white mt-1 capitalize">{healthData.environment}</p>
              </div>
            </div>
          )}

          {healthStatus === 'error' && (
            <p className="mt-3 text-xs text-red-400 bg-red-500/10 rounded-lg p-3">
              Cannot reach the backend. It may be waking up — please wait 30 seconds and{' '}
              <button
                onClick={() => window.location.reload()}
                className="underline hover:text-red-300 cursor-pointer bg-transparent border-none"
              >
                refresh the page
              </button>.
            </p>
          )}
        </div>

        {/* Next milestone CTA */}
        <div className="flex gap-3">
          <a href="/login" className="btn-primary">
            Go to Login
          </a>
          <a href="/register" className="btn-secondary">
            Register
          </a>
        </div>

        <p className="text-xs text-gray-600">
          API docs at{' '}
          <a
            href="https://dtds-backend.onrender.com/docs"
            target="_blank"
            rel="noopener noreferrer"
            className="text-accent hover:underline"
          >
            dtds-backend.onrender.com/docs
          </a>
        </p>
      </div>
    </div>
  )
}
