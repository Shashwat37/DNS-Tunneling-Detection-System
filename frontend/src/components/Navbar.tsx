import { Link, useNavigate, useLocation } from 'react-router-dom'
import { useAuth } from '../context/AuthContext'

export default function Navbar() {
  const { user, isAuthenticated, logout } = useAuth()
  const navigate = useNavigate()
  const location = useLocation()

  const handleLogout = () => {
    logout()
    navigate('/login')
  }

  return (
    <nav className="fixed top-0 inset-x-0 z-50 h-14 border-b border-surface-border bg-surface/80 backdrop-blur-md flex items-center px-6 gap-6">
      {/* Logo */}
      <Link to="/" className="flex items-center gap-2 shrink-0 mr-4">
        <div className="w-7 h-7 rounded-lg bg-accent/20 border border-accent/30 flex items-center justify-center">
          <svg className="w-4 h-4 text-accent" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
            <path strokeLinecap="round" strokeLinejoin="round"
              d="M9 17.25v1.007a3 3 0 01-.879 2.122L7.5 21h9l-.621-.621A3 3 0 0115 18.257V17.25m6-12V15a2.25 2.25 0 01-2.25 2.25H5.25A2.25 2.25 0 013 15V5.25m18 0A2.25 2.25 0 0018.75 3H5.25A2.25 2.25 0 003 5.25m18 0H3" />
          </svg>
        </div>
        <span className="font-bold text-white text-sm tracking-tight">DTDS</span>
      </Link>

      {/* Nav links */}
      {isAuthenticated && (
        <div className="flex items-center gap-1 flex-1">
          <NavLink to="/upload" active={location.pathname === '/upload'}>Upload</NavLink>
          <NavLink to="/history" active={location.pathname === '/history'}>History</NavLink>
        </div>
      )}

      <div className="flex-1" />

      {/* Auth actions */}
      {isAuthenticated ? (
        <div className="flex items-center gap-4">
          <span className="text-sm text-gray-400 hidden sm:block">
            {user?.name}
          </span>
          <button
            onClick={handleLogout}
            id="logout-btn"
            className="btn-secondary text-xs px-3 py-1.5"
          >
            Log out
          </button>
        </div>
      ) : (
        <div className="flex items-center gap-2">
          <Link to="/login" className="btn-secondary text-xs px-3 py-1.5" id="nav-login">Sign in</Link>
          <Link to="/register" className="btn-primary text-xs px-3 py-1.5" id="nav-register">Register</Link>
        </div>
      )}
    </nav>
  )
}

function NavLink({ to, active, children }: { to: string; active: boolean; children: React.ReactNode }) {
  return (
    <Link
      to={to}
      className={`text-sm px-3 py-1.5 rounded-lg transition-colors ${
        active
          ? 'bg-accent/15 text-accent font-semibold'
          : 'text-gray-400 hover:text-white hover:bg-surface-elevated'
      }`}
    >
      {children}
    </Link>
  )
}
