import { lazy, Suspense, useEffect, useState } from 'react'
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { useAuthStore } from './store/authStore'
import { usePermissionStore } from './store/permissionStore'
import { AppearanceProvider } from './components/AppearanceProvider'
import { ErrorBoundary } from './components/ErrorBoundary'
import { OfflineIndicator } from './components/OfflineIndicator'
import { clientLogger } from './lib/clientLogger'
import { ForcePasswordChange } from './components/ForcePasswordChange'

// Normalize SECRET_PATH: ensure leading slash for BrowserRouter basename
const rawSecretPath = window.__ENV?.SECRET_PATH || '/'
const routerBasename = rawSecretPath.startsWith('/') ? rawSecretPath : `/${rawSecretPath}`

// Layout
import Layout from './components/layout/Layout'

// Login, Dashboard, ResetPassword loaded eagerly (critical path)
import Login from './pages/Login'
import Dashboard from './pages/Dashboard'
import ResetPassword from './pages/ResetPassword'
import OAuthCallback from './pages/OAuthCallback'

// Lazy-loaded pages
const Users = lazy(() => import('./pages/Users'))
const UserDetail = lazy(() => import('./pages/UserDetail'))
const Nodes = lazy(() => import('./pages/Nodes'))
const Fleet = lazy(() => import('./pages/Fleet'))
const Hosts = lazy(() => import('./pages/Hosts'))
const Violations = lazy(() => import('./pages/Violations'))
const Blocking = lazy(() => import('./pages/Blocking'))
const Settings = lazy(() => import('./pages/Settings'))
const Admins = lazy(() => import('./pages/Admins'))
const AuditLog = lazy(() => import('./pages/AuditLog'))
const AdminPlugins = lazy(() => import('./pages/AdminPlugins'))
const SystemLogs = lazy(() => import('./pages/SystemLogs'))
const Analytics = lazy(() => import('./pages/Analytics'))
const Automations = lazy(() => import('./pages/automations'))
const Notifications = lazy(() => import('./pages/Notifications'))
const MailServer = lazy(() => import('./pages/MailServer'))
const Finance = lazy(() => import('./pages/Finance'))
const Dns = lazy(() => import('./pages/Dns'))
const BsCheck = lazy(() => import('./pages/BsCheck'))
const Backup = lazy(() => import('./pages/Backup'))
const ApiKeys = lazy(() => import('./pages/ApiKeys'))
const Reports = lazy(() => import('./pages/Reports'))
const Resources = lazy(() => import('./pages/Resources'))
const Squads = lazy(() => import('./pages/Squads'))
const BedolagaDashboard = lazy(() => import('./pages/bedolaga/BedolagaDashboard'))
const BedolagaCustomers = lazy(() => import('./pages/bedolaga/BedolagaCustomers'))
const BedolagaCustomerDetail = lazy(() => import('./pages/bedolaga/BedolagaCustomerDetail'))
const BedolagaPromo = lazy(() => import('./pages/bedolaga/BedolagaPromo'))
const BedolagaMarketing = lazy(() => import('./pages/bedolaga/BedolagaMarketing'))
const BedolagaReferrals = lazy(() => import('./pages/bedolaga/BedolagaReferrals'))
const NotFound = lazy(() => import('./pages/NotFound'))

// Plugin UI route registry — see web/frontend/src/plugins/registry.tsx
import { PLUGIN_ROUTES } from './plugins/registry'
import { useActivePlugins } from './lib/plugins'

/**
 * Inner shell that renders all protected routes, including any contributed
 * by installed plugins. Lives in its own component so we can call
 * ``useActivePlugins`` (a query hook) inside the authenticated tree.
 *
 * Plugin pages render even when the plugin's license is expired or missing
 * — the page itself reacts to the resulting HTTP 402 from the plugin's API
 * by showing a "buy/renew license" banner.
 */
function ProtectedShell() {
  const { data: activePlugins } = useActivePlugins()
  const pluginRouteEntries = (activePlugins ?? []).flatMap((p) =>
    (PLUGIN_ROUTES[p.id] ?? []).map((r) => ({ key: `${p.id}:${r.path}`, ...r })),
  )

  return (
    <ProtectedRoute>
      <Layout>
        <Suspense fallback={<div className="flex items-center justify-center h-64 animate-pulse"><div className="w-8 h-8 rounded-full border-2 border-primary/30 border-t-primary animate-spin" /></div>}>
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/users" element={<PermissionRoute resource="users"><Users /></PermissionRoute>} />
            <Route path="/users/:uuid" element={<PermissionRoute resource="users"><UserDetail /></PermissionRoute>} />
            <Route path="/nodes" element={<PermissionRoute resource="nodes"><Nodes /></PermissionRoute>} />
            <Route path="/fleet" element={<PermissionRoute resource="fleet"><Fleet /></PermissionRoute>} />
            <Route path="/hosts" element={<PermissionRoute resource="hosts"><Hosts /></PermissionRoute>} />
            <Route path="/violations" element={<PermissionRoute resource="violations"><Violations /></PermissionRoute>} />
            <Route path="/blocking" element={<PermissionRoute resource="blocked_ips"><Blocking /></PermissionRoute>} />
            <Route path="/automations" element={<PermissionRoute resource="automation"><Automations /></PermissionRoute>} />
            <Route path="/notifications" element={<PermissionRoute resource="notifications"><Notifications /></PermissionRoute>} />
            <Route path="/mailserver" element={<PermissionRoute resource="mailserver"><MailServer /></PermissionRoute>} />
            <Route path="/admins" element={<PermissionRoute resource="admins"><Admins /></PermissionRoute>} />
            <Route path="/audit" element={<PermissionRoute resource="audit"><AuditLog /></PermissionRoute>} />
            <Route path="/admin/plugins" element={<PermissionRoute resource="plugins"><AdminPlugins /></PermissionRoute>} />
            <Route path="/logs" element={<PermissionRoute resource="logs"><SystemLogs /></PermissionRoute>} />
            <Route path="/analytics" element={<PermissionRoute resource="analytics"><Analytics /></PermissionRoute>} />
            <Route path="/finance" element={<PermissionRoute resource="finance"><Finance /></PermissionRoute>} />
            <Route path="/dns" element={<PermissionRoute resource="dns"><Dns /></PermissionRoute>} />
            <Route path="/bscheck" element={<PermissionRoute resource="bscheck"><BsCheck /></PermissionRoute>} />
            <Route path="/billing" element={<Navigate to="/finance" replace />} />
            <Route path="/backups" element={<PermissionRoute resource="backups"><Backup /></PermissionRoute>} />
            <Route path="/api-keys" element={<PermissionRoute resource="api_keys"><ApiKeys /></PermissionRoute>} />
            <Route path="/reports" element={<PermissionRoute resource="reports"><Reports /></PermissionRoute>} />
            <Route path="/resources" element={<ResourcePermissionRoute><Resources /></ResourcePermissionRoute>} />
            <Route path="/squads" element={<PermissionRoute resource="squads"><Squads /></PermissionRoute>} />
            <Route path="/bedolaga" element={<PermissionRoute resource="bedolaga"><BedolagaDashboard /></PermissionRoute>} />
            <Route path="/bedolaga/customers" element={<PermissionRoute resource="bedolaga_customers"><BedolagaCustomers /></PermissionRoute>} />
            <Route path="/bedolaga/customers/:id" element={<PermissionRoute resource="bedolaga_customers"><BedolagaCustomerDetail /></PermissionRoute>} />
            <Route path="/bedolaga/promo" element={<PermissionRoute resource="bedolaga_promo"><BedolagaPromo /></PermissionRoute>} />
            <Route path="/bedolaga/marketing" element={<PermissionRoute resource="bedolaga_marketing"><BedolagaMarketing /></PermissionRoute>} />
            <Route path="/bedolaga/referrals" element={<PermissionRoute resource="bedolaga"><BedolagaReferrals /></PermissionRoute>} />
            <Route path="/settings" element={<PermissionRoute resource="settings"><Settings /></PermissionRoute>} />
            {pluginRouteEntries.map(({ key, path, Component }) => (
              <Route key={key} path={path} element={<Component />} />
            ))}
            <Route path="*" element={<NotFound />} />
          </Routes>
        </Suspense>
      </Layout>
    </ProtectedRoute>
  )
}

function PermissionRoute({ resource, action = 'view', children }: {
  resource: string
  action?: string
  children: React.ReactNode
}) {
  const hasPermission = usePermissionStore((s) => s.hasPermission)
  return hasPermission(resource, action) ? <>{children}</> : <Navigate to="/" replace />
}

function ResourcePermissionRoute({ children }: { children: React.ReactNode }) {
  const hasPermission = usePermissionStore((s) => s.hasPermission)
  const allowed = hasPermission('config_profiles', 'view')
    || hasPermission('subscription_templates', 'view')
    || hasPermission('snippets', 'view')
  return allowed ? <>{children}</> : <Navigate to="/" replace />
}

/**
 * Protected route wrapper - redirects to login if not authenticated.
 * Also loads RBAC permissions on first mount and waits for them to resolve
 * before rendering children, so child components (Dashboard, Sidebar, etc.)
 * can read permission flags synchronously on first render.
 */
function ProtectedRoute({ children }: { children: React.ReactNode }) {
  const { isAuthenticated } = useAuthStore()
  const { isLoaded, loadError, loadPermissions, mustChangePassword } = usePermissionStore()
  const { t } = useTranslation()

  useEffect(() => {
    if (isAuthenticated && !isLoaded) {
      loadPermissions()
    }
  }, [isAuthenticated, isLoaded, loadPermissions])

  if (!isAuthenticated) {
    return <Navigate to="/login" replace />
  }

  if (isLoaded && mustChangePassword) {
    return <ForcePasswordChange />
  }

  // Wait for permissions to resolve before rendering children.
  // Without this guard, child components render with `isLoaded=false`
  // and `hasPermission(...)` returns false for everything (deny-by-default),
  // which can cause React Query `enabled` flags to flip and queries to be
  // skipped on first render — leading to empty UI until reload.
  if (!isLoaded) {
    // On failure, surface the error and let the user retry instead of
    // spinning forever. The retry button re-invokes `loadPermissions`
    // directly; on success the children render on the next state update.
    if (loadError) {
      return (
        <div className="flex flex-col items-center justify-center h-screen gap-4 px-4">
          <div className="text-sm text-red-400 text-center max-w-md">
            {t('login.permissionsLoadFailed', { defaultValue: 'Failed to load permissions. Please try again.' })}
          </div>
          <div className="text-xs text-dark-300 text-center max-w-md break-all">
            {loadError}
          </div>
          <button
            onClick={() => { void loadPermissions() }}
            className="px-6 py-2 rounded-lg bg-teal-600 hover:bg-teal-500 text-white text-sm font-medium transition-colors"
          >
            {t('login.retry', 'Retry')}
          </button>
        </div>
      )
    }
    return (
      <div className="flex items-center justify-center h-screen">
        <div className="w-8 h-8 rounded-full border-2 border-primary/30 border-t-primary animate-spin" />
      </div>
    )
  }

  return <>{children}</>
}

/**
 * Main App component with routing.
 * Validates the persisted session on startup to clear expired tokens
 * before rendering protected routes.
 */
export default function App() {
  const isAuthenticated = useAuthStore((s) => s.isAuthenticated)
  const validateSession = useAuthStore((s) => s.validateSession)
  const clearPermissions = usePermissionStore((s) => s.clearPermissions)
  const [isValidating, setIsValidating] = useState(true)

  // Initialize frontend error collection
  useEffect(() => {
    clientLogger.init()
    return () => clientLogger.destroy()
  }, [])

  // Validate persisted session on app startup
  useEffect(() => {
    validateSession().finally(() => setIsValidating(false))
  }, [validateSession])

  // Clear permissions on logout
  useEffect(() => {
    if (!isAuthenticated) {
      clearPermissions()
    }
  }, [isAuthenticated, clearPermissions])

  // Show nothing while validating to prevent flash of protected content
  if (isValidating) {
    return null
  }

  return (
    <ErrorBoundary>
      <AppearanceProvider>
        <OfflineIndicator />
        <BrowserRouter basename={routerBasename}>
          <Routes>
            {/* Public routes */}
            <Route path="/login" element={<Login />} />
            <Route path="/reset-password" element={<ResetPassword />} />
            <Route path="/oauth/callback" element={<OAuthCallback />} />

            {/* Standard protected pages (inside admin Layout) */}
            <Route path="/*" element={<ProtectedShell />} />
          </Routes>
        </BrowserRouter>
      </AppearanceProvider>
    </ErrorBoundary>
  )
}
