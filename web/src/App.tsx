import { Routes, Route, useNavigate, useParams, Link } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { api } from './api/client'
import { SEV_ORDER, SEV } from './lib/severity'
import { VD_ORDER, VERDICT } from './lib/verdict'
import Projects from './routes/Projects'
import ProjectRuns from './routes/ProjectRuns'
import RunView from './routes/RunView'

function Sidebar() {
  const navigate = useNavigate()
  const params = useParams()
  const { data } = useQuery({ queryKey: ['projects'], queryFn: api.projects, refetchInterval: 30_000 })

  const projectId = params.projectId
  const runId = params.runId

  return (
    <aside className="sidebar">
      <div className="brand" onClick={() => navigate('/')}>
        <span className="logo"><img src="/logo.png" alt="SARIF Workbench" /></span>
        <div>
          <div className="bt">SARIF Workbench</div>
          <div className="bs">триаж находок</div>
        </div>
      </div>

      <nav className="nav">
        <Link to="/" className={`nav-item${!projectId && !runId ? ' active' : ''}`}>
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <path d="M3 7h18M3 12h18M3 17h18"/>
          </svg>
          Проекты
        </Link>
      </nav>

      {data && data.projects.length > 0 && (
        <>
          <div className="nav-label">Проекты</div>
          {data.projects.map(p => {
            const counts = p.counts ?? {}
            const all = Object.values(counts).reduce((s: number, n) => s + (n as number), 0)
            const isActive = p.id === projectId
            return (
              <button key={p.id} className={`proj${isActive ? ' active' : ''}`}
                onClick={() => navigate(`/projects/${p.id}`)}>
                <span className="pin" />
                <div style={{ minWidth: 0 }}>
                  <div className="pn">{p.name}</div>
                  <div className="pt">{p.team ?? p.repo}</div>
                </div>
                <span className="ct">{(p.counts as Record<string,number>)?.all ?? all}</span>
              </button>
            )
          })}
        </>
      )}

      <div className="side-foot">
        <span className="dot" style={{ background: 'var(--cyan)' }} />
        v0.1 · sarif-workbench
      </div>
    </aside>
  )
}

function Topbar() {
  const params = useParams()
  const { projectId, runId } = params

  const { data: runData } = useQuery({
    queryKey: ['run', runId],
    queryFn: () => api.run(runId!),
    enabled: !!runId,
  })

  return (
    <div className="topbar">
      <div className="crumb">
        <Link to="/">Проекты</Link>
        {projectId && runData && (
          <>
            <span className="sep">/</span>
            <Link to={`/projects/${projectId}`}>{runData.project_name ?? projectId}</Link>
          </>
        )}
        {runId && runData && (
          <>
            <span className="sep">/</span>
            <span className="mono">{runData.commit}</span>
          </>
        )}
        {projectId && !runId && (
          <>
            <span className="sep">/</span>
            <span>{projectId}</span>
          </>
        )}
      </div>
      <div className="spacer" />
      <span className="count-note" style={{ display: 'flex', alignItems: 'center', gap: 7 }}>
        <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" strokeWidth="2">
          <path d="M4 17l6-6-6-6M12 19h8"/>
        </svg>
        загрузка через swb-cli
      </span>
    </div>
  )
}

function AppShell({ children }: { children: React.ReactNode }) {
  return (
    <div className="app">
      <Sidebar />
      <main className="main">
        <Topbar />
        <div className="content">{children}</div>
      </main>
    </div>
  )
}

// Wrapper components to pass params into shell
function ProjectRunsPage() {
  return <ProjectRuns />
}
function RunViewPage() {
  return <RunView />
}

export default function App() {
  return (
    <Routes>
      <Route path="/" element={<AppShell><Projects /></AppShell>} />
      <Route path="/projects/:projectId" element={<AppShell><ProjectRunsPage /></AppShell>} />
      <Route path="/projects/:projectId/runs/:runId" element={<AppShell><RunViewPage /></AppShell>} />
    </Routes>
  )
}
