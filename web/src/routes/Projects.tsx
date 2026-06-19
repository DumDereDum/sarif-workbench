import { useNavigate } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { api, type Project } from '../api/client'
import { SEV_ORDER, SEV, sevStyle } from '../lib/severity'
import { VD_ORDER, VERDICT, verdictStyle } from '../lib/verdict'

function SevBar({ counts }: { counts: Partial<Record<string, number>> }) {
  const total = SEV_ORDER.reduce((s, k) => s + (counts[k] ?? 0), 0) || 1
  return (
    <div className="sevbar">
      {SEV_ORDER.map(s => counts[s] ? (
        <i key={s} style={{ width: `${(counts[s]! / total) * 100}%`, background: SEV[s].c }} />
      ) : null)}
    </div>
  )
}

function VBar({ counts }: { counts: Partial<Record<string, number>> }) {
  const total = VD_ORDER.reduce((s, k) => s + (counts[k] ?? 0), 0) || 1
  return (
    <div className="vbar">
      {VD_ORDER.map(v => counts[v] ? (
        <i key={v} style={{ width: `${(counts[v]! / total) * 100}%`, background: VERDICT[v].c }} />
      ) : null)}
    </div>
  )
}

function triagePct(cvd: Partial<Record<string, number>>) {
  const all = VD_ORDER.reduce((s, k) => s + (cvd[k] ?? 0), 0)
  const unmarked = cvd.unmarked ?? 0
  return all ? Math.round((all - unmarked) / all * 100) : 0
}

function ProjectCard({ p, onClick }: { p: Project; onClick: () => void }) {
  const counts = p.counts as Record<string, number> ?? {}
  const cvd = p.counts_by_verdict as Record<string, number> ?? {}
  const all = counts.all ?? SEV_ORDER.reduce((s, k) => s + (counts[k] ?? 0), 0)

  return (
    <div className="card" onClick={onClick}>
      <div className="card-top">
        <div className="repo-ic">
          <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" strokeWidth="2">
            <path d="M4 4h11l5 5v11H4z"/><path d="M15 4v5h5"/>
          </svg>
        </div>
        <div style={{ minWidth: 0 }}>
          <div className="nm">{p.name}</div>
          <div className="rp">{p.repo}</div>
        </div>
      </div>

      <div className="meta-row">
        <span>Находок: <b>{all}</b></span>
        {p.last_run && <span>Инструмент: <b>{p.last_run.tool}</b></span>}
        {p.last_run && <span>Коммит: <b className="mono">{p.last_run.commit}</b></span>}
      </div>

      <SevBar counts={counts} />
      <div className="sevleg">
        {SEV_ORDER.filter(s => counts[s]).map(s => (
          <span key={s}>
            <i className="dot" style={{ background: SEV[s].c }} />
            {SEV[s].label} {counts[s]}
          </span>
        ))}
      </div>

      <div className="triage-line">
        <div className="tl-h">
          <span>Триаж</span>
          <span>{triagePct(cvd)}% размечено</span>
        </div>
        <VBar counts={cvd} />
      </div>
    </div>
  )
}

function SkeletonGrid() {
  return (
    <div className="grid">
      {Array.from({ length: 4 }).map((_, i) => (
        <div key={i} className="sk-card">
          <div className="skel" style={{ width: '60%', height: 16, marginBottom: 14 }} />
          <div className="skel" style={{ width: '90%', height: 10, marginBottom: 8 }} />
          <div className="skel" style={{ width: '100%', height: 7, marginBottom: 12 }} />
          <div className="skel" style={{ width: '70%', height: 10 }} />
        </div>
      ))}
    </div>
  )
}

export default function Projects() {
  const navigate = useNavigate()
  const { data, isLoading, error } = useQuery({
    queryKey: ['projects'],
    queryFn: api.projects,
    refetchInterval: 30_000,
  })

  if (isLoading) {
    return (
      <>
        <div className="page-h">
          <div className="skel" style={{ width: 160, height: 26 }} />
        </div>
        <SkeletonGrid />
      </>
    )
  }

  if (error) {
    return (
      <div className="empty">
        <div>Ошибка загрузки: {String(error)}</div>
      </div>
    )
  }

  const projects = data?.projects ?? []

  if (projects.length === 0) {
    return (
      <>
        <div className="page-h">
          <h1>Проекты</h1>
        </div>
        <div className="empty">
          <svg viewBox="0 0 64 64" fill="none" stroke="currentColor" strokeWidth="2.4">
            <path d="M14 40c3-13 14-21 26-19" strokeLinecap="round"/>
            <path d="M16 47c0-9 7-15 16-15 6 0 10 3 13 7"/>
            <circle cx="33" cy="40" r="1.4" fill="currentColor"/>
          </svg>
          <div>Проектов пока нет</div>
          <div style={{ marginTop: 8, color: 'var(--muted)', fontSize: 12 }}>
            Загрузите SARIF через <code className="mono">swb-cli enrich</code> и <code className="mono">swb-cli upload</code>
          </div>
        </div>
      </>
    )
  }

  return (
    <>
      <div className="page-h">
        <h1>Проекты</h1>
        <p>{projects.length} {projects.length === 1 ? 'проект' : 'проектов'} · последние прогоны SAST · данные загружены через swb-cli</p>
      </div>
      <div className="grid">
        {projects.map(p => (
          <ProjectCard
            key={p.id}
            p={p}
            onClick={() => p.last_run
              ? navigate(`/projects/${p.id}/runs/${p.last_run.id}`)
              : navigate(`/projects/${p.id}`)
            }
          />
        ))}
      </div>
    </>
  )
}
