import { useParams, useNavigate } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { api, type RunSummary } from '../api/client'
import { SEV_ORDER, SEV } from '../lib/severity'
import { VD_ORDER, VERDICT } from '../lib/verdict'
import { groupRunsByTool, sortToolGroups, fmtToolName } from '../lib/toolGroups'

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
  return all ? Math.round(((all - (cvd.unmarked ?? 0)) / all) * 100) : 0
}

function fmtDate(s: string | null) {
  if (!s) return '—'
  return s.replace('T', ' ').slice(0, 16)
}

export default function ProjectRuns() {
  const { projectId } = useParams<{ projectId: string }>()
  const navigate = useNavigate()
  const qc = useQueryClient()

  const { data, isLoading, error } = useQuery({
    queryKey: ['project-runs', projectId],
    queryFn: () => api.projectRuns(projectId!),
    enabled: !!projectId,
  })

  const baselineMutation = useMutation({
    mutationFn: ({ runId }: { runId: string | null }) => api.setBaseline(projectId!, runId),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['project-runs', projectId] })
      qc.invalidateQueries({ queryKey: ['projects'] })
    },
  })

  if (isLoading) {
    return (
      <>
        <div className="page-h">
          <div className="skel" style={{ width: 200, height: 26 }} />
        </div>
        <div className="panel">
          {Array.from({ length: 3 }).map((_, i) => (
            <div key={i} className="sk-row">
              <div className="skel" style={{ width: 90, height: 12 }} />
              <div className="skel" style={{ width: 140, height: 12 }} />
              <div className="skel" style={{ flex: 1, height: 7 }} />
            </div>
          ))}
        </div>
      </>
    )
  }

  if (error || !data) {
    return <div className="empty">Ошибка загрузки проекта</div>
  }

  const { project, runs } = data
  const baselineRunId = project.baseline_run_id
  const runsDesc = [...runs].reverse()
  // T-3.5.1: одна «текущая» строка на инструмент — используется панелью сравнения ниже.
  // T-3.5.3: сортировка делает порядок строк детерминированным между рендерами
  // (Map-группировка сама по себе порядок не гарантирует).
  const toolGroups = sortToolGroups(groupRunsByTool(runs))

  return (
    <>
      <div className="page-h">
        <h1>{project.name}</h1>
        <p>{project.repo}{project.team ? ` · ${project.team}` : ''} · история прогонов</p>
      </div>

      <div className="info-strip">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <path d="M12 2a10 10 0 100 20 10 10 0 000-20zM12 8v5M12 16h.01"/>
        </svg>
        <div>
          <b>Бейзлайн сравнения</b> — прогон-эталон, относительно которого считается дельта и переносится разметка. Отметьте звёздочкой нужный прогон.
        </div>
      </div>

      {toolGroups.length > 1 && (
        <div className="panel" style={{ marginBottom: 16 }}>
          <div className="panel-h">
            <svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" strokeWidth="2">
              <circle cx="6" cy="6" r="3"/><circle cx="18" cy="18" r="3"/>
              <path d="M6 9v6a3 3 0 003 3h3M18 15V9a3 3 0 00-3-3h-3"/>
            </svg>
            Сравнение инструментов
          </div>
          <div className="tbl-wrap" style={{ maxHeight: 'none' }}>
            <table className="runs-tbl">
              <thead>
                <tr>
                  <th>Инструмент</th>
                  <th>Последний ран</th>
                  <th>Severity</th>
                  <th>Триаж</th>
                </tr>
              </thead>
              <tbody>
                {toolGroups.map(g => {
                  const counts = g.counts as Record<string, number> ?? {}
                  const cvd = g.counts_by_verdict as Record<string, number> ?? {}
                  return (
                    <tr key={g.key} onClick={() => navigate(`/projects/${projectId}/runs/${g.id}`)}>
                      <td className="muted">{fmtToolName(g.tool)}{g.tool_version ? ` ${g.tool_version}` : ''}</td>
                      <td>
                        <span className="run-link">{g.commit}</span>
                        <div className="muted" style={{ fontSize: 11, marginTop: 3 }}>{fmtDate(g.scanned_at ?? g.uploaded_at)}</div>
                      </td>
                      <td style={{ minWidth: 130 }}>
                        <SevBar counts={counts} />
                        <div className="sevleg">
                          {SEV_ORDER.filter(s => counts[s]).map(s => (
                            <span key={s} style={{ color: SEV[s].c }}>{counts[s]}</span>
                          ))}
                        </div>
                      </td>
                      <td style={{ minWidth: 130 }}>
                        <VBar counts={cvd} />
                        <div className="sevleg muted">{triagePct(cvd)}% размечено</div>
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}

      <div className="panel">
        <div className="tbl-wrap" style={{ maxHeight: 'none' }}>
          <table className="runs-tbl">
            <thead>
              <tr>
                <th>Прогон</th>
                <th>Ветка</th>
                <th>Инструмент</th>
                <th>Дата</th>
                <th>Находок</th>
                <th>Severity</th>
                <th>Триаж</th>
                <th>Бейзлайн</th>
              </tr>
            </thead>
            <tbody>
              {runsDesc.map((r, idx) => {
                const isLatest = idx === 0
                const isBase = r.id === baselineRunId
                const counts = r.counts as Record<string, number> ?? {}
                const cvd = r.counts_by_verdict as Record<string, number> ?? {}
                return (
                  <tr key={r.id}>
                    <td>
                      <span className="run-link" onClick={() => navigate(`/projects/${projectId}/runs/${r.id}`)}>
                        {r.commit}
                      </span>
                      {isLatest && <span className="latest-badge" style={{ marginLeft: 7 }}>последний</span>}
                    </td>
                    <td><span className="pill">{r.branch}</span></td>
                    <td className="muted">{r.tool}{r.tool_version ? ` ${r.tool_version}` : ''}</td>
                    <td className="muted">{fmtDate(r.scanned_at ?? r.uploaded_at)}</td>
                    <td><b>{counts.all ?? 0}</b></td>
                    <td style={{ minWidth: 130 }}>
                      <SevBar counts={counts} />
                      <div className="sevleg">
                        {SEV_ORDER.filter(s => counts[s]).map(s => (
                          <span key={s} style={{ color: SEV[s].c }}>{counts[s]}</span>
                        ))}
                      </div>
                    </td>
                    <td style={{ minWidth: 130 }}>
                      <VBar counts={cvd} />
                      <div className="sevleg muted">{triagePct(cvd)}% размечено</div>
                    </td>
                    <td>
                      {isBase
                        ? <span className="base-badge">★ бейзлайн</span>
                        : (
                          <button
                            className="base-btn"
                            onClick={() => baselineMutation.mutate({ runId: r.id })}
                            disabled={baselineMutation.isPending}
                          >
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                              <path d="M12 2l3 6 7 1-5 5 1 7-6-3-6 3 1-7-5-5 7-1z"/>
                            </svg>
                            задать
                          </button>
                        )
                      }
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      </div>
    </>
  )
}
