import { useState, useCallback } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { api, type FindingItem, type AggGroup } from '../api/client'
import { SEV_ORDER, SEV, sevStyle, sevLabel } from '../lib/severity'
import { VD_ORDER, VERDICT, verdictStyle, verdictLabel } from '../lib/verdict'
import FindingDrawer from '../components/FindingDrawer'
import AnalyzeModal from '../components/AnalyzeModal'

const AGG_TABS = [
  { key: 'severity', label: 'Severity' },
  { key: 'verdict',  label: 'Вердикт' },
  { key: 'rule',     label: 'Правило' },
  { key: 'file',     label: 'Файл' },
  { key: 'cwe',      label: 'CWE' },
] as const

function SevChip({ label, count, color, bg, active, onClick }: {
  label: string; count: number; color: string; bg: string; active: boolean; onClick: () => void
}) {
  return (
    <button
      className={`sev-chip${active ? ' active' : ''}`}
      style={{ color, background: bg }}
      onClick={onClick}
    >
      <span className="n">{count}</span> {label}
    </button>
  )
}

function AggDot({ by, groupKey }: { by: string; groupKey: string }) {
  if (by === 'severity') return <span className="dot" style={{ background: SEV[groupKey as keyof typeof SEV]?.c ?? 'var(--faint)' }} />
  if (by === 'verdict') return <span className="dot" style={{ background: VERDICT[groupKey as keyof typeof VERDICT]?.c ?? 'var(--faint)' }} />
  return <span className="dot" style={{ background: 'var(--primary)' }} />
}

export default function RunView() {
  const { projectId, runId } = useParams<{ projectId: string; runId: string }>()
  const navigate = useNavigate()

  const [aggBy, setAggBy] = useState<string>('severity')
  const [aggValue, setAggValue] = useState<string | null>(null)
  const [sevFilter, setSevFilter] = useState<Set<string>>(new Set())
  const [vdFilter, setVdFilter] = useState<Set<string>>(new Set())
  const [q, setQ] = useState('')
  const [openFid, setOpenFid] = useState<string | null>(null)
  const [showAnalyze, setShowAnalyze]   = useState(false)
  const [resetState, setResetState]     = useState<'idle' | 'confirm' | 'loading'>('idle')
  const [pdfLoading, setPdfLoading]     = useState(false)
  const [sarifLoading, setSarifLoading]     = useState(false)

  const toggleSev = (s: string) => setSevFilter(prev => {
    const n = new Set(prev)
    n.has(s) ? n.delete(s) : n.add(s)
    return n
  })
  const toggleVd = (v: string) => setVdFilter(prev => {
    const n = new Set(prev)
    n.has(v) ? n.delete(v) : n.add(v)
    return n
  })

  // Build query params
  const params: Record<string, string> = { page_size: '500' }
  if (sevFilter.size) params.severity = [...sevFilter].join(',')
  if (vdFilter.size) params.verdict = [...vdFilter].join(',')
  if (q) params.q = q

  const qc = useQueryClient()

  const { data: runData, isLoading: runLoading } = useQuery({
    queryKey: ['run', runId],
    queryFn: () => api.run(runId!),
    enabled: !!runId,
  })

  const { data: findingsData, isLoading: findingsLoading } = useQuery({
    queryKey: ['findings', runId, params],
    queryFn: () => api.findings(runId!, params),
    enabled: !!runId,
  })

  const { data: aggData } = useQuery({
    queryKey: ['agg', runId, aggBy],
    queryFn: () => api.aggregations(runId!, aggBy),
    enabled: !!runId,
  })

  const handleClose = useCallback(() => setOpenFid(null), [])

  async function downloadPDFReport() {
    setPdfLoading(true)
    try {
      const resp = await fetch(`/api/v1/runs/${runId}/report-pdf`)
      if (!resp.ok) {
        const err = await resp.json().catch(() => ({}))
        alert(err.message ?? `Ошибка ${resp.status}`)
        return
      }
      const blob = await resp.blob()
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `report-${runId}.pdf`
      a.click()
      URL.revokeObjectURL(url)
    } finally {
      setPdfLoading(false)
    }
  }

  async function downloadSARIFReport() {
    setSarifLoading(true)
    try {
      const resp = await fetch(`/api/v1/runs/${runId}/report-sarif`)
      if (!resp.ok) {
        const err = await resp.json().catch(() => ({}))
        alert(err.message ?? `Ошибка ${resp.status}`)
        return
      }
      const blob = await resp.blob()
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `report-${runId}.sarif`
      a.click()
      URL.revokeObjectURL(url)
    } finally {
      setSarifLoading(false)
    }
  }

  async function doReset() {
    setResetState('loading')
    try {
      await api.resetVerdicts(runId!)
      qc.invalidateQueries({ queryKey: ['findings', runId] })
      qc.invalidateQueries({ queryKey: ['run', runId] })
      qc.invalidateQueries({ queryKey: ['agg', runId] })
    } finally {
      setResetState('idle')
    }
  }

  if (runLoading) {
    return (
      <>
        <div className="sk-card" style={{ marginBottom: 16 }}>
          <div className="skel" style={{ width: '40%', height: 18, marginBottom: 12 }} />
          <div className="skel" style={{ width: '80%', height: 10 }} />
        </div>
        <div className="work">
          <div className="panel" style={{ height: 200 }} />
          <div className="panel">
            {Array.from({ length: 6 }).map((_, i) => (
              <div key={i} className="sk-row">
                <div className="skel" style={{ width: 70, height: 18 }} />
                <div className="skel" style={{ width: 120, height: 12 }} />
                <div className="skel" style={{ flex: 1, height: 12 }} />
              </div>
            ))}
          </div>
        </div>
      </>
    )
  }

  if (!runData) return <div className="empty">Прогон не найден</div>

  const counts = runData.counts as Record<string, number> ?? {}
  const cvd = runData.counts_by_verdict as Record<string, number> ?? {}

  const items = findingsData?.items ?? []
  let displayed = items

  // Filter by aggValue
  if (aggValue !== null) {
    displayed = displayed.filter(f => {
      if (aggBy === 'severity') return f.severity === aggValue
      if (aggBy === 'verdict') return f.verdict === aggValue
      if (aggBy === 'rule') return `${f.rule_id} ${f.rule_name ?? ''}`.trim() === aggValue
      if (aggBy === 'file') return f.uri === aggValue
      if (aggBy === 'cwe') return (f.cwe ?? f.rule_id) === aggValue
      return true
    })
  }

  return (
    <>
      {/* Run header */}
      <div className="run-head">
        <div className="rh-top">
          <h1>{runData.project_name ?? projectId}</h1>
          <span className="pill">{runData.branch}</span>
          <span className="pill">{runData.commit}</span>
          <div style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: 12, flexWrap: 'wrap' }}>
            <button
              className="btn"
              onClick={() => navigate(`/projects/${projectId}`)}
            >
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" style={{ width: 15, height: 15 }}>
                <path d="M3 9l9-7 9 7v11a2 2 0 01-2 2H5a2 2 0 01-2-2z"/><path d="M9 22V12h6v10"/>
              </svg>
              История прогонов
            </button>
            <button className="btn" onClick={downloadPDFReport} disabled={pdfLoading}>
              {pdfLoading ? (
                <span style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                  <span style={{ width: 14, height: 14, border: '2px solid #ccc', borderTopColor: 'var(--primary)', borderRadius: '50%', animation: 'spin .7s linear infinite', flexShrink: 0 }} />
                  Генерация…
                </span>
              ) : (
                <>
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" style={{ width: 15, height: 15 }}>
                    <path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/>
                    <polyline points="14 2 14 8 20 8"/>
                    <line x1="12" y1="18" x2="12" y2="12"/>
                    <polyline points="9 15 12 18 15 15"/>
                  </svg>
                  Скачать отчёт PDF
                </>
              )}
            </button>
            <button className="btn" onClick={downloadSARIFReport} disabled={sarifLoading}>
              {sarifLoading ? (
                <span style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                  <span style={{ width: 14, height: 14, border: '2px solid #ccc', borderTopColor: 'var(--primary)', borderRadius: '50%', animation: 'spin .7s linear infinite', flexShrink: 0 }} />
                  Генерация…
                </span>
              ) : (
                <>
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" style={{ width: 15, height: 15 }}>
                    <path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/>
                    <polyline points="14 2 14 8 20 8"/>
                    <line x1="12" y1="18" x2="12" y2="12"/>
                    <polyline points="9 15 12 18 15 15"/>
                  </svg>
                  Скачать отчёт SARIF
                </>
              )}
            </button>
            {resetState === 'idle' && (
              <button className="btn" onClick={() => setResetState('confirm')}>
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" style={{ width: 15, height: 15 }}>
                  <path d="M3 12a9 9 0 1 0 9-9 9.75 9.75 0 0 0-6.74 2.74L3 8"/>
                  <path d="M3 3v5h5"/>
                </svg>
                Сбросить вердикты
              </button>
            )}
            {resetState === 'confirm' && (
              <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                <span style={{ fontSize: 12, color: 'var(--crit)', fontWeight: 600 }}>Сбросить все вердикты?</span>
                <button className="btn btn-danger" style={{ padding: '5px 10px', fontSize: 12 }} onClick={doReset}>Да</button>
                <button className="btn" style={{ padding: '5px 10px', fontSize: 12 }} onClick={() => setResetState('idle')}>Отмена</button>
              </div>
            )}
            {resetState === 'loading' && (
              <span style={{ fontSize: 12, color: 'var(--muted)' }}>Сбрасываю…</span>
            )}
            <button
              className="btn btn-primary"
              onClick={() => setShowAnalyze(true)}
            >
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" style={{ width: 15, height: 15 }}>
                <circle cx="12" cy="12" r="3"/><path d="M12 1v4M12 19v4M4.22 4.22l2.83 2.83M16.95 16.95l2.83 2.83M1 12h4M19 12h4M4.22 19.78l2.83-2.83M16.95 7.05l2.83-2.83"/>
              </svg>
              Анализировать ИИ
            </button>
          </div>
        </div>

        <div className="rh-sub">
          {runData.tool && <span>Инструмент: <b>{runData.tool}{runData.tool_version ? ` ${runData.tool_version}` : ''}</b></span>}
          {runData.scanned_at && <span>Сканирование: <b>{runData.scanned_at.replace('T', ' ').slice(0, 16)}</b></span>}
          <span>Всего: <b>{counts.all ?? 0}</b></span>
        </div>

        <div className="sev-summary">
          <span className="sum-label">Severity</span>
          {SEV_ORDER.map(s => (
            <SevChip
              key={s}
              label={SEV[s].label}
              count={counts[s] ?? 0}
              color={SEV[s].c}
              bg={SEV[s].bg}
              active={sevFilter.has(s)}
              onClick={() => toggleSev(s)}
            />
          ))}
        </div>

        <div className="sev-summary">
          <span className="sum-label">Вердикт</span>
          {VD_ORDER.map(v => (
            <SevChip
              key={v}
              label={VERDICT[v].label}
              count={cvd[v] ?? 0}
              color={VERDICT[v].c}
              bg={VERDICT[v].bg}
              active={vdFilter.has(v)}
              onClick={() => toggleVd(v)}
            />
          ))}
        </div>
      </div>

      <div className="work">
        {/* Aggregation panel */}
        <div className="panel">
          <div className="panel-h">
            <svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M3 6h18M7 12h10M11 18h2"/>
            </svg>
            Агрегация
          </div>
          <div className="agg-tabs">
            {AGG_TABS.map(t => (
              <button
                key={t.key}
                className={`agg-tab${aggBy === t.key ? ' active' : ''}`}
                onClick={() => { setAggBy(t.key); setAggValue(null) }}
              >
                {t.label}
              </button>
            ))}
          </div>
          <div className="agg-list">
            {(aggData?.groups ?? []).map((g: AggGroup) => {
              const label = aggBy === 'severity' ? sevLabel(g.key)
                : aggBy === 'verdict' ? verdictLabel(g.key)
                : g.label
              return (
                <button
                  key={g.key}
                  className={`agg-row${aggValue === g.key ? ' active' : ''}`}
                  onClick={() => setAggValue(aggValue === g.key ? null : g.key)}
                >
                  <AggDot by={aggBy} groupKey={g.key} />
                  <span className="lbl">{label}</span>
                  <span className="cnt">{g.count}</span>
                </button>
              )
            })}
          </div>
        </div>

        {/* Findings table */}
        <div className="panel">
          <div className="filterbar">
            <div className="search">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <circle cx="11" cy="11" r="7"/><path d="M21 21l-4-4"/>
              </svg>
              <input
                placeholder="Поиск по файлу, правилу, сообщению, функции…"
                value={q}
                onChange={e => setQ(e.target.value)}
              />
            </div>
            <span className="count-note">
              {findingsLoading ? '…' : `${displayed.length} из ${findingsData?.total ?? 0}`}
            </span>
            <button
              className="chip-clear"
              onClick={() => { setSevFilter(new Set()); setVdFilter(new Set()); setQ(''); setAggValue(null) }}
            >
              Сбросить
            </button>
          </div>

          <div className="tbl-wrap">
            <table>
              <thead>
                <tr>
                  <th>Severity</th>
                  <th>Правило</th>
                  <th>Расположение</th>
                  <th>Функция</th>
                  <th>Сообщение</th>
                  <th>Вердикт</th>
                </tr>
              </thead>
              <tbody>
                {findingsLoading && (
                  <tr><td colSpan={6}>
                    {Array.from({ length: 5 }).map((_, i) => (
                      <div key={i} className="sk-row">
                        <div className="skel" style={{ width: 70, height: 18 }} />
                        <div className="skel" style={{ flex: 1, height: 12 }} />
                      </div>
                    ))}
                  </td></tr>
                )}
                {!findingsLoading && displayed.length === 0 && (
                  <tr><td colSpan={6}>
                    <div className="empty">
                      <svg viewBox="0 0 64 64" fill="none" stroke="currentColor" strokeWidth="2.4">
                        <path d="M14 40c3-13 14-21 26-19" strokeLinecap="round"/>
                        <path d="M16 47c0-9 7-15 16-15 6 0 10 3 13 7"/>
                        <circle cx="33" cy="40" r="1.4" fill="currentColor"/>
                      </svg>
                      <div>Нет находок под текущие фильтры</div>
                    </div>
                  </td></tr>
                )}
                {!findingsLoading && displayed.map((f: FindingItem) => (
                  <tr key={f.id} onClick={() => setOpenFid(f.id)}>
                    <td>
                      <span className="sev-tag" style={sevStyle(f.severity)}>
                        <span className="dot" style={{ background: SEV[f.severity as keyof typeof SEV]?.c ?? 'var(--note)' }} />
                        {sevLabel(f.severity)}
                      </span>
                    </td>
                    <td>
                      <div className="rule-cell">
                        <span className="rid">{f.cwe ?? f.rule_id}</span>
                        <span className="rnm">{f.rule_name}</span>
                      </div>
                    </td>
                    <td>
                      <span className="loc">
                        {f.uri.split('/').slice(-2).join('/')}
                        <span className="ln">:{f.start_line}</span>
                      </span>
                    </td>
                    <td><span className="scope">{f.scope ?? '—'}</span></td>
                    <td><span className="msg" title={f.message}>{f.message}</span></td>
                    <td>
                      <span className="vd-tag" style={verdictStyle(f.verdict)}>
                        {verdictLabel(f.verdict)}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>

      <FindingDrawer findingId={openFid} runId={runId!} onClose={handleClose} />

      {showAnalyze && (
        <AnalyzeModal
          runId={runId!}
          totalUnmarked={cvd.unmarked ?? 0}
          onClose={() => setShowAnalyze(false)}
        />
      )}
    </>
  )
}
