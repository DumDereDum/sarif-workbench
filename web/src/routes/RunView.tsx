import { useState, useCallback, useEffect } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { api, type FindingItem, type AggGroup } from '../api/client'
import { SEV_ORDER, SEV, sevStyle, sevLabel } from '../lib/severity'
import { VD_ORDER, VERDICT, verdictStyle, verdictLabel } from '../lib/verdict'
import FindingDrawer from '../components/FindingDrawer'
import AnalyzeModal from '../components/AnalyzeModal'
import DiffView from '../components/DiffView'
import StatusMessage from '../components/StatusMessage'

const VIEW_TABS = [
  { key: 'findings', label: 'Находки' },
  { key: 'diff',      label: 'Сравнение с бейзлайном' },
] as const

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

  const [view, setView] = useState<typeof VIEW_TABS[number]['key']>('findings')
  const [aggBy, setAggBy] = useState<string>('severity')
  const [aggValue, setAggValue] = useState<string | null>(null)
  const [sevFilter, setSevFilter] = useState<Set<string>>(new Set())
  const [vdFilter, setVdFilter] = useState<Set<string>>(new Set())
  const [q, setQ] = useState('')
  const [debouncedQ, setDebouncedQ] = useState('')
  const [page, setPage] = useState(1)
  const [openFid, setOpenFid] = useState<string | null>(null)
  const [openFindingRunId, setOpenFindingRunId] = useState<string | null>(null)
  const [showAnalyze, setShowAnalyze]   = useState(false)
  const [resetState, setResetState]     = useState<'idle' | 'confirm' | 'loading'>('idle')
  const [pdfLoading, setPdfLoading]     = useState(false)
  const [pdfError, setPdfError]         = useState<string | null>(null)
  const [resetError, setResetError]     = useState<string | null>(null)

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

  useEffect(() => {
    const timer = window.setTimeout(() => setDebouncedQ(q.trim()), 300)
    return () => window.clearTimeout(timer)
  }, [q])

  useEffect(() => { setPage(1) }, [sevFilter, vdFilter, aggBy, aggValue, debouncedQ])

  // Keep filtering and pagination on the server so every matching result is reachable.
  const params: Record<string, string> = { page: String(page), page_size: '100' }
  if (sevFilter.size) params.severity = [...sevFilter].join(',')
  if (vdFilter.size) params.verdict = [...vdFilter].join(',')
  if (debouncedQ) params.q = debouncedQ
  if (aggValue !== null) {
    if (aggBy === 'severity') params.severity = aggValue
    if (aggBy === 'verdict') params.verdict = aggValue
    if (aggBy === 'rule') params.rule_id_exact = aggValue
    if (aggBy === 'file') params.uri_exact = aggValue
    if (aggBy === 'cwe') params.cwe_key = aggValue
  }

  // Facet counts respect the other active filters while leaving the current
  // facet open, so its choices and counts remain useful for changing it.
  const aggParams: Record<string, string> = {}
  if (aggBy !== 'severity' && sevFilter.size) aggParams.severity = [...sevFilter].join(',')
  if (aggBy !== 'verdict' && vdFilter.size) aggParams.verdict = [...vdFilter].join(',')
  if (debouncedQ) aggParams.q = debouncedQ

  const qc = useQueryClient()

  const { data: runData, isLoading: runLoading, error: runError } = useQuery({
    queryKey: ['run', runId],
    queryFn: () => api.run(runId!),
    enabled: !!runId,
  })

  const { data: findingsData, isLoading: findingsLoading, isFetching: findingsFetching, error: findingsError } = useQuery({
    queryKey: ['findings', runId, params],
    queryFn: () => api.findings(runId!, params),
    enabled: !!runId,
  })

  const { data: aggData, error: aggError } = useQuery({
    queryKey: ['agg', runId, aggBy, aggParams],
    queryFn: () => api.aggregations(runId!, aggBy, aggParams),
    enabled: !!runId,
  })

  const handleClose = useCallback(() => setOpenFid(null), [])

  async function downloadReport() {
    setPdfLoading(true)
    setPdfError(null)
    try {
      const resp = await fetch(`/api/v1/runs/${runId}/report`)
      if (!resp.ok) {
        const err = await resp.json().catch(() => ({}))
        console.error('Не удалось скачать PDF-отчёт:', resp.status, err)
        setPdfError(err?.detail?.message ?? err?.message ?? `Не удалось сгенерировать отчёт (ошибка ${resp.status})`)
        return
      }
      const blob = await resp.blob()
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `report-${runId}.pdf`
      a.click()
      URL.revokeObjectURL(url)
    } catch (e) {
      console.error('Не удалось скачать PDF-отчёт:', e)
      setPdfError('Не удалось скачать отчёт — проверьте соединение с сервером')
    } finally {
      setPdfLoading(false)
    }
  }

  async function doReset() {
    setResetState('loading')
    setResetError(null)
    try {
      await api.resetVerdicts(runId!)
      qc.invalidateQueries({ queryKey: ['findings', runId] })
      qc.invalidateQueries({ queryKey: ['run', runId] })
      qc.invalidateQueries({ queryKey: ['agg', runId] })
    } catch (error) {
      setResetError(`Не удалось сбросить вердикты: ${String(error)}`)
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

  if (!runData) return (
    <StatusMessage tone="error" title={runError ? 'Не удалось загрузить прогон' : 'Прогон не найден'}>
      {runError ? String(runError) : 'Проверьте ссылку или вернитесь к истории прогонов.'}
    </StatusMessage>
  )

  const counts = runData.counts as Record<string, number> ?? {}
  const cvd = runData.counts_by_verdict as Record<string, number> ?? {}

  const displayed = findingsData?.items ?? []
  const total = findingsData?.total ?? 0
  const pageSize = findingsData?.page_size ?? 100
  const totalPages = Math.max(1, Math.ceil(total / pageSize))
  const firstItem = total === 0 ? 0 : (page - 1) * pageSize + 1
  const lastItem = Math.min(page * pageSize, total)
  const searchPending = q.trim() !== debouncedQ

  const clearAllFilters = () => {
    setSevFilter(new Set())
    setVdFilter(new Set())
    setQ('')
    setDebouncedQ('')
    setAggValue(null)
    setPage(1)
  }

  const activeFilterLabels = [
    ...[...sevFilter].map(value => ({ key: `severity:${value}`, label: sevLabel(value), remove: () => setSevFilter(prev => { const next = new Set(prev); next.delete(value); return next }) })),
    ...[...vdFilter].map(value => ({ key: `verdict:${value}`, label: verdictLabel(value), remove: () => setVdFilter(prev => { const next = new Set(prev); next.delete(value); return next }) })),
    ...(aggValue !== null ? [{
      key: `group:${aggBy}:${aggValue}`,
      label: `${AGG_TABS.find(t => t.key === aggBy)?.label}: ${aggData?.groups.find(g => g.key === aggValue)?.label ?? aggValue}`,
      remove: () => setAggValue(null),
    }] : []),
    ...(q.trim() ? [{ key: 'search', label: `Поиск: ${q.trim()}`, remove: () => { setQ(''); setDebouncedQ('') } }] : []),
  ]

  const openFinding = (findingId: string, findingRunId = runId!) => {
    setOpenFindingRunId(findingRunId)
    setOpenFid(findingId)
  }

  const toggleAggregate = (key: string) => {
    setPage(1)
    if (aggBy === 'severity') {
      setSevFilter(prev => prev.size === 1 && prev.has(key) ? new Set() : new Set([key]))
      setAggValue(null)
    } else if (aggBy === 'verdict') {
      setVdFilter(prev => prev.size === 1 && prev.has(key) ? new Set() : new Set([key]))
      setAggValue(null)
    } else {
      setAggValue(aggValue === key ? null : key)
    }
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
            <button className="btn" onClick={downloadReport} disabled={pdfLoading}>
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

        {pdfError && (
          <StatusMessage tone="error" title="Не удалось скачать PDF">{pdfError}</StatusMessage>
        )}
        {resetError && <StatusMessage tone="error" title="Сброс не выполнен">{resetError}</StatusMessage>}

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
              onClick={() => { toggleSev(s); setPage(1) }}
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
              onClick={() => { toggleVd(v); setPage(1) }}
            />
          ))}
        </div>
      </div>

      <div className="panel" style={{ marginBottom: 16 }}>
        <div className="agg-tabs">
          {VIEW_TABS.map(t => (
            <button
              key={t.key}
              className={`agg-tab${view === t.key ? ' active' : ''}`}
              onClick={() => setView(t.key)}
            >
              {t.label}
            </button>
          ))}
        </div>
      </div>

      {view === 'diff' && (
        <DiffView
          runId={runId!}
          baselineRunId={runData.baseline_run_id}
          onOpenFinding={openFinding}
        />
      )}

      {view === 'findings' && (
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
                onClick={() => { setAggBy(t.key); setAggValue(null); setPage(1) }}
              >
                {t.label}
              </button>
            ))}
          </div>
          <div className="agg-list">
            {aggError && <StatusMessage tone="error" title="Не удалось загрузить сводку" compact>{String(aggError)}</StatusMessage>}
            {(aggData?.groups ?? []).map((g: AggGroup) => {
              const label = aggBy === 'severity' ? sevLabel(g.key)
                : aggBy === 'verdict' ? verdictLabel(g.key)
                : g.label
              return (
                <button
                  key={g.key}
                  className={`agg-row${(aggBy === 'severity' ? sevFilter.has(g.key) : aggBy === 'verdict' ? vdFilter.has(g.key) : aggValue === g.key) ? ' active' : ''}`}
                  onClick={() => toggleAggregate(g.key)}
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
                onChange={e => { setQ(e.target.value); setPage(1) }}
              />
            </div>
            <span className="count-note">
              {findingsFetching || searchPending ? 'Обновление…' : `Показано ${firstItem}–${lastItem} из ${total}`}
            </span>
            <button
              className="chip-clear"
              onClick={clearAllFilters}
            >
              Сбросить всё
            </button>
            {activeFilterLabels.length > 0 && (
              <div className="active-filters" aria-label="Активные фильтры">
                {activeFilterLabels.map(filter => (
                  <button key={filter.key} className="filter-chip" onClick={filter.remove} title="Убрать фильтр">
                    {filter.label}<span aria-hidden="true">×</span>
                  </button>
                ))}
              </div>
            )}
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
                {findingsError && (
                  <tr><td colSpan={6}>
                    <StatusMessage tone="error" title="Не удалось загрузить находки" compact>
                      {String(findingsError)}
                    </StatusMessage>
                  </td></tr>
                )}
                {!findingsLoading && !findingsError && displayed.length === 0 && (
                  <tr><td colSpan={6}>
                    <StatusMessage tone="empty" title="Нет находок под текущие фильтры">
                      Уберите часть фильтров или измените поисковый запрос.
                    </StatusMessage>
                  </td></tr>
                )}
                {!findingsLoading && !findingsError && displayed.map((f: FindingItem) => (
                  <tr key={f.id} onClick={() => openFinding(f.id)}>
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
          {totalPages > 1 && !findingsError && (
            <div className="pagination" aria-label="Страницы находок">
              <span className="muted">Страница {page} из {totalPages}</span>
              <div className="pagination-actions">
                <button className="btn" onClick={() => setPage(p => Math.max(1, p - 1))} disabled={page <= 1 || findingsFetching || searchPending}>
                  Назад
                </button>
                <button className="btn" onClick={() => setPage(p => Math.min(totalPages, p + 1))} disabled={page >= totalPages || findingsFetching || searchPending}>
                  Далее
                </button>
              </div>
            </div>
          )}
        </div>
      </div>
      )}

      <FindingDrawer
        findingId={openFid}
        runId={openFindingRunId ?? runId!}
        onClose={handleClose}
        onVerdictUpdated={() => qc.invalidateQueries({ queryKey: ['diff', runId, runData.baseline_run_id] })}
      />

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
