import { useEffect } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { api, normalizeDetail } from '../api/client'
import { SEV, sevStyle } from '../lib/severity'
import { VERDICT, SRC_LABEL, verdictStyle, verdictLabel } from '../lib/verdict'

interface Props {
  findingId: string | null
  runId: string
  onClose: () => void
}

function CodeBlock({ snippet, hotLine }: { snippet: { start_line: number; lines: string[]; hot_line: number }; hotLine?: number }) {
  const hl = hotLine ?? snippet.hot_line
  return (
    <div className="code">
      {snippet.lines.map((ln, i) => {
        const num = snippet.start_line + i
        const isHot = num === hl
        return (
          <div key={i} className={`cl${isHot ? ' hot' : ''}`}>
            <span className="gut">{num}</span>
            <span className="src">{ln}</span>
          </div>
        )
      })}
    </div>
  )
}

export default function FindingDrawer({ findingId, runId, onClose }: Props) {
  const qc = useQueryClient()
  const open = !!findingId

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose() }
    document.addEventListener('keydown', onKey)
    return () => document.removeEventListener('keydown', onKey)
  }, [onClose])

  const { data: raw, isLoading } = useQuery({
    queryKey: ['finding', findingId],
    queryFn: () => api.finding(findingId!),
    enabled: !!findingId,
  })

  const verdictMut = useMutation({
    mutationFn: ({ verdict, rationale }: { verdict: string; rationale: string }) =>
      api.setVerdict(findingId!, verdict, rationale),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['finding', findingId] })
      qc.invalidateQueries({ queryKey: ['findings', runId] })
      qc.invalidateQueries({ queryKey: ['run', runId] })
    },
  })

  const f = raw ? normalizeDetail(raw as Record<string, unknown>) : null

  return (
    <>
      <div className={`scrim${open ? ' open' : ''}`} onClick={onClose} />
      <aside className={`drawer${open ? ' open' : ''}`}>
        {isLoading && (
          <div style={{ padding: 24 }}>
            <div className="skel" style={{ height: 16, width: '60%', marginBottom: 12 }} />
            <div className="skel" style={{ height: 12, width: '80%' }} />
          </div>
        )}

        {f && (
          <>
            <div className="dr-head">
              <div style={{ flex: 1 }}>
                <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center' }}>
                  <span className="sev-tag" style={sevStyle(f.severity)}>
                    <span className="dot" style={{ background: SEV[f.severity as keyof typeof SEV]?.c ?? 'var(--note)' }} />
                    {SEV[f.severity as keyof typeof SEV]?.label ?? f.severity}
                  </span>
                  {f.cwe && <span className="pill">{f.cwe}</span>}
                  <span className="vd-tag" style={verdictStyle(f.verdictObj.verdict)}>
                    {verdictLabel(f.verdictObj.verdict)}
                  </span>
                </div>
                <h2 style={{ marginTop: 8 }}>{f.rule_name || f.rule_id}</h2>
              </div>
              <button className="dr-close" onClick={onClose}>
                <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" strokeWidth="2">
                  <path d="M18 6L6 18M6 6l12 12"/>
                </svg>
              </button>
            </div>

            <div className="dr-body">
              {/* Location */}
              <div className="dr-sec">
                <h3>Расположение</h3>
                <div className="kv">
                  <span className="k">Файл</span>
                  <span className="v mono">{f.uri}:{f.start_line}</span>
                  {f.scope && <><span className="k">Функция</span><span className="v mono">{f.scope}</span></>}
                  {f.lang && <><span className="k">Язык</span><span className="v">{f.lang}</span></>}
                  <span className="k">swb_id</span>
                  <span className="v mono">{f.swb_id}</span>
                </div>
              </div>

              {/* Code snippet */}
              {f.snippet && (
                <div className="dr-sec">
                  <h3>Код</h3>
                  <CodeBlock snippet={f.snippet} hotLine={f.start_line} />
                </div>
              )}

              {/* Message */}
              <div className="dr-sec">
                <h3>Сообщение анализатора</h3>
                <div className="rule-desc">{f.message}</div>
              </div>

              {/* Rule description */}
              {f.rule_description && (
                <div className="dr-sec">
                  <h3>Описание правила{f.cwe ? ` (${f.cwe})` : ''}</h3>
                  <div className="rule-desc">{f.rule_description}</div>
                </div>
              )}

              {/* Git info */}
              {f.git && (
                <div className="dr-sec">
                  <h3>Git</h3>
                  <div className="kv">
                    {f.git.last_changed && <><span className="k">Изменено</span><span className="v">{f.git.last_changed}</span></>}
                    {f.git.blame_commit && <><span className="k">blame-коммит</span><span className="v mono">{f.git.blame_commit}</span></>}
                    {f.git.blob_sha && <><span className="k">blob sha</span><span className="v mono">{f.git.blob_sha}</span></>}
                  </div>
                </div>
              )}

              {/* Verdict */}
              <div className="dr-sec">
                <h3>Вердикт триажа</h3>
                <VerdictCard verdict={f.verdictObj} />

                <div className="vd-actions-h">Переопределить</div>
                <div className="vd-actions">
                  {(['true_positive', 'false_positive', 'uncertain'] as const).map(v => {
                    const isActive = f.verdictObj.verdict === v
                    return (
                      <button
                        key={v}
                        className="vd-btn"
                        style={isActive ? { background: VERDICT[v].c, borderColor: VERDICT[v].c, color: '#fff' } : undefined}
                        onClick={() => verdictMut.mutate({ verdict: v, rationale: '' })}
                        disabled={verdictMut.isPending}
                      >
                        <span className="dot" style={{ background: VERDICT[v].c }} />
                        {VERDICT[v].label}
                      </button>
                    )
                  })}
                  <button
                    className="vd-btn"
                    onClick={() => verdictMut.mutate({ verdict: 'unmarked', rationale: '' })}
                    disabled={verdictMut.isPending || f.verdictObj.verdict === 'unmarked'}
                  >
                    Сбросить
                  </button>
                </div>

                {/* Audit trail */}
                {f.verdictObj.history.length > 0 && (
                  <>
                    <div className="vd-actions-h">История</div>
                    <div className="audit">
                      {f.verdictObj.history.map((h, i) => (
                        <div key={i} className="ar">
                          <span className="adot" style={{ background: h.source === 'human' ? 'var(--primary)' : 'var(--cyan)' }} />
                          <span>{SRC_LABEL[h.source ?? ''] ?? h.source} → <b>{verdictLabel(h.verdict)}</b></span>
                          <span style={{ flex: 1 }} />
                          <span className="faint mono">{h.at?.slice(0, 10)}</span>
                        </div>
                      ))}
                    </div>
                  </>
                )}
              </div>
            </div>
          </>
        )}
      </aside>
    </>
  )
}

function VerdictCard({ verdict }: { verdict: ReturnType<typeof normalizeDetail>['verdictObj'] }) {
  const v = verdict.verdict
  if (v === 'unmarked') {
    return (
      <div className="vd-card">
        <div className="vh">
          <span className="vd-tag" style={verdictStyle('unmarked')}>Не размечено</span>
        </div>
        <div className="rationale muted">Находка ещё не прошла триаж и не размечена инженером.</div>
      </div>
    )
  }
  return (
    <div className="vd-card">
      <div className="vh">
        <span className="vd-tag" style={verdictStyle(v)}>{verdictLabel(v)}</span>
        {verdict.source && (
          <span className="src-tag">
            <span className="dot" style={{ background: verdict.source === 'human' ? 'var(--primary)' : 'var(--cyan)' }} />
            {SRC_LABEL[verdict.source] ?? verdict.source}
          </span>
        )}
      </div>
      {verdict.rationale && <div className="rationale">{verdict.rationale}</div>}
    </div>
  )
}
