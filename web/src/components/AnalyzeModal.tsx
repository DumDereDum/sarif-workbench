import { useState, useRef, useEffect } from 'react'
import { useQueryClient } from '@tanstack/react-query'

// T-44: provider/model/key no longer live on the client (no localStorage,
// no api_key field anywhere) — GET /api/v1/providers is the single source
// of truth for what's actually configured and callable on the server
// (T-42 gates already applied there: a disabled remote provider is simply
// absent from this list, not just refused when called).
interface ProviderInfo {
  name: string
  local: boolean
  default_model: string | null
}

interface AnalyzeModalProps {
  runId: string
  totalUnmarked: number
  onClose: () => void
}

type Step = 'config' | 'running' | 'done'

interface ErrorEntry {
  finding_id: string
  uri: string
  start_line: number
  message: string
}

interface Progress {
  done: number
  total: number
  tokens: number
  errors: number
  lastVerdict?: string
  errorLog: ErrorEntry[]
  stoppedReason?: string
  stopMessage?: string
}

const STANDARD_PROMPTS = [
  { id: 'honest',   label: 'Честный анализ',       desc: 'ИИ выносит настоящий вердикт: TP / FP / Uncertain' },
  { id: 'force_fp', label: 'Все — False Positive',  desc: 'Принудительно размечает все находки как FP с формальным комментарием' },
]

function ErrorLog({ entries, defaultOpen = false }: { entries: ErrorEntry[]; defaultOpen?: boolean }) {
  const [open, setOpen] = useState(defaultOpen)
  return (
    <div className="err-log">
      <button className="err-log-toggle" onClick={() => setOpen(o => !o)}>
        <svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" strokeWidth="2">
          <path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/>
          <line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>
        </svg>
        {entries.length} {entries.length === 1 ? 'ошибка' : 'ошибок'}
        <svg viewBox="0 0 24 24" width="12" height="12" fill="none" stroke="currentColor" strokeWidth="2"
          style={{ marginLeft: 'auto', transform: open ? 'rotate(180deg)' : 'none', transition: 'transform .15s' }}>
          <path d="M6 9l6 6 6-6"/>
        </svg>
      </button>
      {open && (
        <div className="err-log-body">
          {entries.map((e, i) => (
            <div key={i} className="err-entry">
              <span className="err-loc">{e.uri.split('/').slice(-1)[0]}:{e.start_line}</span>
              <span className="err-msg">{e.message}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

export default function AnalyzeModal({ runId, totalUnmarked, onClose }: AnalyzeModalProps) {
  const qc = useQueryClient()
  const abortRef = useRef<AbortController | null>(null)

  const [step, setStep]               = useState<Step>('config')
  const [providers, setProviders]     = useState<ProviderInfo[]>([])
  const [providersLoaded, setProvidersLoaded] = useState(false)
  const [selProvider, setSelProvider] = useState('')
  const [model, setModel]             = useState('')
  const [promptId, setPromptId]       = useState('honest')
  const [customSystem, setCustom]     = useState('')
  const [progress, setProgress]       = useState<Progress>({ done: 0, total: 0, tokens: 0, errors: 0, errorLog: [] })
  const [errMsg, setErrMsg]           = useState('')
  const [promptTexts, setPromptTexts] = useState<Record<string, string>>({})
  const [providersLoadError, setProvidersLoadError] = useState<string | null>(null)

  useEffect(() => {
    fetch('/api/v1/prompts')
      .then(r => r.json())
      .then((data: { prompts: { id: string; system: string }[] }) => {
        const map: Record<string, string> = {}
        for (const p of data.prompts) map[p.id] = p.system
        setPromptTexts(map)
      })
      .catch(e => console.error('Не удалось загрузить тексты промптов:', e))
  }, [])

  // T-44: провайдеры/модели/дефолт приходят с сервера, а не хардкодятся —
  // единый источник, из которого убран рассинхрон "deepseek" в UI vs
  // реального реестра на сервере (см. Why задачи T-44).
  useEffect(() => {
    fetch('/api/v1/providers')
      .then(r => r.json())
      .then((data: { providers: ProviderInfo[]; default_provider: string | null }) => {
        setProviders(data.providers)
        const def = data.default_provider ?? data.providers[0]?.name ?? ''
        setSelProvider(def)
        setModel(data.providers.find(p => p.name === def)?.default_model ?? '')
      })
      .catch(e => {
        console.error('Не удалось загрузить список AI-провайдеров:', e)
        setProvidersLoadError('Не удалось загрузить список провайдеров — проверьте, что сервер доступен')
      })
      .finally(() => setProvidersLoaded(true))
  }, [])

  function selectProvider(name: string) {
    setSelProvider(name)
    setModel(providers.find(p => p.name === name)?.default_model ?? '')
  }

  async function startAnalysis() {
    if (!selProvider) { setErrMsg('Нет доступного AI-провайдера'); return }
    if (promptId === 'custom' && !customSystem.trim()) { setErrMsg('Введите системный промпт'); return }

    setErrMsg('')
    setStep('running')
    setProgress({ done: 0, total: totalUnmarked, tokens: 0, errors: 0, lastVerdict: undefined, errorLog: [] })

    const abort = new AbortController()
    abortRef.current = abort

    try {
      const resp = await fetch(`/api/v1/runs/${runId}/analyze`, {
        method: 'POST',
        signal: abort.signal,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          provider: selProvider,
          model,
          prompt_id: promptId,
          custom_system: promptId === 'custom' ? customSystem : undefined,
          only_unmarked: true,
        }),
      })

      if (!resp.ok) {
        const err = await resp.json().catch(() => ({}))
        throw new Error(err?.message ?? `HTTP ${resp.status}`)
      }

      const reader = resp.body!.getReader()
      const decoder = new TextDecoder()
      let buf = ''
      let finished = false

      while (true) {
        const { done, value } = await reader.read()
        if (done) break

        buf += decoder.decode(value, { stream: true })
        const lines = buf.split('\n')
        buf = lines.pop() ?? ''

        for (const line of lines) {
          if (!line.startsWith('data: ')) continue
          try {
            const ev = JSON.parse(line.slice(6))

            if (ev.type === 'progress') {
              setProgress(p => ({
                ...p,
                done: ev.done,
                total: ev.total,
                tokens: ev.tokens_total,
                lastVerdict: ev.verdict,
              }))
              qc.invalidateQueries({ queryKey: ['findings', runId] })
            }

            if (ev.type === 'error') {
              setProgress(p => ({
                ...p,
                done: ev.done,
                total: ev.total,
                errors: p.errors + 1,
                errorLog: [...p.errorLog, {
                  finding_id: ev.finding_id,
                  uri: ev.uri ?? '',
                  start_line: ev.start_line ?? 0,
                  message: ev.message ?? 'неизвестная ошибка',
                }],
              }))
            }

            if (ev.type === 'done') {
              finished = true
              setProgress(p => ({
                ...p,
                done: ev.done,
                total: ev.total,
                tokens: ev.tokens_total,
                // T-37: цикл на сервере мог остановиться досрочно (circuit breaker
                // на подряд идущих ошибках провайдера) — сообщаем причину пользователю.
                stoppedReason: ev.stopped_reason,
                stopMessage: ev.message,
              }))
              qc.invalidateQueries({ queryKey: ['findings', runId] })
              qc.invalidateQueries({ queryKey: ['run', runId] })
              setStep('done')
            }
          } catch (e) {
            console.warn('Не удалось разобрать SSE-событие, строка пропущена:', line, e)
          }
        }
      }

      // Stream closed without a done event — show error
      if (!finished) {
        setStep('config')
        setErrMsg('Соединение прервано сервером. Проверьте логи uvicorn.')
      }
    } catch (e: any) {
      if (e?.name === 'AbortError') return
      setStep('config')
      setErrMsg(`Ошибка: ${e?.message ?? String(e)}`)
    }
  }

  function cancel() {
    abortRef.current?.abort()
    setStep('config')
  }

  // Close on Escape
  useEffect(() => {
    const h = (e: KeyboardEvent) => { if (e.key === 'Escape' && step !== 'running') onClose() }
    window.addEventListener('keydown', h)
    return () => window.removeEventListener('keydown', h)
  }, [step, onClose])

  const pct = progress.total > 0 ? Math.round((progress.done / progress.total) * 100) : 0

  const showPopover = step === 'config'
  const activePromptMeta = promptId === 'custom'
    ? { id: 'custom', label: 'Свой промпт' }
    : STANDARD_PROMPTS.find(p => p.id === promptId)

  return (
    <div className="modal-backdrop" onClick={e => { if (e.target === e.currentTarget && step !== 'running') onClose() }}>
      <div className="modal-shell">
      <div className="modal">
        <div className="modal-header">
          <span className="modal-title">
            <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" strokeWidth="2">
              <circle cx="12" cy="12" r="3"/><path d="M12 1v4M12 19v4M4.22 4.22l2.83 2.83M16.95 16.95l2.83 2.83M1 12h4M19 12h4M4.22 19.78l2.83-2.83M16.95 7.05l2.83-2.83"/>
            </svg>
            AI-анализ
          </span>
          {step !== 'running' && (
            <button className="modal-close" onClick={onClose}>
              <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M18 6L6 18M6 6l12 12"/>
              </svg>
            </button>
          )}
        </div>

        {/* ── CONFIG ── */}
        {step === 'config' && (
          <div className="modal-body">
            <div className="form-row">
              <div className="form-group">
                <label className="form-label">Провайдер</label>
                {providersLoaded && providers.length === 0 ? (
                  <div className="form-error">
                    {providersLoadError ?? (
                      'Нет доступного AI-провайдера — настройте SWB_AI_PROVIDERS или разрешите ' +
                      'удалённый провайдер (SWB_ALLOW_REMOTE_PROVIDERS)'
                    )}
                  </div>
                ) : (
                  <select
                    className="form-input"
                    value={selProvider}
                    onChange={e => selectProvider(e.target.value)}
                    autoFocus
                  >
                    {providers.map(p => (
                      <option key={p.name} value={p.name}>
                        {p.name}{p.local ? ' (локальный)' : ''}
                      </option>
                    ))}
                  </select>
                )}
              </div>
              <div className="form-group" style={{ maxWidth: 200 }}>
                <label className="form-label">Модель</label>
                <input
                  type="text"
                  className="form-input"
                  value={model}
                  onChange={e => setModel(e.target.value)}
                />
              </div>
            </div>

            <div className="form-section">
              <div className="form-label">Промпт</div>
              <div className="prompt-options">
                {STANDARD_PROMPTS.map(p => (
                  <label key={p.id} className={`prompt-option${promptId === p.id ? ' active' : ''}`}>
                    <input
                      type="radio"
                      name="prompt"
                      value={p.id}
                      checked={promptId === p.id}
                      onChange={() => setPromptId(p.id)}
                    />
                    <div>
                      <div className="prompt-name">{p.label}</div>
                      <div className="prompt-desc">{p.desc}</div>
                    </div>
                  </label>
                ))}
                <label className={`prompt-option${promptId === 'custom' ? ' active' : ''}`}>
                  <input
                    type="radio"
                    name="prompt"
                    value="custom"
                    checked={promptId === 'custom'}
                    onChange={() => setPromptId('custom')}
                  />
                  <div>
                    <div className="prompt-name">Свой промпт</div>
                    <div className="prompt-desc">Произвольный системный промпт</div>
                  </div>
                </label>
              </div>
            </div>

            {errMsg && <div className="form-error">{errMsg}</div>}

            <div className="modal-footer">
              <div className="analyze-meta">
                <span className="unmk-badge">{totalUnmarked}</span>
                <span className="muted">непроверенных находок</span>
              </div>
              <button className="btn btn-primary" onClick={startAnalysis}>
                Запустить анализ
              </button>
            </div>
          </div>
        )}

        {/* ── RUNNING ── */}
        {step === 'running' && (
          <div className="modal-body modal-running">
            <div className="run-status">
              <div className="run-spinner" />
              <span>Анализирую находки...</span>
            </div>

            <div className="progress-wrap">
              <div className="progress-bar">
                <div className="progress-fill" style={{ width: `${pct}%` }} />
              </div>
              <div className="progress-meta">
                <span className="progress-count">{progress.done} / {progress.total}</span>
                <span className="progress-tokens">
                  <svg viewBox="0 0 24 24" width="12" height="12" fill="none" stroke="currentColor" strokeWidth="2">
                    <circle cx="12" cy="12" r="9"/><path d="M9 9h.01M15 9h.01M9.5 14.5c1.5 1.5 3.5 1.5 5 0"/>
                  </svg>
                  {progress.tokens.toLocaleString()} токенов
                </span>
                {progress.errors > 0 && (
                  <span className="progress-errors">{progress.errors} ошибок</span>
                )}
              </div>
            </div>

            {progress.lastVerdict && (
              <div className="last-verdict">
                Последний:&nbsp;
                <span className={`vd-mini vd-${progress.lastVerdict}`}>
                  {progress.lastVerdict === 'true_positive' ? 'TP'
                    : progress.lastVerdict === 'false_positive' ? 'FP'
                    : 'Uncertain'}
                </span>
              </div>
            )}

            {progress.errorLog.length > 0 && (
              <ErrorLog entries={progress.errorLog} />
            )}

            <div className="modal-footer">
              <button className="btn btn-danger" onClick={cancel}>Отменить</button>
            </div>
          </div>
        )}

        {/* ── DONE ── */}
        {step === 'done' && (
          <div className="modal-body modal-done">
            <div className="done-icon">
              <svg viewBox="0 0 24 24" width="40" height="40" fill="none" stroke="var(--ok)" strokeWidth="2">
                <circle cx="12" cy="12" r="10"/><path d="M8 12l3 3 5-5" strokeLinecap="round" strokeLinejoin="round"/>
              </svg>
            </div>
            <div className="done-title">
              {progress.stoppedReason ? 'Анализ остановлен досрочно' : 'Анализ завершён'}
            </div>
            {progress.stoppedReason && (
              <div className="form-error" style={{ width: '100%' }}>
                {progress.stopMessage ?? (
                  progress.stoppedReason === 'circuit_breaker'
                    ? 'Слишком много ошибок провайдера подряд — анализ остановлен.'
                    : 'Соединение прервано — анализ остановлен.'
                )}
              </div>
            )}
            <div className="done-stats">
              <div className="done-stat">
                <span className="done-n">{progress.done}</span>
                <span className="muted">находок</span>
              </div>
              <div className="done-stat">
                <span className="done-n">{progress.tokens.toLocaleString()}</span>
                <span className="muted">токенов</span>
              </div>
              {progress.errors > 0 && (
                <div className="done-stat">
                  <span className="done-n" style={{ color: 'var(--crit)' }}>{progress.errors}</span>
                  <span className="muted">ошибок</span>
                </div>
              )}
            </div>

            {progress.errorLog.length > 0 && (
              <div style={{ width: '100%', textAlign: 'left' }}>
                <ErrorLog entries={progress.errorLog} defaultOpen />
              </div>
            )}

            <div className="modal-footer" style={{ justifyContent: 'center' }}>
              <button className="btn btn-primary" onClick={onClose}>Закрыть</button>
            </div>
          </div>
        )}
      </div>

      {/* ── PROMPT POPOVER ── */}
      {showPopover && activePromptMeta && (
        <div className="prompt-popover" key={activePromptMeta.id}>
          <div className="popover-header">
            <div className="popover-label">Системный промпт</div>
            <div className="popover-prompt-name">{activePromptMeta.label}</div>
          </div>
          {promptId === 'custom' ? (
            <textarea
              className="popover-textarea"
              placeholder="Введите системный промпт..."
              value={customSystem}
              onChange={e => setCustom(e.target.value)}
              autoFocus
            />
          ) : (
            <pre className="popover-body">{promptTexts[promptId] ?? ''}</pre>
          )}
        </div>
      )}

      </div>
    </div>
  )
}
