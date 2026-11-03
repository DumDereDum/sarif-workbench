import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { ApiError, api, type DiffCounts, type FindingItem } from '../api/client'
import { SEV, sevStyle, sevLabel } from '../lib/severity'
import { verdictStyle, verdictLabel } from '../lib/verdict'
import StatusMessage from './StatusMessage'

const DIFF_CATEGORIES = [
  { key: 'new' as const,       label: 'Новые',          color: 'var(--new)',  bg: 'var(--new-bg)' },
  { key: 'closed' as const,    label: 'Закрытые',       color: 'var(--ok)',   bg: 'var(--ok-bg)' },
  { key: 'unchanged' as const, label: 'Без изменений',  color: 'var(--unmk)', bg: 'var(--unmk-bg)' },
]

type DiffCategory = typeof DIFF_CATEGORIES[number]['key']

const EMPTY_CATEGORY_MSG: Record<DiffCategory, string> = {
  new: 'Новых находок нет — по сравнению с бейзлайном ничего не добавилось',
  closed: 'Закрытых находок нет — по сравнению с бейзлайном ничего не исчезло',
  unchanged: 'Нет находок, совпадающих с бейзлайном',
}

interface DiffViewProps {
  runId: string
  baselineRunId: string | null
  onOpenFinding: (findingId: string, owningRunId: string) => void
}

export default function DiffView({ runId, baselineRunId, onOpenFinding }: DiffViewProps) {
  const [category, setCategory] = useState<DiffCategory>('new')
  const [page, setPage] = useState(1)

  const { data, isLoading, isFetching, error } = useQuery({
    queryKey: ['diff', runId, baselineRunId, category, page],
    queryFn: () => api.diff(runId, baselineRunId ?? undefined, { category, page: String(page), page_size: '100' }),
    enabled: !!runId && !!baselineRunId,
    retry: false,
  })

  if (!baselineRunId) {
    return (
      <div className="panel">
        <StatusMessage tone="info" title="Бейзлайн не задан">
          Отметьте звёздочкой ран-эталон в истории прогонов, чтобы включить сравнение.
        </StatusMessage>
      </div>
    )
  }

  if (isLoading) {
    return (
      <div className="panel">
        <div className="sev-summary" style={{ padding: 14 }}>
          <div className="skel" style={{ width: 92, height: 30 }} />
          <div className="skel" style={{ width: 100, height: 30 }} />
          <div className="skel" style={{ width: 132, height: 30 }} />
        </div>
        {Array.from({ length: 5 }).map((_, i) => (
          <div key={i} className="sk-row">
            <div className="skel" style={{ width: 70, height: 18 }} />
            <div className="skel" style={{ flex: 1, height: 12 }} />
          </div>
        ))}
      </div>
    )
  }

  if (error) {
    const apiErr = error instanceof ApiError ? error : null
    let msg = apiErr?.message || 'Не удалось загрузить сравнение с бейзлайном'
    if (apiErr?.code === 'no_baseline') {
      msg = 'Бейзлайн не задан. Отметьте звёздочкой ран-эталон в истории прогонов.'
    } else if (apiErr?.code === 'baseline_project_mismatch') {
      msg = 'Бейзлайн относится к другому проекту — сравнение невозможно.'
    } else if (apiErr?.code === 'not_found') {
      msg = 'Прогон или бейзлайн не найдены.'
    }
    return (
      <div className="panel">
        <StatusMessage tone="error" title="Не удалось загрузить сравнение">{msg}</StatusMessage>
      </div>
    )
  }

  if (!data) return null

  const counts = data.counts as DiffCounts
  const items = data[category]
  const total = data.total ?? counts[category]
  const pageSize = data.page_size ?? 100
  const totalPages = Math.max(1, Math.ceil(total / pageSize))
  const firstItem = total === 0 ? 0 : (page - 1) * pageSize + 1
  const lastItem = Math.min(page * pageSize, total)

  return (
    <div className="panel">
      <div className="panel-h">
        <svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" strokeWidth="2">
          <path d="M17 3l4 4-4 4M21 7H9M7 21l-4-4 4-4M3 17h12"/>
        </svg>
        Сравнение с бейзлайном
      </div>
      <div className="sev-summary" style={{ padding: '14px' }}>
        {DIFF_CATEGORIES.map(c => (
          <button
            key={c.key}
            className={`sev-chip${category === c.key ? ' active' : ''}`}
            style={{ color: c.color, background: c.bg }}
            onClick={() => { setCategory(c.key); setPage(1) }}
          >
            <span className="n">{counts[c.key] ?? 0}</span> {c.label}
          </button>
        ))}
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
            {items.length === 0 && (
              <tr><td colSpan={6}>
                <StatusMessage tone="empty" title={EMPTY_CATEGORY_MSG[category]} />
              </td></tr>
            )}
            {items.map((f: FindingItem) => (
              <tr
                key={f.id}
                className="interactive-row"
                tabIndex={0}
                onClick={() => onOpenFinding(f.id, category === 'closed' ? data.baseline_run_id : runId)}
                onKeyDown={e => {
                  if (e.key === 'Enter' || e.key === ' ') {
                    e.preventDefault()
                    onOpenFinding(f.id, category === 'closed' ? data.baseline_run_id : runId)
                  }
                }}
              >
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
      {totalPages > 1 && (
        <div className="pagination" aria-label="Страницы сравнения">
          <span className="muted">Показано {firstItem}–{lastItem} из {total}</span>
          <div className="pagination-actions">
            <button className="btn" onClick={() => setPage(p => Math.max(1, p - 1))} disabled={page <= 1 || isFetching}>
              Назад
            </button>
            <span className="muted">Страница {page} из {totalPages}</span>
            <button className="btn" onClick={() => setPage(p => Math.min(totalPages, p + 1))} disabled={page >= totalPages || isFetching}>
              Далее
            </button>
          </div>
        </div>
      )}
    </div>
  )
}
