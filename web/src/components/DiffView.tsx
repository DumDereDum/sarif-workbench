import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { ApiError, api, type DiffCounts, type FindingItem } from '../api/client'
import { SEV, sevStyle, sevLabel } from '../lib/severity'
import { verdictStyle, verdictLabel } from '../lib/verdict'

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
}

function WarnIcon() {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.4">
      <path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/>
      <line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>
    </svg>
  )
}

function StarIcon() {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.4">
      <path d="M12 2l3 6 7 1-5 5 1 7-6-3-6 3 1-7-5-5 7-1z"/>
    </svg>
  )
}

export default function DiffView({ runId, baselineRunId }: DiffViewProps) {
  const [category, setCategory] = useState<DiffCategory>('new')

  const { data, isLoading, error } = useQuery({
    queryKey: ['diff', runId, baselineRunId],
    queryFn: () => api.diff(runId),
    enabled: !!runId && !!baselineRunId,
    retry: false,
  })

  if (!baselineRunId) {
    return (
      <div className="panel">
        <div className="empty">
          <StarIcon />
          <div>Бейзлайн не задан. Отметьте звёздочкой ран-эталон в истории прогонов, чтобы включить сравнение.</div>
        </div>
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
        <div className="empty">
          <WarnIcon />
          <div>{msg}</div>
        </div>
      </div>
    )
  }

  if (!data) return null

  const counts = data.counts as DiffCounts
  const items = data[category]

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
            onClick={() => setCategory(c.key)}
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
                <div className="empty">
                  <svg viewBox="0 0 64 64" fill="none" stroke="currentColor" strokeWidth="2.4">
                    <path d="M14 40c3-13 14-21 26-19" strokeLinecap="round"/>
                    <path d="M16 47c0-9 7-15 16-15 6 0 10 3 13 7"/>
                    <circle cx="33" cy="40" r="1.4" fill="currentColor"/>
                  </svg>
                  <div>{EMPTY_CATEGORY_MSG[category]}</div>
                </div>
              </td></tr>
            )}
            {items.map((f: FindingItem) => (
              <tr key={f.id} style={{ cursor: 'default' }}>
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
  )
}
