import type { RunSummary } from '../api/client'

// T-3.5.1: список ранов проекта плоский и хронологический; чтобы сравнивать
// инструменты (T-3.5.2/T-3.5.3), сводим его к одной «текущей» строке на
// каждый встречающийся Run.tool. Группировка не запрашивает API заново —
// работает над уже загруженным `data.runs`.

export interface ToolGroup extends RunSummary {
  /** нормализованный ключ группы (`tool.trim().toLowerCase()`), не для показа в UI */
  key: string
}

function normalizeToolKey(tool: string | null | undefined): string {
  return (tool ?? '').trim().toLowerCase()
}

// `Date.parse` невалидной строки даёт `NaN`, а `NaN !== NaN` истинно в JS —
// без нормализации это ломает тай-брейк (см. review T-3.5.1 п.2): считаем
// невалидную/отсутствующую дату эквивалентной "нет даты", чтобы обе стороны
// сравнения увиделись равными и сравнение упало на тай-брейк по `id`.
function parseUploadedAt(uploadedAt: string | null): number {
  if (!uploadedAt) return -Infinity
  const t = Date.parse(uploadedAt)
  return Number.isNaN(t) ? -Infinity : t
}

// Выбирает "более актуальный" ран для группы: больший uploaded_at, при
// равенстве (или отсутствии/невалидности даты у обоих) — больший id, чтобы
// результат был детерминированным независимо от порядка входного массива.
function isNewer(candidate: RunSummary, current: RunSummary): boolean {
  const ct = parseUploadedAt(candidate.uploaded_at)
  const cur = parseUploadedAt(current.uploaded_at)
  if (ct !== cur) return ct > cur
  return candidate.id > current.id
}

/**
 * Группирует раны проекта по инструменту (`tool`, нормализованный по
 * `trim().toLowerCase()`), оставляя на группу один — самый актуальный — ран.
 * Оригинальное написание `tool`/`tool_version` берётся из выбранного рана,
 * не из нормализованного ключа.
 */
export function groupRunsByTool(runs: RunSummary[]): ToolGroup[] {
  const byKey = new Map<string, RunSummary>()
  for (const run of runs) {
    const key = normalizeToolKey(run.tool)
    const current = byKey.get(key)
    if (!current || isNewer(run, current)) {
      byKey.set(key, run)
    }
  }
  return Array.from(byKey.entries()).map(([key, run]) => ({ ...run, key }))
}
