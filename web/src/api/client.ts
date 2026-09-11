const BASE = '/api/v1'

// Ошибка API с сохранённым машиночитаемым кодом (`error` в теле ответа),
// когда UI должен различать причины 4xx (например `no_baseline` в diff-эндпоинте).
// `detail` (T-38) — весь разобранный объект `detail` ответа как есть, когда это
// словарь: для `version_conflict` (409 на PATCH .../verdict) в нём лежит
// актуальное состояние находки под ключом `finding`, чтобы UI не падал молча,
// а мог сразу показать пользователю, что изменилось (без лишнего round-trip'а).
export class ApiError extends Error {
  status: number
  code?: string
  detail?: Record<string, unknown>
  constructor(message: string, status: number, code?: string, detail?: Record<string, unknown>) {
    super(message)
    this.name = 'ApiError'
    this.status = status
    this.code = code
    this.detail = detail
  }
}

// FastAPI оборачивает `raise HTTPException(status, detail)` как `{"detail": detail}`.
// В этом проекте `detail` почти всегда — словарь `{"error": "...", "message": "..."}`
// (см. server/swb_server/routers/*.py), но может быть и голой строкой (обычный
// `HTTPException(404, "not found")`) или списком (стандартные pydantic-ошибки валидации
// FastAPI) — в этих случаях machine-readable кода нет, используем только текст/статус.
function parseErrorBody(body: unknown, fallback: string): { message: string; code?: string; detail?: Record<string, unknown> } {
  if (body && typeof body === 'object' && 'detail' in body) {
    const detail = (body as { detail: unknown }).detail
    if (detail && typeof detail === 'object' && !Array.isArray(detail)) {
      const d = detail as Record<string, unknown>
      return {
        message: typeof d.message === 'string' ? d.message : fallback,
        code: typeof d.error === 'string' ? d.error : undefined,
        detail: d,
      }
    }
    if (typeof detail === 'string') return { message: detail }
  }
  return { message: fallback }
}

async function req<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(BASE + path, init)
  if (!res.ok) {
    const body = await res.json().catch(() => null)
    const { message, code, detail } = parseErrorBody(body, res.statusText)
    throw new ApiError(message, res.status, code, detail)
  }
  return res.json() as Promise<T>
}

// ---- Types ----

export interface Counts {
  critical: number; high: number; medium: number; low: number; note: number; all: number
}

export interface CountsByVerdict {
  true_positive: number; false_positive: number; uncertain: number; unmarked: number
}

export interface RunSummary {
  id: string; commit: string; branch: string; tool: string; tool_version?: string
  scanned_at: string | null; uploaded_at: string | null
  counts: Partial<Counts>; counts_by_verdict: Partial<CountsByVerdict>
  counts_by_fstec?: Record<string, number>
}

export interface Project {
  id: string; name: string; repo: string; team: string | null
  baseline_run_id: string | null
  last_run: RunSummary | null
  counts: Partial<Counts>; counts_by_verdict: Partial<CountsByVerdict>
  counts_by_fstec?: Record<string, number>
}

export interface Run {
  id: string; project_id: string; project_name: string | null; project_repo: string | null
  commit: string; branch: string; tool: string | null; tool_version: string | null
  scanned_at: string | null; uploaded_at: string | null
  counts: Partial<Counts>; counts_by_verdict: Partial<CountsByVerdict>
  counts_by_fstec?: Record<string, number>
  baseline_run_id: string | null
}

// Блок расчёта по методике ФСТЭК. `status`: assessed | needs_assessment |
// not_applicable. У непосчитанной находки v/level/remediation равны null, а
// `missing` перечисляет незаданные показатели — пустая оценка не должна
// выглядеть как «Низкий».
export interface FstecBlock {
  status: string
  v: number | null
  level: string | null
  level_label: string | null
  remediation: string | null
  missing: string[]
  methodology: string
  breakdown?: Record<string, unknown> | null
}

export interface FindingItem {
  id: string; swb_id: string; occurrence: number
  severity: string; rule_id: string; rule_name: string; cwe: string | null
  security_severity: number | null; fstec: FstecBlock
  uri: string; start_line: number; scope: string | null; message: string
  verdict: string; verdict_source: string | null; lang: string | null
  fingerprint_algo?: string | null; fingerprint_level?: string | null
}

// Методика ФСТЭК от 30.06.2025. Варианты показателей и подписи уровней
// приходят с сервера (`GET /fstec/indicators`), а не переписываются здесь:
// это нормативные значения, и расхождение копий меняет уровень критичности
// в отчёте для регулятора. Ровно та ошибка, от которой предостерегает
// комментарий в lib/severity.ts, где такая копия ведётся вручную.
export interface FstecIndicatorValue {
  value: string; label: string; score: number; weighted: number
}
export interface FstecIndicator {
  symbol: string; title: string; weight: number; values: FstecIndicatorValue[]
}
export interface FstecLevel {
  key: string; label: string; remediation: string
  min_value: number | null; min_inclusive: boolean
}
export interface FstecIndicators {
  methodology: string; formula: string
  indicators: Record<string, FstecIndicator>
  levels: FstecLevel[]
  // Значение E, с которым живёт находка, пока сведений об эксплуатации
  // никто не проставил. Не пропуск, а строка таблицы 1 — форма показывает
  // его наравне с заданными вручную.
  exploitation_default: { value: string; label: string; reason: string }
}

// Показатель E на конкретной находке. `set_by_human: false` — умолчание;
// выдавать его за решение специалиста нельзя, отсюда отдельный признак.
export interface ExploitationBlock {
  value: string
  label: string
  score: number
  set_by_human: boolean
  ref: string | null
  by: string | null
  at: string | null
}

export interface FstecProfile {
  component_type: string | null
  vulnerable_share: string | null
  perimeter_exposure: string | null
  missing: string[]
  complete: boolean
  updated_by: string | null
  updated_at: string | null
}

// Оценка правила: показатель H и, когда анализатор не дал security-severity,
// оценка CVSS. Хранится глобально, не на проект — последствие эксплуатации
// не зависит от репозитория, в котором находка нашлась.
export interface RuleImpactRow {
  tool: string
  rule_id: string
  rule_name: string | null
  cwes: string[]
  findings: number
  impacts: string[]
  not_applicable: boolean
  i_cvss: number | null
  cvss_vector: string | null
  note: string | null
  updated_by: string | null
  updated_at: string | null
  assessed: boolean
}

export interface RuleImpactPage {
  total: number
  unassessed: number
  items: RuleImpactRow[]
}

export interface RuleImpactPatch {
  tool: string
  rule_id: string
  impacts?: string[]
  not_applicable?: boolean
  i_cvss?: number | null
  cvss_vector?: string | null
  note?: string | null
  updated_by?: string | null
}

export interface FindingsPage {
  total: number; page: number; page_size: number; items: FindingItem[]
}

export interface Snippet {
  start_line: number; end_line: number | null; lines: string[]; hot_line: number
}

// T-39 (ADR 0001 §8): multi-location payload — not identity, purely display.
export interface LocationRegion {
  start_line: number; end_line: number | null; start_column: number | null
}
export interface ExtraLocation { uri: string; region: LocationRegion }
export interface RelatedLocation { uri: string; region: LocationRegion; message: string | null }
export interface CodeFlowStep { uri: string; line: number | null; message: string | null }
export interface ThreadFlow { steps: CodeFlowStep[] }
export interface CodeFlow { thread_flows: ThreadFlow[] }

export interface VerdictObj {
  verdict: string; source: string | null; rationale: string | null
  provider: string | null; needs_reconfirm: boolean
  version: number | null // T-38: оптимистическая блокировка — вернуть в PATCH .../verdict как есть
  history: Array<{ verdict: string; source: string | null; at: string }>
}

export interface FindingDetail extends FindingItem {
  rule_description: string | null; help_uri: string | null
  exploitation: ExploitationBlock
  end_line: number | null
  snippet: Snippet | null
  // T-39: always arrays (possibly empty), server never sends null for these.
  code_flow: CodeFlow[]
  extra_locations: ExtraLocation[]
  related_locations: RelatedLocation[]
  git: { blob_sha?: string; blame_commit?: string; last_changed?: string } | null
  verdict: string; // overridden by `verdict` object below
  verdictObj: VerdictObj
}

export interface AggGroup { key: string; label: string; count: number }
export interface AggResponse { by: string; groups: AggGroup[] }

export interface DiffCounts { new: number; closed: number; unchanged: number }

export interface DiffResponse {
  run_id: string; baseline_run_id: string
  new: FindingItem[]; closed: FindingItem[]; unchanged: FindingItem[]
  counts: DiffCounts
}

// ---- API calls ----

export const api = {
  async deleteRun(runId: string): Promise<void> {
    const response = await fetch(`/api/v1/runs/${runId}`, {
      method: 'DELETE',
    })
    
    if (!response.ok) {
      const error = await response.json().catch(() => ({ message: 'Failed to delete run' }))
      throw new Error(error.message || `HTTP ${response.status}: Failed to delete run`)
    }
  },

  async deleteProject(projectId: string): Promise<void> {
    const response = await fetch(`/api/v1/projects/${projectId}`, {
      method: 'DELETE',
    })
    
    if (!response.ok) {
      const error = await response.json().catch(() => ({ message: 'Failed to delete project' }))
      throw new Error(error.detail || error.message || 'Failed to delete project')
    }
  },

  projects: (): Promise<{ projects: Project[] }> =>
    req('/projects'),

  projectRuns: (projectId: string): Promise<{ project: Pick<Project, 'id'|'name'|'repo'|'team'|'baseline_run_id'>; runs: RunSummary[] }> =>
    req(`/projects/${projectId}/runs`),

  setBaseline: (projectId: string, baselineRunId: string | null): Promise<unknown> =>
    req(`/projects/${projectId}/baseline`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ baseline_run_id: baselineRunId }),
    }),

  run: (runId: string): Promise<Run> =>
    req(`/runs/${runId}`),

  findings: (runId: string, params: Record<string, string>): Promise<FindingsPage> => {
    const qs = new URLSearchParams(params).toString()
    return req(`/runs/${runId}/findings${qs ? '?' + qs : ''}`)
  },

  aggregations: (runId: string, by: string): Promise<AggResponse> =>
    req(`/runs/${runId}/aggregations?by=${by}`),

  diff: (runId: string, baselineRunId?: string): Promise<DiffResponse> => {
    const qs = baselineRunId ? `?baseline=${encodeURIComponent(baselineRunId)}` : ''
    return req(`/runs/${runId}/diff${qs}`)
  },

  finding: (fid: string): Promise<unknown> =>
    req(`/findings/${fid}`),

  // version (T-38) — значение VerdictObj.version, прочитанное последним GET
  // /findings/{id}; сервер сравнивает его с текущей версией identity и
  // отвечает 409 version_conflict, если находка успела измениться под клиентом.
  setVerdict: (fid: string, verdict: string, rationale: string, version: number): Promise<unknown> =>
    req(`/findings/${fid}/verdict`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ verdict, rationale, version }),
    }),

  // value: null возвращает находку к умолчанию. Для остальных значений
  // сервер требует ссылку на источник и отвечает 400 без неё.
  setExploitation: (
    fid: string,
    value: string | null,
    ref: string,
  ): Promise<{ exploitation: ExploitationBlock; fstec: FstecBlock }> =>
    req(`/findings/${fid}/exploitation`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ value, ref }),
    }),

  resetVerdicts: (runId: string): Promise<{ reset: number }> =>
    req(`/runs/${runId}/reset`, { method: 'POST' }),

  fstecIndicators: (): Promise<FstecIndicators> => req('/fstec/indicators'),

  ruleImpacts: (params: { unassessed?: boolean; tool?: string } = {}): Promise<RuleImpactPage> => {
    const qs = new URLSearchParams()
    if (params.unassessed) qs.set('unassessed', 'true')
    if (params.tool) qs.set('tool', params.tool)
    const q = qs.toString()
    return req(`/fstec/rule-impacts${q ? `?${q}` : ''}`)
  },

  // Ключ (tool, rule_id) едет в теле: идентификаторы правил содержат слэши,
  // названия инструментов — пробелы, и путь пришлось бы кодировать.
  setRuleImpact: (patch: RuleImpactPatch): Promise<{ saved: number; recomputed: Record<string, number> }> =>
    req('/fstec/rule-impacts', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(patch),
    }),

  fstecProfile: (projectId: string): Promise<FstecProfile> =>
    req(`/projects/${projectId}/fstec-profile`),

  setFstecProfile: (
    projectId: string,
    patch: Partial<Record<'component_type' | 'vulnerable_share' | 'perimeter_exposure', string | null>>,
  ): Promise<FstecProfile & { recomputed: Record<string, number> }> =>
    req(`/projects/${projectId}/fstec-profile`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(patch),
    }),
}

export function normalizeDetail(raw: Record<string, unknown>): FindingDetail {
  const verdictObj = raw.verdict as VerdictObj
  return {
    ...(raw as unknown as FindingDetail),
    verdictObj,
    verdict: verdictObj.verdict,
  }
}
