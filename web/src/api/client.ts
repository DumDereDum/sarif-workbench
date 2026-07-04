const BASE = '/api/v1'

// Ошибка API с сохранённым машиночитаемым кодом (`error` в теле ответа),
// когда UI должен различать причины 4xx (например `no_baseline` в diff-эндпоинте).
export class ApiError extends Error {
  status: number
  code?: string
  constructor(message: string, status: number, code?: string) {
    super(message)
    this.name = 'ApiError'
    this.status = status
    this.code = code
  }
}

// FastAPI оборачивает `raise HTTPException(status, detail)` как `{"detail": detail}`.
// В этом проекте `detail` почти всегда — словарь `{"error": "...", "message": "..."}`
// (см. server/swb_server/routers/*.py), но может быть и голой строкой (обычный
// `HTTPException(404, "not found")`) или списком (стандартные pydantic-ошибки валидации
// FastAPI) — в этих случаях machine-readable кода нет, используем только текст/статус.
function parseErrorBody(body: unknown, fallback: string): { message: string; code?: string } {
  if (body && typeof body === 'object' && 'detail' in body) {
    const detail = (body as { detail: unknown }).detail
    if (detail && typeof detail === 'object' && !Array.isArray(detail)) {
      const d = detail as Record<string, unknown>
      return {
        message: typeof d.message === 'string' ? d.message : fallback,
        code: typeof d.error === 'string' ? d.error : undefined,
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
    const { message, code } = parseErrorBody(body, res.statusText)
    throw new ApiError(message, res.status, code)
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
}

export interface Project {
  id: string; name: string; repo: string; team: string | null
  baseline_run_id: string | null
  last_run: RunSummary | null
  counts: Partial<Counts>; counts_by_verdict: Partial<CountsByVerdict>
}

export interface Run {
  id: string; project_id: string; project_name: string | null; project_repo: string | null
  commit: string; branch: string; tool: string | null; tool_version: string | null
  scanned_at: string | null; uploaded_at: string | null
  counts: Partial<Counts>; counts_by_verdict: Partial<CountsByVerdict>
  baseline_run_id: string | null
}

export interface FindingItem {
  id: string; swb_id: string; occurrence: number
  severity: string; rule_id: string; rule_name: string; cwe: string | null
  uri: string; start_line: number; scope: string | null; message: string
  verdict: string; verdict_source: string | null; lang: string | null
  fingerprint_algo?: string | null; fingerprint_level?: string | null
}

export interface FindingsPage {
  total: number; page: number; page_size: number; items: FindingItem[]
}

export interface Snippet {
  start_line: number; end_line: number | null; lines: string[]; hot_line: number
}

export interface VerdictObj {
  verdict: string; source: string | null; rationale: string | null
  provider: string | null; needs_reconfirm: boolean
  history: Array<{ verdict: string; source: string | null; at: string }>
}

export interface FindingDetail extends FindingItem {
  rule_description: string | null; help_uri: string | null
  end_line: number | null
  snippet: Snippet | null; code_flow: unknown | null
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

  setVerdict: (fid: string, verdict: string, rationale: string): Promise<unknown> =>
    req(`/findings/${fid}/verdict`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ verdict, rationale }),
    }),

  resetVerdicts: (runId: string): Promise<{ reset: number }> =>
    req(`/runs/${runId}/reset`, { method: 'POST' }),
}

export function normalizeDetail(raw: Record<string, unknown>): FindingDetail {
  const verdictObj = raw.verdict as VerdictObj
  return {
    ...(raw as unknown as FindingDetail),
    verdictObj,
    verdict: verdictObj.verdict,
  }
}
