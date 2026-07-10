// SYNC: VD_ORDER must be kept manually in sync with the single source of
// truth `contract/swb_contract/verdict.py::VERDICT_ORDER` (T-34). Values are
// identical as of this writing; there is no codegen/build-step tying them
// together, so a change on the Python side must be mirrored here by hand.
export const VD_ORDER = ['true_positive', 'false_positive', 'uncertain', 'unmarked'] as const
export type Verdict = typeof VD_ORDER[number]

export const VERDICT: Record<Verdict, { label: string; short: string; c: string; bg: string }> = {
  true_positive:  { label: 'True Positive',  short: 'TP', c: 'var(--tp)',   bg: 'var(--tp-bg)'   },
  false_positive: { label: 'False Positive', short: 'FP', c: 'var(--fp)',   bg: 'var(--fp-bg)'   },
  uncertain:      { label: 'Не уверен',      short: '?',  c: 'var(--unc)',  bg: 'var(--unc-bg)'  },
  unmarked:       { label: 'Не размечено',   short: '—',  c: 'var(--unmk)', bg: 'var(--unmk-bg)' },
}

export const SRC_LABEL: Record<string, string> = {
  llm:      'AI-модель',
  human:    'инженер',
  imported: 'перенесён с прогона',
}

export function verdictStyle(v: string) {
  const info = VERDICT[v as Verdict] ?? VERDICT.unmarked
  return { color: info.c, background: info.bg }
}

export function verdictLabel(v: string): string {
  return VERDICT[v as Verdict]?.label ?? v
}
