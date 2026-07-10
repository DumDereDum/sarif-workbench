// SYNC: SEV_ORDER must be kept manually in sync with the single source of
// truth `contract/swb_contract/severity.py::SEV_ORDER` (T-34). Values are
// identical as of this writing; there is no codegen/build-step tying them
// together, so a change on the Python side must be mirrored here by hand.
export const SEV_ORDER = ['critical', 'high', 'medium', 'low', 'note'] as const
export type Severity = typeof SEV_ORDER[number]

export const SEV: Record<Severity, { label: string; c: string; bg: string }> = {
  critical: { label: 'Critical', c: 'var(--crit)',  bg: 'var(--crit-bg)' },
  high:     { label: 'High',     c: 'var(--high)',  bg: 'var(--high-bg)' },
  medium:   { label: 'Medium',   c: 'var(--med)',   bg: 'var(--med-bg)'  },
  low:      { label: 'Low',      c: 'var(--low)',   bg: 'var(--low-bg)'  },
  note:     { label: 'Note',     c: 'var(--note)',  bg: 'var(--note-bg)' },
}

export function sevStyle(s: string) {
  const info = SEV[s as Severity] ?? SEV.note
  return { color: info.c, background: info.bg }
}

export function sevLabel(s: string): string {
  return SEV[s as Severity]?.label ?? s
}
