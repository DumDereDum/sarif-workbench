// Оформление уровней критичности по методике ФСТЭК от 30.06.2025.
//
// Здесь только представление: цвета и подписи двух групп, которых в методике
// нет. Порядок уровней и их названия приходят с сервера
// (`GET /fstec/indicators`) — это нормативные значения, и вторая копия рано
// или поздно разойдётся с документом. Именно на такую ручную копию жалуется
// комментарий в lib/severity.ts.
//
// Цвета совпадают с палитрой severity намеренно: обе шкалы говорят «насколько
// плохо», и второй набор оттенков для того же смысла только запутал бы. Шкалы
// различаются подписью ряда, а не цветом — они отвечают на разные вопросы:
// severity про «с чего начать разбор», уровень ФСТЭК про «за какой срок
// положено устранить».

/** Ключи, которых нет в таблице 2: находка без данных и находка, которую
 *  решили не оценивать. Идут после уровней — они не уровни. */
export const FSTEC_EXTRA = [
  { key: 'needs_assessment', label: 'Требует оценки' },
  { key: 'not_applicable', label: 'Не применимо' },
] as const

const COLORS: Record<string, { c: string; bg: string }> = {
  critical: { c: 'var(--crit)', bg: 'var(--crit-bg)' },
  high: { c: 'var(--high)', bg: 'var(--high-bg)' },
  medium: { c: 'var(--med)', bg: 'var(--med-bg)' },
  low: { c: 'var(--low)', bg: 'var(--low-bg)' },
  needs_assessment: { c: 'var(--muted)', bg: 'var(--note-bg)' },
  not_applicable: { c: 'var(--faint)', bg: 'var(--note-bg)' },
}

export function fstecColor(key: string | null | undefined) {
  return COLORS[key ?? ''] ?? COLORS.needs_assessment
}

export function fstecStyle(key: string | null | undefined) {
  const { c, bg } = fstecColor(key)
  return { color: c, background: bg }
}

/** Ключ группы находки: уровень у посчитанных, статус у остальных.
 *  Та же логика, что в SQL на сервере (`_fstec_order_expr`). */
export function fstecKey(f: { status: string; level: string | null }) {
  return f.status === 'assessed' && f.level ? f.level : f.status
}
