import type { FstecBlock } from '../api/client'
import { FSTEC_EXTRA, fstecStyle, fstecKey } from '../lib/fstec'

// Разложение расчёта по методике ФСТЭК — то место, где аудитор проверяет
// арифметику. Показывает не только итог, но и каждый показатель с его весом,
// произведение, метку источника оценки CVSS и значения, отброшенные правилом
// максимума пп. 15-17.
//
// Данные приходят готовыми из `GET /findings/{id}`: сервер считает разложение
// заново на каждое открытие карточки и не хранит его — это чистая функция от
// входов, и сохранённая копия разошлась бы с ними при первом пересчёте.

// Форма разложения задаётся сервером (`fstec.assess`). Типы здесь описывают
// ровно то, что он отдаёт; лишнего не выдумываем.
interface Term {
  symbol: string
  title: string
  weight: number
  value: string
  value_label: string
  score: number
  weighted: number
  candidates: { value: string; value_label: string; score: number }[]
}

interface Breakdown {
  formula: string
  methodology: string
  i_cvss: { value: number; source: string }
  i_infr: { value: number; formula: string; terms: Term[] }
  i_at: { value: number; formula: string; term: Term }
  i_imp: { value: number; formula: string; term: Term }
  v: number
}

const SOURCE_LABEL: Record<string, string> = {
  sarif_security_severity: 'из отчёта анализатора',
  manual_rule: 'проставлена для правила',
  manual_finding: 'проставлена для этой находки',
}

// Подписи показателей в перечне недостающих. Ключи приходят с сервера
// (`fstec.assess`), символы K/L/P/H — обозначения из таблицы 1 методики.
const MISSING_LABEL: Record<string, string> = {
  i_cvss: 'базовая оценка CVSS',
  K: 'тип компонента системы (K)',
  L: 'доля уязвимых компонентов (L)',
  P: 'доступность из интернета (P)',
  H: 'последствия эксплуатации (H)',
  E: 'сведения об эксплуатации (E)',
}

function TermRow({ t }: { t: Term }) {
  // Отброшенные правилом максимума значения показываются рядом с выбранным:
  // без них видно только победителя, и проверить выбор нельзя.
  const discarded = t.candidates.filter(c => c.value !== t.value)
  return (
    <div className="fb-term">
      <span className="fb-sym">{t.symbol}</span>
      <div className="fb-term-body">
        <div className="fb-term-v">{t.value_label}</div>
        <div className="fb-term-m">
          {t.score} × {t.weight} = <b>{t.weighted}</b>
        </div>
        {discarded.length > 0 && (
          <div className="fb-discarded">
            отброшено правилом максимума: {discarded
              .map(c => `${c.value_label} (${c.score})`)
              .join(', ')}
          </div>
        )}
      </div>
    </div>
  )
}

export function FstecBreakdown({ fstec }: { fstec: FstecBlock }) {
  const key = fstecKey(fstec)
  const label = fstec.level_label
    ?? FSTEC_EXTRA.find(e => e.key === fstec.status)?.label
    ?? '—'

  const b = fstec.breakdown as unknown as Breakdown | null

  return (
    <div className="dr-sec">
      <h3>Критичность по методике ФСТЭК</h3>

      <div className="fb-head">
        <span className="sev-tag" style={fstecStyle(key)}>{label}</span>
        {fstec.status === 'assessed' && (
          <>
            <span className="fb-v">V = {fstec.v}</span>
            {/* Рекомендуемый срок устранения — п. 21 методики */}
            <span className="fb-rem">устранить {fstec.remediation}</span>
          </>
        )}
      </div>

      {fstec.status === 'needs_assessment' && (
        <div className="fb-missing">
          Расчёт не выполнялся: не заданы {fstec.missing
            .map(m => MISSING_LABEL[m] ?? m)
            .join(', ')}.
          {' '}Показатели K, L и P задаются в профиле проекта, H — на странице
          «Оценка правил». Подставлять значения по умолчанию нельзя: они попали
          бы в отчёт как факт.
        </div>
      )}

      {fstec.status === 'not_applicable' && (
        <div className="fb-missing">
          Оценивать нечего: правило признано не относящимся к уязвимостям либо
          находка разобрана как ложное срабатывание.
        </div>
      )}

      {b && (
        <div className="fb">
          <div className="fb-formula">{b.formula}</div>

          <div className="fb-line">
            <span className="fb-name">I_cvss</span>
            <span className="fb-val">{b.i_cvss.value}</span>
            <span className="fb-note">
              {SOURCE_LABEL[b.i_cvss.source] ?? b.i_cvss.source}
            </span>
          </div>

          <div className="fb-line">
            <span className="fb-name">I_infr</span>
            <span className="fb-val">{b.i_infr.value}</span>
            <span className="fb-note">{b.i_infr.formula}</span>
          </div>
          <div className="fb-terms">
            {b.i_infr.terms.map(t => <TermRow key={t.symbol} t={t} />)}
          </div>

          <div className="fb-line">
            <span className="fb-name">I_at</span>
            <span className="fb-val">{b.i_at.value}</span>
            <span className="fb-note">{b.i_at.formula}</span>
          </div>
          <div className="fb-terms"><TermRow t={b.i_at.term} /></div>

          <div className="fb-line">
            <span className="fb-name">I_imp</span>
            <span className="fb-val">{b.i_imp.value}</span>
            <span className="fb-note">{b.i_imp.formula}</span>
          </div>
          <div className="fb-terms"><TermRow t={b.i_imp.term} /></div>

          <div className="fb-total">
            V = {b.i_cvss.value} × {b.i_infr.value} × ({b.i_at.value} + {b.i_imp.value})
            {' = '}<b>{b.v}</b>
          </div>
        </div>
      )}

      <div className="fb-meth">{fstec.methodology}</div>
    </div>
  )
}
