import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { api, type RuleImpactRow } from '../api/client'

// Очередь на разбор: правила анализаторов, которым ещё не задан показатель H
// (последствия эксплуатации, п. 17 методики).
//
// Показатель задаётся на правило, а не на находку, по двум причинам. Правило
// анализатора уже CWE и описывает один конкретный дефект: `DEREF_OF_NULL` —
// это разыменование NULL, тогда как CWE-119, под который попадают его соседи,
// покрывает всё от чтения за границей буфера до выполнения кода. И это тот же
// уровень, на котором живёт `security-severity`: он тоже константа правила,
// одна на все его находки.
//
// Автоматического источника у H нет — проверено на выгрузке БДУ (ФСТЭК
// проставляет последствие каждой уязвимости отдельно, и внутри одного CWE
// значения расходятся) и на каталоге MITRE (там перечислено всё, что
// когда-либо наблюдалось, и при правиле максимума больше половины CWE
// получили бы 0,5, перестав различать находки).

function fmtDate(s: string | null) {
  return s ? s.replace('T', ' ').slice(0, 16) : ''
}

function RuleForm({ row, onDone }: { row: RuleImpactRow; onDone: () => void }) {
  const qc = useQueryClient()
  const { data: meta } = useQuery({
    queryKey: ['fstec-indicators'],
    queryFn: api.fstecIndicators,
    staleTime: Infinity,
  })

  const [impacts, setImpacts] = useState<Set<string>>(new Set(row.impacts))
  const [na, setNa] = useState(row.not_applicable)
  const [iCvss, setICvss] = useState(row.i_cvss?.toString() ?? '')
  const [note, setNote] = useState(row.note ?? '')

  const save = useMutation({
    mutationFn: () =>
      api.setRuleImpact({
        tool: row.tool,
        rule_id: row.rule_id,
        impacts: na ? [] : [...impacts],
        not_applicable: na,
        i_cvss: iCvss.trim() === '' ? null : Number(iCvss),
        note: note.trim() || null,
      }),
    onSuccess: () => {
      // Запись пересчитывает находки правила во всех проектах (п. 19) —
      // открытые списки, сводки и карточки устарели.
      qc.invalidateQueries({ queryKey: ['rule-impacts'] })
      qc.invalidateQueries({ queryKey: ['findings'] })
      qc.invalidateQueries({ queryKey: ['run'] })
      qc.invalidateQueries({ queryKey: ['runs'] })
      qc.invalidateQueries({ queryKey: ['agg'] })
      onDone()
    },
  })

  const hValues = meta?.indicators?.H?.values ?? []
  // Правило максимума п. 17: из выбранных последствий в расчёт идёт
  // наибольшее. Показываем, какое именно, — иначе выбор нескольких значений
  // выглядит как сложение.
  const winner = hValues
    .filter(v => impacts.has(v.value))
    .reduce<{ label: string; score: number } | null>(
      (best, v) => (!best || v.score > best.score ? { label: v.label, score: v.score } : best),
      null,
    )

  // Решение «не уязвимость» убирает находки правила из оценки целиком и
  // предъявляется аудитору — без обоснования оно непредъявимо. Сервер это
  // тоже проверяет; здесь кнопка блокируется, чтобы не ловить 400.
  const canSave = na ? note.trim().length > 0 : impacts.size > 0 || iCvss.trim() !== ''

  return (
    <div className="ri-form">
      <label className="ri-na">
        <input type="checkbox" checked={na} onChange={e => setNa(e.target.checked)} />
        Правило не относится к уязвимостям — находки не оцениваются
      </label>

      {!na && (
        <>
          <div className="ri-block-t">
            Последствия эксплуатации (H) · из выбранного в расчёт идёт наибольшее
          </div>
          <div className="ri-impacts">
            {hValues.map(v => (
              <label key={v.value} className={impacts.has(v.value) ? 'on' : ''}>
                <input
                  type="checkbox"
                  checked={impacts.has(v.value)}
                  onChange={e => setImpacts(prev => {
                    const n = new Set(prev)
                    if (e.target.checked) n.add(v.value)
                    else n.delete(v.value)
                    return n
                  })}
                />
                <span className="ri-score">{v.score}</span>
                {v.label}
              </label>
            ))}
          </div>
          {winner && (
            <div className="ri-winner">
              В расчёт пойдёт: <b>{winner.label}</b> — {winner.score}
            </div>
          )}

          <div className="ri-block-t">
            Базовая оценка CVSS · только если анализатор её не дал
          </div>
          <input
            className="ri-input"
            type="number" min={0} max={10} step={0.1}
            placeholder="0-10; пусто — берётся из отчёта, где она есть"
            value={iCvss}
            onChange={e => setICvss(e.target.value)}
          />
        </>
      )}

      <div className="ri-block-t">
        Обоснование{na ? ' · обязательно' : ''} · попадёт в отчёт для аудитора
      </div>
      <textarea
        className="ri-input"
        rows={2}
        value={note}
        onChange={e => setNote(e.target.value)}
        placeholder="Почему выбраны эти последствия либо почему правило исключено"
      />

      <div className="ri-actions">
        <button className="btn" onClick={onDone}>Отмена</button>
        <button
          className="btn primary"
          disabled={!canSave || save.isPending}
          onClick={() => save.mutate()}
        >
          {save.isPending ? 'Сохраняю…' : `Сохранить и пересчитать (${row.findings})`}
        </button>
      </div>
      {save.isError && <div className="form-error">Не удалось сохранить оценку</div>}
    </div>
  )
}

export default function RuleImpacts() {
  const [onlyUnassessed, setOnlyUnassessed] = useState(true)
  const [open, setOpen] = useState<string | null>(null)

  const { data, isLoading } = useQuery({
    queryKey: ['rule-impacts', onlyUnassessed],
    queryFn: () => api.ruleImpacts({ unassessed: onlyUnassessed }),
  })

  return (
    <>
      <div className="page-h">
        <h1>Оценка правил</h1>
        <p>
          Последствия эксплуатации по методике ФСТЭК · задаются один раз на правило
          и действуют во всех проектах
        </p>
      </div>

      <div className="info-strip">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <path d="M12 2a10 10 0 100 20 10 10 0 000-20zM12 8v5M12 16h.01" />
        </svg>
        <div>
          Отсортировано по числу находок. Распределение неравномерное: несколько
          верхних правил обычно закрывают большую часть находок, поэтому разбирать
          выгоднее сверху вниз.
        </div>
      </div>

      <div className="panel">
        <div className="panel-h" style={{ justifyContent: 'space-between' }}>
          <span>
            {data ? `${data.unassessed} без оценки из ${data.total}` : 'Загрузка…'}
          </span>
          <label className="ri-toggle">
            <input
              type="checkbox"
              checked={onlyUnassessed}
              onChange={e => { setOnlyUnassessed(e.target.checked); setOpen(null) }}
            />
            только неоценённые
          </label>
        </div>

        <div className="tbl-wrap">
          <table className="tbl">
            <thead>
              <tr>
                <th style={{ width: 90 }}>Находок</th>
                <th style={{ width: 130 }}>Инструмент</th>
                <th>Правило</th>
                <th style={{ width: 170 }}>CWE</th>
                <th style={{ width: 150 }}>Оценка</th>
              </tr>
            </thead>
            <tbody>
              {isLoading && (
                <tr><td colSpan={5}><div className="empty">Загрузка…</div></td></tr>
              )}
              {data?.items.length === 0 && (
                <tr><td colSpan={5}>
                  <div className="empty">
                    <div>Все правила разобраны</div>
                  </div>
                </td></tr>
              )}
              {data?.items.map(row => {
                const id = `${row.tool} ${row.rule_id}`
                const isOpen = open === id
                return [
                  <tr
                    key={id}
                    className={isOpen ? 'open' : ''}
                    onClick={() => setOpen(isOpen ? null : id)}
                  >
                    <td><b>{row.findings}</b></td>
                    <td><span className="scope">{row.tool}</span></td>
                    <td>
                      <div className="rule-cell">
                        <span className="rid">{row.rule_id}</span>
                        {row.rule_name && row.rule_name !== row.rule_id && (
                          <span className="rnm">{row.rule_name}</span>
                        )}
                      </div>
                    </td>
                    <td>
                      {row.cwes.length
                        ? row.cwes.map(c => <span key={c} className="pill">{c}</span>)
                        : <span className="scope">—</span>}
                    </td>
                    <td>
                      {row.not_applicable ? (
                        <span className="vd-tag">не уязвимость</span>
                      ) : row.assessed ? (
                        <span className="vd-tag" title={row.note ?? ''}>
                          оценено{row.updated_at ? ` · ${fmtDate(row.updated_at)}` : ''}
                        </span>
                      ) : (
                        <span className="scope">не задано</span>
                      )}
                    </td>
                  </tr>,
                  isOpen ? (
                    <tr key={`${id}-form`} className="ri-form-row">
                      <td colSpan={5}>
                        <RuleForm row={row} onDone={() => setOpen(null)} />
                      </td>
                    </tr>
                  ) : null,
                ]
              })}
            </tbody>
          </table>
        </div>
      </div>
    </>
  )
}
