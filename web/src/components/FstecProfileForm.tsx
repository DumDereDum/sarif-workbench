import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { api, type FstecIndicator } from '../api/client'

// Показатели K, L и P описывают информационную систему, а не находку, и в
// отчёте анализатора их нет по природе: он видит исходный код, а не
// развёрнутый компонент. Методика (п. 8в, п. 11) берёт их из инвентаризации,
// поэтому заполняются вручную — один раз на проект.
//
// Варианты списков приходят с сервера (`GET /fstec/indicators`), а не заданы
// здесь: это нормативные значения из таблицы 1, и вторая копия рано или
// поздно разойдётся с методикой. Рядом, в lib/severity.ts, такая ручная копия
// уже ведётся — и там же стоит предупреждение, что синхронизация держится
// только на внимательности.
const FIELDS = [
  { key: 'component_type', symbol: 'K' },
  { key: 'vulnerable_share', symbol: 'L' },
  { key: 'perimeter_exposure', symbol: 'P' },
] as const

type FieldKey = typeof FIELDS[number]['key']

export function FstecProfileForm({ projectId }: { projectId: string }) {
  const qc = useQueryClient()

  const { data: meta } = useQuery({
    queryKey: ['fstec-indicators'],
    queryFn: api.fstecIndicators,
    staleTime: Infinity, // таблица методики не меняется в течение сессии
  })
  const { data: profile } = useQuery({
    queryKey: ['fstec-profile', projectId],
    queryFn: () => api.fstecProfile(projectId),
  })

  const save = useMutation({
    mutationFn: (patch: Partial<Record<FieldKey, string | null>>) =>
      api.setFstecProfile(projectId, patch),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['fstec-profile', projectId] })
      // Запись профиля пересчитывает уровни всех находок проекта (п. 19) —
      // открытые списки и сводки устарели.
      qc.invalidateQueries({ queryKey: ['runs'] })
      qc.invalidateQueries({ queryKey: ['findings'] })
      qc.invalidateQueries({ queryKey: ['project'] })
    },
  })

  if (!meta || !profile) return null

  const recomputed = save.data?.recomputed
  const assessed = recomputed?.assessed ?? 0

  return (
    <div className="panel" style={{ marginBottom: 16 }}>
      <div className="panel-h">
        <svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" strokeWidth="2">
          <path d="M3 21h18M5 21V7l7-4 7 4v14M9 21v-6h6v6" />
        </svg>
        Профиль информационной системы
      </div>

      <div className="fstec-profile">
        {FIELDS.map(({ key, symbol }) => {
          const ind: FstecIndicator | undefined = meta.indicators[symbol]
          if (!ind) return null
          const value = profile[key] ?? ''
          return (
            <label key={key} className="fstec-field">
              <span className="fstec-field-t">
                {ind.title} <i>({symbol})</i>
              </span>
              <select
                value={value}
                disabled={save.isPending}
                onChange={e => save.mutate({ [key]: e.target.value || null } as Partial<Record<FieldKey, string | null>>)}
              >
                <option value="">— не задано —</option>
                {ind.values.map(v => (
                  // Рядом с вариантом — его значение и произведение на весовой
                  // коэффициент: выбор виден не только словами, но и числом,
                  // которое попадёт в расчёт.
                  <option key={v.value} value={v.value}>
                    {v.label} · {v.score} × {ind.weight} = {v.weighted}
                  </option>
                ))}
              </select>
            </label>
          )
        })}
      </div>

      {!profile.complete ? (
        <div className="fstec-hint warn">
          Уровень критичности по методике ФСТЭК не рассчитывается: не заданы
          показатели {profile.missing.map(m => FIELDS.find(f => f.key === m)?.symbol ?? m).join(', ')}.
          Находки остаются в статусе «требует оценки» — подставлять значения по
          умолчанию нельзя, они попали бы в отчёт как факт.
        </div>
      ) : (
        <div className="fstec-hint">
          Профиль заполнен{profile.updated_by ? ` · ${profile.updated_by}` : ''}
          {profile.updated_at ? ` · ${profile.updated_at.replace('T', ' ').slice(0, 16)}` : ''}
          {recomputed ? ` · пересчитано находок: ${assessed}` : ''}
        </div>
      )}

      {save.isError && (
        <div className="form-error">Не удалось сохранить профиль</div>
      )}
    </div>
  )
}
