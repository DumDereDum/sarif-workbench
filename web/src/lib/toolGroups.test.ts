// Тесты T-3.5.1 для groupRunsByTool. Прогоняются через `npm --prefix web run
// test` (см. web/package.json + web/tsconfig.test.json): tsc компилирует
// только этот файл и toolGroups.ts в JS, дальше `node --test` запускает их
// нативным раннером node:test — без новых npm-зависимостей (vitest/jest в
// проекте нет, добавлять не нужно).
//
// @types/node в проекте не подключён (см. project-conventions: без новых
// зависимостей для этой задачи), поэтому у Node-модулей ниже нет объявлений
// типов — подавляем только эту диагностику, импортированные биндинги
// получают тип any, что не мешает остальной строгой проверке файла.
// @ts-expect-error -- no @types/node in this project, see comment above
import { test } from 'node:test'
// @ts-expect-error -- no @types/node in this project, see comment above
import assert from 'node:assert/strict'

import { groupRunsByTool, sortToolGroups, fmtToolName } from './toolGroups'
import type { RunSummary } from '../api/client'

function run(id: string, tool: string | null, uploadedAt: string | null, all?: number): RunSummary {
  return {
    id,
    commit: 'c-' + id,
    branch: 'main',
    tool: tool as unknown as string, // RunSummary.tool всё же может прийти null с сервера (models.py: nullable)
    tool_version: 'v1-' + id,
    scanned_at: null,
    uploaded_at: uploadedAt,
    counts: all === undefined ? {} : { all },
    counts_by_verdict: {},
  }
}

test('"Semgrep" и "semgrep " (регистр/пробел) схлопываются в одну группу с оригинальным написанием последнего рана', () => {
  const runs = [run('r-1', 'Semgrep', '2026-01-01T00:00:00'), run('r-2', 'semgrep ', '2026-01-02T00:00:00')]
  const groups = groupRunsByTool(runs)
  assert.equal(groups.length, 1)
  assert.equal(groups[0].key, 'semgrep')
  assert.equal(groups[0].id, 'r-2')
  assert.equal(groups[0].tool, 'semgrep ') // оригинальное написание, не нормализованный ключ
  assert.equal(groups[0].tool_version, 'v1-r-2')
})

test('разные инструменты остаются разными группами', () => {
  const runs = [run('r-1', 'Semgrep', '2026-01-01T00:00:00'), run('r-2', 'CodeQL', '2026-01-02T00:00:00')]
  const groups = groupRunsByTool(runs)
  assert.equal(groups.length, 2)
})

test('тай-брейк по id при равном uploaded_at', () => {
  const runs = [run('r-1', 'Semgrep', '2026-01-01T00:00:00'), run('r-2', 'Semgrep', '2026-01-01T00:00:00')]
  const groups = groupRunsByTool(runs)
  assert.equal(groups.length, 1)
  assert.equal(groups[0].id, 'r-2')
})

test('тай-брейк по id при равном uploaded_at не зависит от позиции в массиве (зеркало предыдущего теста)', () => {
  // Тот же сценарий, что и в предыдущем тесте, но r-2 (больший id) идёт
  // ПЕРВЫМ, а r-1 — последним. Победитель всё равно r-2: тай-брейк должен
  // определяться строго по большему id, а не по тому, кто последний в
  // массиве (реализация вида "при равенстве побеждает последний встреченный"
  // прошла бы предыдущий тест, но не пройдёт этот).
  const runs = [run('r-2', 'Semgrep', '2026-01-01T00:00:00'), run('r-1', 'Semgrep', '2026-01-01T00:00:00')]
  const groups = groupRunsByTool(runs)
  assert.equal(groups.length, 1)
  assert.equal(groups[0].id, 'r-2')
})

test('тай-брейк по id при невалидном (непарсящемся) uploaded_at у обоих ранов', () => {
  const runs = [run('r-1', 'Semgrep', 'not-a-date'), run('r-2', 'Semgrep', 'also-not-a-date')]
  const groups = groupRunsByTool(runs)
  assert.equal(groups.length, 1)
  // NaN !== NaN в JS: без нормализации это ломало тай-брейк, побеждал бы
  // первый встреченный в массиве, а не детерминированно больший id.
  assert.equal(groups[0].id, 'r-2')
})

test('тай-брейк по id, когда uploaded_at отсутствует (null) у обоих ранов', () => {
  const runs = [run('r-1', 'Semgrep', null), run('r-2', 'Semgrep', null)]
  const groups = groupRunsByTool(runs)
  assert.equal(groups.length, 1)
  assert.equal(groups[0].id, 'r-2')
})

test('результат не зависит от порядка входного массива', () => {
  const asc = [
    run('r-1', 'Semgrep', '2026-01-01T00:00:00'),
    run('r-2', 'Semgrep', '2026-01-03T00:00:00'),
    run('r-3', 'Semgrep', '2026-01-02T00:00:00'),
  ]
  const desc = [...asc].reverse()
  assert.equal(groupRunsByTool(asc)[0].id, 'r-2')
  assert.equal(groupRunsByTool(desc)[0].id, 'r-2')
})

test('пустой/null tool не роняет функцию и группируется отдельно от непустых значений', () => {
  const runs = [run('r-1', '', '2026-01-01T00:00:00'), run('r-2', null, '2026-01-02T00:00:00'), run('r-3', 'Semgrep', '2026-01-01T00:00:00')]
  const groups = groupRunsByTool(runs)
  assert.equal(groups.length, 2) // "" и null нормализуются в один и тот же ключ ''
  const emptyGroup = groups.find(g => g.key === '')
  assert.ok(emptyGroup)
  assert.equal(emptyGroup!.id, 'r-2')
})

// ---- T-3.5.3: sortToolGroups ----

test('sortToolGroups сортирует группы по counts.all по убыванию', () => {
  const runs = [
    run('r-1', 'CodeQL', '2026-01-01T00:00:00', 5),
    run('r-2', 'Semgrep', '2026-01-01T00:00:00', 20),
    run('r-3', 'Bandit', '2026-01-01T00:00:00', 12),
  ]
  const sorted = sortToolGroups(groupRunsByTool(runs))
  assert.deepEqual(sorted.map(g => g.tool), ['Semgrep', 'Bandit', 'CodeQL'])
})

test('sortToolGroups: тай-брейк по алфавиту нормализованного ключа при равном counts.all', () => {
  const runs = [
    run('r-1', 'Zeta', '2026-01-01T00:00:00', 10),
    run('r-2', 'Alpha', '2026-01-01T00:00:00', 10),
    run('r-3', 'Mid', '2026-01-01T00:00:00', 10),
  ]
  const sorted = sortToolGroups(groupRunsByTool(runs))
  assert.deepEqual(sorted.map(g => g.tool), ['Alpha', 'Mid', 'Zeta'])
})

test('sortToolGroups: тай-брейк использует нормализованный key, а не исходный tool (регистро-зависимый кейс)', () => {
  // По ASCII 'Z' (90) < 'a' (97), поэтому по СЫРЫМ строкам 'Zebra' < 'apple' —
  // если бы тай-брейк в toolGroups.ts сравнивал a.tool/b.tool вместо
  // a.key/b.key, порядок был бы ['Zebra', 'apple']. По нормализованным ключам
  // ('apple' < 'zebra') верный порядок — 'apple' раньше 'Zebra'. Тест ловит
  // регресс, если a.key/b.key заменят на a.tool/b.tool.
  const runs = [
    run('r-1', 'Zebra', '2026-01-01T00:00:00', 10),
    run('r-2', 'apple', '2026-01-01T00:00:00', 10),
  ]
  const sorted = sortToolGroups(groupRunsByTool(runs))
  assert.deepEqual(sorted.map(g => g.tool), ['apple', 'Zebra'])
})

test('sortToolGroups: отсутствующий counts.all считается 0, не роняет сортировку', () => {
  const runs = [
    run('r-1', 'HasCounts', '2026-01-01T00:00:00', 3),
    run('r-2', 'NoCounts', '2026-01-01T00:00:00'), // counts: {}
  ]
  const sorted = sortToolGroups(groupRunsByTool(runs))
  assert.deepEqual(sorted.map(g => g.tool), ['HasCounts', 'NoCounts'])
})

test('sortToolGroups не мутирует входной массив и возвращает новый', () => {
  const runs = [run('r-1', 'B', '2026-01-01T00:00:00', 1), run('r-2', 'A', '2026-01-01T00:00:00', 2)]
  const groups = groupRunsByTool(runs)
  const originalOrder = groups.map(g => g.tool)
  const sorted = sortToolGroups(groups)
  assert.notEqual(sorted, groups)
  assert.deepEqual(groups.map(g => g.tool), originalOrder) // исходный массив не тронут
  assert.deepEqual(sorted.map(g => g.tool), ['A', 'B'])
})

// ---- T-3.5.3: fmtToolName ----

test('fmtToolName: плейсхолдер "(unknown)" для пустого/null/только-пробельного tool, обычное имя — как есть', () => {
  assert.equal(fmtToolName(null), '(unknown)')
  assert.equal(fmtToolName(undefined), '(unknown)')
  assert.equal(fmtToolName(''), '(unknown)')
  assert.equal(fmtToolName('   '), '(unknown)')
  assert.equal(fmtToolName('\t\n'), '(unknown)')
  assert.equal(fmtToolName('Semgrep'), 'Semgrep')
  assert.equal(fmtToolName('CodeQL'), 'CodeQL')
})

test('fmtToolName: критерий "пусто" совпадает с критерием normalizeToolKey — не рассинхронизирован', () => {
  // normalizeToolKey (использует groupRunsByTool) и fmtToolName не экспортируют
  // общую реализацию напрямую, поэтому сверяем поведение через один и тот же
  // набор граничных значений: группа пуста (key === '') тогда и только тогда,
  // когда fmtToolName даёт плейсхолдер — иначе панель сравнения могла бы
  // показать группу-заглушку без плейсхолдера (или наоборот).
  const boundaryValues: Array<string | null | undefined> = [null, undefined, '', '   ', '\t\n', 'Semgrep', ' Semgrep ', 'a', '0']
  for (const tool of boundaryValues) {
    const [group] = groupRunsByTool([run('r-1', tool ?? null, '2026-01-01T00:00:00')])
    const isEmptyKey = group.key === ''
    const isPlaceholder = fmtToolName(tool) === '(unknown)'
    assert.equal(isPlaceholder, isEmptyKey, `рассинхронизация критерия "пусто" для tool=${JSON.stringify(tool)}`)
  }
})
