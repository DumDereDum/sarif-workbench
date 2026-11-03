// @ts-expect-error -- no @types/node in this project, see toolGroups.test.ts.
import { test } from 'node:test'
// @ts-expect-error -- no @types/node in this project, see toolGroups.test.ts.
import assert from 'node:assert/strict'

import { toggleBaselineSelection } from './baseline'

test('clicking a run with no current baseline assigns that run', () => {
  assert.equal(toggleBaselineSelection(null, 'run-1'), 'run-1')
})

test('clicking the current baseline clears it', () => {
  assert.equal(toggleBaselineSelection('run-1', 'run-1'), null)
})

test('clicking another run replaces the current baseline', () => {
  assert.equal(toggleBaselineSelection('run-1', 'run-2'), 'run-2')
})
