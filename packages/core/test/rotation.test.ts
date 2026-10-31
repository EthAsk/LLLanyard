import test from 'node:test';
import assert from 'node:assert/strict';
import { rotationStatus } from '../src/index.js';

const meta = (created: string, days: number) => ({ id: 'openai:default', provider: 'openai', label: 'default', createdAt: created, rotateAfterDays: days, last4: 'abcd' });
const now = new Date('2026-10-27T12:00:00Z');

test('rotation: ok / due-soon / overdue boundaries', () => {
  assert.equal(rotationStatus(meta('2026-10-01T00:00:00Z', 90), now).state, 'ok');
  const soon = rotationStatus(meta('2026-08-10T00:00:00Z', 90), now); // age 78d, due in 12d
  assert.equal(soon.state, 'due-soon');
  assert.equal(soon.dueInDays, 12);
  const late = rotationStatus(meta('2026-06-01T00:00:00Z', 90), now); // age 148d
  assert.equal(late.state, 'overdue');
  assert.ok(late.dueInDays < 0);
  assert.ok(late.rotateUrl?.startsWith('https://'));
});
