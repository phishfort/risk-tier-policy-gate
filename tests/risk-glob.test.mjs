import assert from 'node:assert/strict';
import test from 'node:test';

import { toRegex } from '../scripts/risk-glob.mjs';

test('question mark matches exactly one non-path character', () => {
  const matcher = toRegex('**/api-v?.js');
  assert.equal(matcher.test('src/api-v1.js'), true);
  assert.equal(matcher.test('api-va.js'), true);
  assert.equal(matcher.test('src/api-v.js'), false);
  assert.equal(matcher.test('src/api-v12.js'), false);
  assert.equal(matcher.test('src/api-v/1.js'), false);
});

test('regex metacharacters remain literal in glob patterns', () => {
  const matcher = toRegex('config/file[1]+(prod).json');
  assert.equal(matcher.test('config/file[1]+(prod).json'), true);
  assert.equal(matcher.test('config/file1prod.json'), false);
});
