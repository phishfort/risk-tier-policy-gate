import assert from 'node:assert/strict';
import test from 'node:test';

import {
  approvalAction,
  effectiveApprovals,
  isApprovalDeltaLowRisk,
  parseFilteredNumstat,
  pathSetFromNul,
  shouldDismissApproval,
} from '../scripts/risk-transition.mjs';

import rules from '../config/risk-rules.json' with { type: 'json' };

test('HIGH always reconciles active approvals against current HEAD', () => {
  assert.equal(
    approvalAction({ previousTier: 'high', fullTier: 'high' }),
    'reconcile-high-approvals',
  );
  assert.equal(
    approvalAction({ previousTier: 'low', fullTier: 'high' }),
    'reconcile-high-approvals',
  );
});

test('HIGH -> LOW approves only because the full PR is now low risk', () => {
  assert.equal(
    approvalAction({ previousTier: 'high', fullTier: 'low' }),
    'ensure-low-approval',
  );
});

test('LOW always verifies that an active bot approval exists', () => {
  assert.equal(
    approvalAction({ previousTier: 'low', fullTier: 'low' }),
    'ensure-low-approval',
  );
});

test('approval deltas are preserved only when deterministically low and below size limits', () => {
  assert.equal(
    isApprovalDeltaLowRisk({
      files: ['README.md', 'tests/widget.test.js'],
      insertions: 20,
      rules,
    }),
    true,
  );
  assert.equal(
    isApprovalDeltaLowRisk({ files: ['src/widget.js'], insertions: 2, rules }),
    false,
  );
  assert.equal(
    isApprovalDeltaLowRisk({ files: ['docs/auth/README.md'], insertions: 2, rules }),
    false,
  );
  assert.equal(
    isApprovalDeltaLowRisk({
      files: ['.github/workflows/deploy.yml', 'docs/deploy.md'],
      insertions: 2,
      rules,
    }),
    false,
  );
  assert.equal(
    isApprovalDeltaLowRisk({ files: ['README.md'], insertions: 1000, rules }),
    false,
  );
  assert.equal(
    isApprovalDeltaLowRisk({ files: [], insertions: 1000, rules }),
    false,
  );
  assert.equal(
    isApprovalDeltaLowRisk({
      files: Array.from({ length: 50 }, (_, index) => `docs/${index}.md`),
      insertions: 50,
      rules,
    }),
    false,
  );
});

test('bot approvals are always dismissed on HIGH, including at current HEAD', () => {
  assert.equal(
    shouldDismissApproval({
      reviewerLogin: 'github-actions[bot]',
      reviewCommitId: 'head',
      headSha: 'head',
      deltaLowRisk: true,
    }),
    true,
  );
});

test('deleted-account approvals are null-safe and follow commit freshness', () => {
  assert.equal(
    shouldDismissApproval({
      reviewerLogin: undefined,
      reviewCommitId: 'head',
      headSha: 'head',
      deltaLowRisk: true,
    }),
    false,
  );
  assert.equal(
    shouldDismissApproval({
      reviewerLogin: undefined,
      reviewCommitId: 'old',
      headSha: 'head',
      deltaLowRisk: false,
    }),
    true,
  );
});

test('only the latest review per account is an effective approval', () => {
  const reviews = [
    { id: 1, state: 'APPROVED', submitted_at: '2026-01-01T00:00:00Z', user: { login: 'alice' } },
    { id: 2, state: 'CHANGES_REQUESTED', submitted_at: '2026-01-02T00:00:00Z', user: { login: 'alice' } },
    { id: 3, state: 'APPROVED', submitted_at: '2026-01-03T00:00:00Z', user: { login: 'bob' } },
    { id: 4, state: 'APPROVED', submitted_at: '2026-01-04T00:00:00Z', user: null },
    { id: 5, state: 'COMMENTED', submitted_at: '2026-01-05T00:00:00Z', user: { login: 'bob' } },
    { id: 6, state: 'APPROVED', submitted_at: '2026-01-01T00:00:00Z', user: { login: 'carol' } },
    { id: 7, state: 'APPROVED', submitted_at: '2026-01-06T00:00:00Z', user: { login: 'carol' } },
  ];
  assert.deepEqual(effectiveApprovals(reviews).map(review => review.id), [3, 4, 7]);
});

test('approval size counts only files still in the PR', () => {
  const fullFileSet = pathSetFromNul(Buffer.from('README.md\0'));
  const result = parseFilteredNumstat(
    Buffer.from('1500\t0\tbase-merge.js\x003\t0\tREADME.md\x00'),
    fullFileSet,
  );
  assert.deepEqual(result.files.map(file => file.toString()), ['README.md']);
  assert.equal(result.insertions, 3);
});

test('rename-expanded numstat cannot bypass the insertion size gate', () => {
  const fullFileSet = pathSetFromNul(Buffer.from('old-name.md\0new-name.md\0'));
  const result = parseFilteredNumstat(
    Buffer.from('0\t1500\told-name.md\x001503\t0\tnew-name.md\x00'),
    fullFileSet,
  );
  assert.equal(result.files.length, 2);
  assert.equal(result.insertions, 1503);
  assert.equal(
    isApprovalDeltaLowRisk({
      files: result.files.map(file => file.toString()),
      insertions: result.insertions,
      rules,
    }),
    false,
  );
});

test('current human approvals and stale approvals across proven-safe deltas are preserved', () => {
  assert.equal(
    shouldDismissApproval({
      reviewerLogin: 'human',
      reviewCommitId: 'head',
      headSha: 'head',
      deltaLowRisk: false,
    }),
    false,
  );
  assert.equal(
    shouldDismissApproval({
      reviewerLogin: 'human',
      reviewCommitId: 'old',
      headSha: 'head',
      deltaLowRisk: true,
    }),
    false,
  );
});

test('stale human approval is dismissed when any unreviewed delta is not proven safe', () => {
  assert.equal(
    shouldDismissApproval({
      reviewerLogin: 'human',
      reviewCommitId: 'old',
      headSha: 'head',
      deltaLowRisk: false,
    }),
    true,
  );
});
