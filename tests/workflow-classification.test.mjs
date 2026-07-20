import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';

const workflow = fs.readFileSync('.github/workflows/risk-tier-required.yml', 'utf8');

test('checkout credentials are not exposed to the LLM workspace', () => {
  assert.equal((workflow.match(/persist-credentials: false/g) || []).length, 2);
  assert.match(workflow, /cancel-in-progress: false/);
  assert.match(workflow, /repository: phishfort\/risk-tier-policy-gate/);
  assert.match(workflow, /ref: \$\{\{ github\.workflow_sha \}\}/);
  assert.match(workflow, /ref: \$\{\{ steps\.pr\.outputs\.head_sha \}\}/);
});

test('aggregate classification always receives the merge-base full PR file list', () => {
  assert.match(workflow, /git diff --no-renames --name-only -z "\$FULL_BASE_SHA\.\.\.\$HEAD_SHA"/);
  assert.match(workflow, /git diff --no-renames --shortstat "\$FULL_BASE_SHA\.\.\.\$HEAD_SHA"/);
  assert.match(workflow, /risk-rules\.mjs full-changed-files\.txt "\$RULES_PATH"/);
  assert.doesNotMatch(workflow, /github\.event\.before|incremental-changed-files|context\.payload\.pull_request\.head\.sha/);
});

test('full LLM classification is structured and applied deterministically', () => {
  assert.match(workflow, /--json-schema.*"tier"/);
  assert.doesNotMatch(workflow, /minItems|maxItems|maxLength/);
  assert.match(workflow, /Apply full PR classification/);
  assert.match(workflow, /tier = 'high';/);
  assert.match(workflow, /tierLabels\.length !== 1/);
  assert.match(workflow, /--disallowedTools GitHub,Bash,Edit,Write/);
  assert.match(workflow, /--allowedTools Read,Glob,Grep/);
  assert.match(workflow, /Generate full PR diff for LLM/);
  assert.match(workflow, /if: steps\.claude\.outputs\.available == 'true'/);
  assert.equal((workflow.match(/> full-pr\.diff/g) || []).length, 1);
});

test('HIGH approval reconciliation is review-relative and fail-closed', () => {
  assert.match(workflow, /github\.paginate\(github\.rest\.pulls\.listReviews/);
  assert.match(workflow, /'git', \['diff', '--no-renames', '--numstat', '-z', reviewCommitId, headSha\]/);
  assert.doesNotMatch(workflow, /'--shortstat', reviewCommitId|'--name-only', '-z', reviewCommitId/);
  assert.match(workflow, /parseFilteredNumstat\(numstat, fullFileSet\)/);
  assert.match(workflow, /effectiveApprovals\(reviews\)/);
  assert.match(workflow, /throw new Error\(`Failed to dismiss required approvals/);
  assert.match(workflow, /Approvals that do not satisfy the current HIGH gate remain active/);
  assert.match(workflow, /hasBotApproval/);
  assert.match(workflow, /deltaLowRisk: \(\) => approvalDeltaIsLowRisk/);
});

test('classification mutations are centralized and race tolerant', () => {
  assert.equal((workflow.match(/github\.rest\.issues\.removeLabel/g) || []).length, 1);
  assert.equal((workflow.match(/github\.rest\.issues\.listComments/g) || []).length, 1);
  assert.match(workflow, /github\.paginate\(github\.rest\.issues\.listComments/);
  assert.match(workflow, /if \(err\.status !== 404\) throw err/);
});

test('review users are null-safe and policy tests run in CI', () => {
  assert.doesNotMatch(workflow, /review\.user\.login/);
  assert.match(workflow, /review\.user\?\.login/);
  const ci = fs.readFileSync('.github/workflows/policy-tests.yml', 'utf8');
  assert.match(ci, /node --test tests\/\*\.test\.mjs/);
});

test('queued runs use and revalidate the live PR revision', () => {
  assert.match(workflow, /Resolve current PR revision/);
  assert.ok((workflow.match(/github\.rest\.pulls\.get/g) || []).length >= 3);
  assert.match(workflow, /Skipping stale classification/);
  assert.match(workflow, /Skipping stale approval reconciliation/);
});

test('valid approvals and existing requests are not re-requested', () => {
  assert.match(workflow, /activeHumanApprovals\.length > 0/);
  assert.match(workflow, /listRequestedReviewers/);
  assert.match(workflow, /alreadyRequested\.has/);
});

test('previous tier and bot identity are not duplicated', () => {
  assert.doesNotMatch(workflow, /Check previous classification|PREVIOUS_LABEL|previousTier/);
  assert.doesNotMatch(workflow, /github-actions\[bot\]/);
  assert.match(workflow, /BOT_LOGIN/);
});
