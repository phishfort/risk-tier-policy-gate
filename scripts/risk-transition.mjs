import { toRegex } from './risk-glob.mjs';

const TIERS = new Set(['high', 'low']);
export const BOT_LOGIN = 'github-actions[bot]';

function assertTier(tier, name) {
  if (!TIERS.has(tier)) {
    throw new TypeError(`${name} must be "high" or "low"; received ${JSON.stringify(tier)}`);
  }
}

/** Decide the aggregate approval action from the full-PR tier only. */
export function approvalAction({ previousTier, fullTier }) {
  assertTier(fullTier, 'fullTier');
  if (previousTier && !TIERS.has(previousTier)) {
    throw new TypeError(`previousTier must be empty, "high", or "low"; received ${JSON.stringify(previousTier)}`);
  }

  if (fullTier === 'high') return 'reconcile-high-approvals';
  return 'ensure-low-approval';
}

/**
 * Prove that the net changes since a human approval are deterministically safe.
 * Unknown code changes fail closed and require fresh review.
 */
export function isApprovalDeltaLowRisk({ files, insertions, rules }) {
  if (!Array.isArray(files) || !rules || !Array.isArray(rules.highRiskCategories) ||
      !Array.isArray(rules.lowRiskPatterns) || !Number.isFinite(insertions)) {
    return false;
  }
  if (files.length >= 50 || insertions >= 1000) return false;
  if (files.length === 0) return true;

  const highMatchers = rules.highRiskCategories.flatMap(category =>
    Array.isArray(category.patterns) ? category.patterns.map(toRegex) : [],
  );
  const lowMatchers = rules.lowRiskPatterns.map(toRegex);

  if (files.some(file => highMatchers.some(regex => regex.test(file)))) return false;
  return files.every(file => lowMatchers.some(regex => regex.test(file)));
}

/** Return only the latest effective APPROVED review for each account. */
export function effectiveApprovals(reviews) {
  if (!Array.isArray(reviews)) return [];
  const latest = new Map();
  for (const review of reviews) {
    // COMMENTED/PENDING reviews do not revoke an existing approval. Approval,
    // change-request, and dismissal states are decisive for the review gate.
    if (!['APPROVED', 'CHANGES_REQUESTED', 'DISMISSED'].includes(review.state)) continue;
    const login = review.user?.login;
    // A deleted account has no stable identity, so assess each record by its
    // reviewed commit rather than trying to group unrelated null users.
    const key = login ? `user:${login}` : `deleted:${review.id}`;
    const current = latest.get(key);
    const submitted = Date.parse(review.submitted_at || '') || 0;
    const currentSubmitted = current ? Date.parse(current.submitted_at || '') || 0 : -1;
    if (!current || submitted > currentSubmitted ||
        (submitted === currentSubmitted && Number(review.id) > Number(current.id))) {
      latest.set(key, review);
    }
  }
  return [...latest.values()].filter(review => review.state === 'APPROVED');
}

function splitNul(buffer) {
  const records = [];
  let start = 0;
  for (let index = 0; index < buffer.length; index += 1) {
    if (buffer[index] === 0) {
      if (index > start) records.push(buffer.subarray(start, index));
      start = index + 1;
    }
  }
  if (start < buffer.length) records.push(buffer.subarray(start));
  return records;
}

export function pathSetFromNul(buffer) {
  if (!Buffer.isBuffer(buffer)) throw new TypeError('path list must be a Buffer');
  return new Set(splitNul(buffer).map(file => file.toString('hex')));
}

/** Parse raw `git diff --no-renames --numstat -z` output and filter it to the current PR. */
export function parseFilteredNumstat(numstat, fullFileSet) {
  if (!Buffer.isBuffer(numstat) || !(fullFileSet instanceof Set)) {
    throw new TypeError('numstat must be a Buffer and fullFileSet must be a Set');
  }

  const files = [];
  let insertions = 0;
  for (const record of splitNul(numstat)) {
    const firstTab = record.indexOf(9);
    const secondTab = firstTab < 0 ? -1 : record.indexOf(9, firstTab + 1);
    if (firstTab < 1 || secondTab < 0) throw new Error('Unexpected git numstat record');
    const file = record.subarray(secondTab + 1);
    if (!fullFileSet.has(file.toString('hex'))) continue;
    const added = record.subarray(0, firstTab).toString('ascii');
    if (!/^\d+$/.test(added)) throw new Error('Binary or invalid insertion count');
    insertions += Number(added);
    files.push(file);
  }
  return { files, insertions };
}

/** Bot approval never satisfies HIGH; other approvals are valid at HEAD or across a proven-safe delta. */
export function shouldDismissApproval({ reviewerLogin, reviewCommitId, headSha, deltaLowRisk }) {
  if (reviewerLogin === BOT_LOGIN) return true;
  if (reviewCommitId === headSha) return false;
  return deltaLowRisk !== true;
}
