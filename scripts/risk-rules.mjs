#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';

const [, , changedFilesPath, rulesPath] = process.argv;
if (!changedFilesPath || !rulesPath) {
  console.error('Usage: node scripts/risk-rules.mjs <changed-files.txt> <rules.json>');
  process.exit(1);
}

const changedFiles = fs
  .readFileSync(changedFilesPath, 'utf8')
  .split('\n')
  .map((s) => s.trim())
  .filter(Boolean);

const rules = JSON.parse(fs.readFileSync(rulesPath, 'utf8'));

// --- Schema validation ---------------------------------------------------
function validateRules(rules, filePath) {
  const errors = [];

  if (!Array.isArray(rules.highRiskCategories) || rules.highRiskCategories.length === 0) {
    errors.push('highRiskCategories must be a non-empty array');
  } else {
    rules.highRiskCategories.forEach((cat, i) => {
      if (typeof cat.name !== 'string' || cat.name.length === 0) {
        errors.push(`highRiskCategories[${i}].name must be a non-empty string`);
      }
      if (!Array.isArray(cat.patterns) || cat.patterns.length === 0) {
        errors.push(`highRiskCategories[${i}].patterns must be a non-empty array`);
      } else if (!cat.patterns.every((p) => typeof p === 'string')) {
        errors.push(`highRiskCategories[${i}].patterns must only contain strings`);
      }
    });
  }

  if (!Array.isArray(rules.lowRiskPatterns) || rules.lowRiskPatterns.length === 0) {
    errors.push('lowRiskPatterns must be a non-empty array');
  } else if (!rules.lowRiskPatterns.every((p) => typeof p === 'string')) {
    errors.push('lowRiskPatterns must only contain strings');
  }

  if (errors.length > 0) {
    console.error(`Invalid risk-rules schema in ${filePath}:`);
    errors.forEach((e) => console.error(`  - ${e}`));
    process.exit(1);
  }
}

validateRules(rules, rulesPath);
// -------------------------------------------------------------------------

const categories = [];
const highHits = [];

function toRegex(glob) {
  const escaped = glob
    .replace(/[.+^${}()|[\]\\]/g, '\\$&')
    .replace(/\*\*\//g, '::DOUBLE_STAR_SLASH::')
    .replace(/\*\*/g, '::DOUBLE_STAR::')
    .replace(/\*/g, '[^/]*')
    .replace(/::DOUBLE_STAR_SLASH::/g, '(.*/)?')
    .replace(/::DOUBLE_STAR::/g, '.*');
  return new RegExp(`^${escaped}$`);
}

const highMatchers = rules.highRiskCategories.map((c) => ({
  ...c,
  regexes: c.patterns.map(toRegex),
}));

const lowMatchers = rules.lowRiskPatterns.map(toRegex);

for (const file of changedFiles) {
  for (const cat of highMatchers) {
    if (cat.regexes.some((r) => r.test(file))) {
      categories.push(cat.name);
      highHits.push({ file, category: cat.name });
    }
  }
}

const uniqueCategories = [...new Set(categories)];

// Lockfile-only exception: if the only high-risk hits are lockfiles with no
// corresponding manifest change, downgrade to non-forced (let LLM decide or
// treat as low-safe).
const lockfileMap = {
  'package-lock.json': 'package.json',
  'yarn.lock': 'package.json',
  'pnpm-lock.yaml': 'package.json',
  'poetry.lock': 'pyproject.toml',
  'Gemfile.lock': 'Gemfile',
  'go.sum': 'go.mod',
};
const changedSet = new Set(changedFiles);
const lockfileOnly =
  highHits.length > 0 &&
  highHits.every((h) => {
    const basename = path.basename(h.file);
    if (!(basename in lockfileMap)) return false;
    const manifest = h.file.replace(basename, lockfileMap[basename]);
    return !changedSet.has(manifest);
  });

const forcedHigh = uniqueCategories.length > 0 && !lockfileOnly;
const allLowSafe = !forcedHigh && changedFiles.length > 0 && changedFiles.every((f) => lowMatchers.some((r) => r.test(f)));

const result = {
  changed_files: changedFiles,
  deterministic_tier: forcedHigh ? 'high' : allLowSafe ? 'low' : 'unknown',
  forced_high: forcedHigh,
  all_low_safe: allLowSafe,
  lockfile_only: lockfileOnly,
  matched_categories: uniqueCategories,
  high_hits: highHits,
  summary: forcedHigh
    ? `High risk forced by deterministic rules (${uniqueCategories.join(', ')})`
    : lockfileOnly
    ? 'Lockfile-only change (no manifest modified); downgraded from high-risk'
    : allLowSafe
    ? 'Low risk by deterministic safe-file patterns'
    : 'No deterministic high-risk hit; LLM classification required',
};

fs.writeFileSync('risk-result.json', JSON.stringify(result, null, 2));

const ghOut = process.env.GITHUB_OUTPUT;
if (ghOut) {
  fs.appendFileSync(ghOut, `deterministic_tier=${result.deterministic_tier}\n`);
  fs.appendFileSync(ghOut, `forced_high=${result.forced_high}\n`);
  fs.appendFileSync(ghOut, `all_low_safe=${result.all_low_safe}\n`);
}

console.log(JSON.stringify(result, null, 2));
