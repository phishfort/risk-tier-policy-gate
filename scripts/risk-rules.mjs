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

const categories = [];
const highHits = [];

function toRegex(glob) {
  const escaped = glob
    .replace(/[.+^${}()|[\]\\]/g, '\\$&')
    .replace(/\*\*/g, '::DOUBLE_STAR::')
    .replace(/\*/g, '[^/]*')
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
const forcedHigh = uniqueCategories.length > 0;
const allLowSafe = !forcedHigh && changedFiles.length > 0 && changedFiles.every((f) => lowMatchers.some((r) => r.test(f)));

const result = {
  changed_files: changedFiles,
  deterministic_tier: forcedHigh ? 'high' : allLowSafe ? 'low' : 'unknown',
  forced_high: forcedHigh,
  all_low_safe: allLowSafe,
  matched_categories: uniqueCategories,
  high_hits: highHits,
  summary: forcedHigh
    ? `High risk forced by deterministic rules (${uniqueCategories.join(', ')})`
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
