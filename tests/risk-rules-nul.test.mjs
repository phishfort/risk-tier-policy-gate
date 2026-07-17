import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import test from 'node:test';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

test('risk rules parse NUL-delimited filenames without newline or space ambiguity', () => {
  const temp = mkdtempSync(path.join(tmpdir(), 'risk-rules-nul-'));
  try {
    const changedPath = path.join(temp, 'changed-files.txt');
    writeFileSync(changedPath, 'docs/auth/strange\nname.md\0README.md\0');

    const result = spawnSync(
      process.execPath,
      [
        path.join(repoRoot, 'scripts/risk-rules.mjs'),
        changedPath,
        path.join(repoRoot, 'config/risk-rules.json'),
      ],
      { cwd: temp, encoding: 'utf8' },
    );
    assert.equal(result.status, 0, result.stderr);

    const riskResult = JSON.parse(readFileSync(path.join(temp, 'risk-result.json'), 'utf8'));
    assert.deepEqual(riskResult.changed_files, ['docs/auth/strange\nname.md', 'README.md']);
    assert.equal(riskResult.forced_high, true);
  } finally {
    rmSync(temp, { recursive: true, force: true });
  }
});

test('risk rules fail closed on non-UTF-8 filenames', () => {
  const temp = mkdtempSync(path.join(tmpdir(), 'risk-rules-invalid-'));
  try {
    const changedPath = path.join(temp, 'changed-files.txt');
    writeFileSync(changedPath, Buffer.from([0x64, 0x6f, 0x63, 0x73, 0x2f, 0xff, 0x00]));
    const result = spawnSync(
      process.execPath,
      [
        path.join(repoRoot, 'scripts/risk-rules.mjs'),
        changedPath,
        path.join(repoRoot, 'config/risk-rules.json'),
      ],
      { cwd: temp, encoding: 'utf8' },
    );
    assert.notEqual(result.status, 0);
  } finally {
    rmSync(temp, { recursive: true, force: true });
  }
});
