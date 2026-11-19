#!/usr/bin/env node
// Endpoint auth gate — deterministic layer.
//
// Runs the central semgrep rules (security/endpoint-auth/rules) over the files changed
// in the PR (checked out at the PR head), keeps only findings that overlap lines the PR
// adds (diff merge-base -> working tree, so line numbers match the PR head), applies per-rule
// suppressions, adds a few config checks, and detects which changed files touch HTTP
// route/handler code (used to decide whether the LLM endpoint review should run).
//
// Usage:
//   node scripts/endpoint-auth-scan.mjs \
//     --base <merge-base of PR base and head> \
//     --full full-changed-files.txt --changed changed-files.txt \
//     --rules .risk-tier-policy-gate/security/endpoint-auth/rules \
//     --out endpoint-auth-result.json [--diff-out endpoint-auth-diff.patch]
//
// Never exits non-zero for findings: the workflow decides what to do with them.
// Exits non-zero only on bad usage.

import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';

const args = Object.fromEntries(
  process.argv.slice(2).reduce((acc, a, i, all) => {
    if (a.startsWith('--')) acc.push([a.slice(2), all[i + 1]]);
    return acc;
  }, []),
);
for (const k of ['base', 'full', 'changed', 'rules', 'out']) {
  if (!args[k]) {
    console.error(`missing --${k}`);
    process.exit(2);
  }
}

const readList = (p) =>
  fs.existsSync(p) ? fs.readFileSync(p, 'utf8').split('\n').map((s) => s.trim()).filter(Boolean) : [];

const fullFiles = readList(args.full);
const changedFiles = new Set(readList(args.changed));

// Paths that are test/fixture/tooling code: never scanned, never trigger the LLM review.
const IGNORED_PATH =
  /(^|\/)(node_modules|dist|build|\.next|vendor|coverage|__tests__|__mocks__|tests?|spec|fixtures?|testdata|mocks?|e2e|harness|examples?|docs?|\.storybook|stories)(\/|$)|\.(test|spec|stories)\.[cm]?[jt]sx?$|(^|\/)test_[^/]*\.py$|_test\.(py|go)$|\.min\.js$|\.d\.ts$/i;
const CODE_EXT = /\.(m?[jt]sx?|cjs|cts|mts|py|go)$/i;

const existing = fullFiles.filter((f) => fs.existsSync(f) && fs.statSync(f).isFile());
// Semgrep rule-test fixtures are deliberately vulnerable code — never report them. Only the
// real semgrep convention counts (a sibling `<same-basename>.yml|.yaml` rule file AND
// `ruleid:` annotations), so adding a `// ruleid:` comment alone cannot hide code.
const isRuleFixture = (f) => {
  const base = f.replace(/\.[^./]+$/, '');
  const hasRuleFile = fs.existsSync(`${base}.yml`) || fs.existsSync(`${base}.yaml`);
  return hasRuleFile && /^\s*(\/\/|#)\s*ruleid:/m.test(fs.readFileSync(f, 'utf8'));
};
const codeFiles = existing.filter((f) => CODE_EXT.test(f) && !IGNORED_PATH.test(f) && !isRuleFixture(f));

// ---------------------------------------------------------------- added lines per file
// Diff base -> WORKING TREE (the checked-out PR head). Pass the merge-base as `base` so
// commits that landed on the base branch meanwhile are not attributed to the PR.
function addedLines(base, files) {
  const map = new Map();
  if (files.length === 0) return map;
  const r = spawnSync('git', ['diff', '-U0', '--no-color', '--no-ext-diff', base, '--', ...files], {
    encoding: 'utf8',
    maxBuffer: 256 * 1024 * 1024,
  });
  if (r.status !== 0) throw new Error(`git diff failed: ${r.stderr}`);
  let cur = null;
  for (const line of r.stdout.split('\n')) {
    if (line.startsWith('+++ ')) {
      cur = line.startsWith('+++ b/') ? line.slice(6) : null;
      if (cur && !map.has(cur)) map.set(cur, { lines: new Set(), text: [] });
      continue;
    }
    const h = /^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@/.exec(line);
    if (h && cur) {
      const start = Number(h[1]);
      const count = h[2] === undefined ? 1 : Number(h[2]);
      for (let i = 0; i < count; i++) map.get(cur).lines.add(start + i);
      continue;
    }
    if (cur && line.startsWith('+') && !line.startsWith('+++')) map.get(cur).text.push(line.slice(1));
  }
  return map;
}

let scannerError = null;
let added = new Map();
try {
  added = addedLines(args.base, existing);
} catch (e) {
  scannerError = String(e.message || e);
}

// ---------------------------------------------------------------- semgrep
const findings = [];
if (!scannerError && codeFiles.length > 0) {
  const r = spawnSync(
    'semgrep',
    ['scan', '--metrics=off', '--quiet', '--json', '--disable-version-check', '--disable-nosem', '--timeout', '20', '--config', args.rules, ...codeFiles],
    { encoding: 'utf8', maxBuffer: 256 * 1024 * 1024 },
  );
  // semgrep exits 0 (no findings) or 1 (findings); >=2 is an error.
  if (r.error || (r.status !== 0 && r.status !== 1)) {
    scannerError = `semgrep failed (exit ${r.status}): ${(r.stderr || String(r.error || '')).slice(0, 500)}`;
  } else {
    let out;
    try {
      out = JSON.parse(r.stdout);
    } catch (e) {
      scannerError = `could not parse semgrep output: ${e.message}`;
    }
    const fileCache = new Map();
    const fileText = (f) => {
      if (!fileCache.has(f)) fileCache.set(f, fs.readFileSync(f, 'utf8'));
      return fileCache.get(f);
    };
    for (const res of out?.results ?? []) {
      const file = path.relative(process.cwd(), path.resolve(res.path));
      const meta = res.extra?.metadata ?? {};
      const a = added.get(file);
      if (!a) continue;
      let touches = false;
      for (let l = res.start.line; l <= res.end.line; l++) {
        if (a.lines.has(l)) {
          touches = true;
          break;
        }
      }
      if (!touches) continue;
      if (meta.suppress_if_file_matches) {
        let src = String(meta.suppress_if_file_matches);
        let flags = '';
        if (src.startsWith('(?i)')) {
          src = src.slice(4);
          flags = 'i';
        }
        if (new RegExp(src, flags).test(fileText(file))) continue;
      }
      // Inline `nosemgrep` suppressions are honoured but never silent: the finding is
      // kept as `suppressed`, and a suppression ADDED by this PR forces human review.
      const srcLines = fileText(file).split('\n');
      const supLine = [res.start.line, res.start.line - 1, res.end.line].find((l) => /nosemgrep/i.test(srcLines[l - 1] ?? ''));
      const suppressed = supLine !== undefined;
      findings.push({
        source: 'rule',
        suppressed,
        suppression_added: suppressed && a.lines.has(supLine),
        suppression_reason: suppressed ? (srcLines[supLine - 1].split(/nosemgrep:?/i)[1] ?? '').trim().slice(0, 200) : undefined,
        rule: String(res.check_id).split('.').pop(),
        gate: meta.gate === 'high' ? 'high' : 'info',
        category: meta.category ?? 'endpoint-auth',
        file,
        line: res.start.line,
        end_line: res.end.line,
        in_increment: changedFiles.has(file),
        message: String(res.extra?.message ?? '').replace(/\s+/g, ' ').trim(),
      });
    }
    for (const err of out?.errors ?? []) {
      if (err.level === 'error') scannerError = scannerError ?? `semgrep error: ${String(err.message).slice(0, 300)}`;
    }
  }
}

// ---------------------------------------------------------------- config checks (info only)
const WRANGLER = /(^|\/)wrangler(\.[\w-]+)?\.(toml|jsonc?)$/i;
for (const file of existing) {
  if (IGNORED_PATH.test(file)) continue;
  const a = added.get(file);
  if (!a) continue; // file not in diff output (e.g. mode-only change)

  // Evaluated even for pure deletions: removing `workers_dev = false` is the risky edit.
  if (WRANGLER.test(file)) {
    const src = fs.readFileSync(file, 'utf8');
    const isToml = file.endsWith('.toml');
    const wdTrue = isToml ? /^\s*workers_dev\s*=\s*true\b/m.test(src) : /"workers_dev"\s*:\s*true\b/.test(src);
    const wdFalse = isToml ? /^\s*workers_dev\s*=\s*false\b/m.test(src) : /"workers_dev"\s*:\s*false\b/.test(src);
    const hasRoutes = isToml ? /^\s*(routes?\s*=|\[\[(env\.[\w-]+\.)?routes\]\])/m.test(src) : /"routes?"\s*:/.test(src);
    if (wdTrue || (!wdFalse && !hasRoutes)) {
      findings.push({
        source: 'config',
        rule: 'worker-reachable-on-workers-dev',
        gate: 'info',
        category: 'exposure',
        file,
        line: 1,
        end_line: 1,
        in_increment: changedFiles.has(file),
        message:
          'This Worker is reachable on its public `*.workers.dev` URL (`workers_dev` is ' +
          (wdTrue ? '`true`' : 'not set and no `routes` are defined') +
          '). Cloudflare Access on a custom domain does NOT protect the workers.dev URL. ' +
          'If this Worker relies on Access for auth, set `workers_dev = false` and `preview_urls = false`, ' +
          'or verify the Access JWT in code.',
      });
    }
  }

  // Only deploy definitions — not docs or code that merely mention the flag.
  const DEPLOY_FILE = /(^|\/)(\.github\/workflows\/[^/]+\.ya?ml|[^/]+\.(sh|bash|tf|tfvars)|Makefile|cloudbuild[^/]*\.ya?ml|[^/]*deploy[^/]*\.ya?ml)$/i;
  if (!DEPLOY_FILE.test(file)) continue;
  const addedText = a.text.join('\n');
  if (/--allow-unauthenticated\b/.test(addedText) || /allUsers[\s\S]{0,200}(run|cloudfunctions)\.invoker|(run|cloudfunctions)\.invoker[\s\S]{0,200}allUsers/.test(addedText)) {
    findings.push({
      source: 'config',
      rule: 'public-invoker',
      gate: 'info',
      category: 'exposure',
      file,
      line: 1,
      end_line: 1,
      in_increment: changedFiles.has(file),
      message:
        'This change makes a Cloud Run service / Cloud Function publicly invokable (`allUsers` / ' +
        '`--allow-unauthenticated`). Every route it serves must then enforce its own auth.',
    });
  }
}

// ---------------------------------------------------------------- route-touching detection
const ROUTE_LINE = [
  /\basync\s+fetch\s*\(\s*(request|req)\b/,
  /\bfetch\s*:\s*(async\s*)?\(\s*(request|req)\b/,
  /\b(url|u|reqUrl)\.pathname\s*(===|==|!==|\.startsWith|\.match|\.endsWith)/,
  /\b(app|router|routes|api|server|hono|r|v\d+|admin|bp|blueprint|public|internal)\.(get|post|put|patch|delete|all|use|route|on)\s*\(\s*['"`]\//,
  /\bexport\s+(const|async\s+function|function)\s+onRequest(Get|Post|Put|Patch|Delete|Head|Options)?\b/,
  /\.https\.onRequest\s*\(|\bonRequest\s*\(/,
  /@\w+\.(get|post|put|patch|delete|route|api_route|websocket)\s*\(/,
  /@(Controller|Get|Post|Put|Patch|Delete|All|Head|Options|UseGuards|Public|SkipAuth|AllowAnonymous)\s*\(/, // NestJS & co.
  /\bexport\s+(async\s+)?function\s+(GET|POST|PUT|PATCH|DELETE)\b|\bexport\s+const\s+(GET|POST|PUT|PATCH|DELETE)\s*=/,
  /\b(publicProcedure|protectedProcedure|adminProcedure)\b/,
  /\bhttp\.HandleFunc\s*\(|\.(GET|POST|PUT|PATCH|DELETE|Handle|HandleFunc)\s*\(\s*"\//,
  /\b(server|mcp|agent)\.(tool|registerTool|resource|prompt)\s*\(/,
  /\bnew\s+Hono\s*\(|\bexpress\s*\(\s*\)|\bRouter\s*\(\s*\)|\bFastAPI\s*\(|\bAPIRouter\s*\(|\bFlask\s*\(/,
  // Route tables: ['GET', /^\/v1\/x$/, handler, { public: true }] / ['POST', '/v1/x', handler]
  /\[\s*['"`](GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|ALL|ANY|\*)['"`]\s*,\s*(\/|['"`]\/)/i,
  // Route objects: { method: 'GET', path: '/x' } / { path: '/x', method: 'GET' }
  /\bmethods?\s*:\s*\[?\s*['"`](GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|ALL)['"`][^}]*\b(path|url|route|pattern)\s*:/i,
  /\b(path|url|route|pattern)\s*:\s*['"`]\/[^'"`]*['"`]\s*,[^}]*\bmethods?\s*:/i,
];
const ROUTE_PATH = /(^|\/)(pages\/api\/|app\/(.*\/)?route\.[cm]?[jt]sx?$)/;
const routeFilesFull = [];
for (const file of codeFiles) {
  const a = added.get(file);
  if (!a || a.text.length === 0) continue;
  if (ROUTE_PATH.test(file) || a.text.some((l) => ROUTE_LINE.some((re) => re.test(l)))) routeFilesFull.push(file);
}
const routeFilesIncrement = routeFilesFull.filter((f) => changedFiles.has(f));

// Diff of route files for the LLM reviewer (it gets no shell access).
if (args['diff-out']) {
  let patch = '';
  if (routeFilesFull.length > 0) {
    const r = spawnSync('git', ['diff', '-U25', '--no-color', '--no-ext-diff', args.base, '--', ...routeFilesFull], {
      encoding: 'utf8',
      maxBuffer: 256 * 1024 * 1024,
    });
    patch = r.stdout ?? '';
  }
  const MAX = 400_000;
  if (patch.length > MAX) patch = patch.slice(0, MAX) + '\n\n[diff truncated — read the files directly for the rest]\n';
  fs.writeFileSync(args['diff-out'], patch);
}

const highCount = findings.filter((f) => f.gate === 'high' && !f.suppressed).length;
const result = {
  version: 1,
  scanner_error: scannerError,
  scanned_code_files: codeFiles.length,
  findings,
  high_count: highCount,
  route_files_full: routeFilesFull,
  route_files_increment: routeFilesIncrement,
};
fs.writeFileSync(args.out, JSON.stringify(result, null, 2));

const ghOut = process.env.GITHUB_OUTPUT;
if (ghOut) {
  fs.appendFileSync(ghOut, `det_high=${highCount}\n`);
  fs.appendFileSync(ghOut, `det_total=${findings.length}\n`);
  fs.appendFileSync(ghOut, `route_touching_full=${routeFilesFull.length > 0}\n`);
  fs.appendFileSync(ghOut, `route_touching_increment=${routeFilesIncrement.length > 0}\n`);
  fs.appendFileSync(ghOut, `scanner_ok=${scannerError ? 'false' : 'true'}\n`);
}
console.log(
  `endpoint-auth scan: ${codeFiles.length} code files, ${findings.length} findings (${highCount} high), ` +
    `${routeFilesFull.length} route files (${routeFilesIncrement.length} in this push)` +
    (scannerError ? ` — SCANNER ERROR: ${scannerError}` : ''),
);
for (const f of findings) console.log(`  [${f.gate}] ${f.rule} ${f.file}:${f.line}`);
