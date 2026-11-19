// Endpoint auth gate — report step (called from actions/github-script in
// .github/workflows/endpoint-auth-required.yml).
//
// Merges deterministic findings (endpoint-auth-result.json) with the optional AI endpoint
// review, then publishes them WITHOUT blocking the PR:
//   - a separate check run "Endpoint auth findings" (red on findings, inline annotations)
//   - a PR comment (marker <!-- endpoint-auth-gate -->), only when there is something to say
//   - the label `security:unauth-endpoint` while unresolved findings exist
// and writes endpoint-auth-final.json into workDir (for debugging / tests).

const fs = require('fs');
const path = require('path');

const MARKER = '<!-- endpoint-auth-gate -->';
const LLM_DATA_RE = /<!-- endpoint-auth-llm:([A-Za-z0-9+/=]*) -->/;
const LABEL = 'security:unauth-endpoint';
const CHECK_NAME = 'Endpoint auth findings';
const RULES_URL = 'https://github.com/phishfort/risk-tier-policy-gate/tree/main/security/endpoint-auth';
const AUTH_LEVELS = new Set(['none', 'weak', 'ok', 'unclear']);

function readJson(p, fallback) {
  try {
    return JSON.parse(fs.readFileSync(p, 'utf8'));
  } catch {
    return fallback;
  }
}

function readList(p) {
  try {
    return fs.readFileSync(p, 'utf8').split('\n').map((s) => s.trim()).filter(Boolean);
  } catch {
    return [];
  }
}

// Pull the final assistant text out of claude-code-action's execution file and parse
// the first JSON object in it. Returns null when nothing usable is found.
function parseLlmOutput(executionFile) {
  if (!executionFile || !fs.existsSync(executionFile)) return null;
  let text = '';
  const raw = fs.readFileSync(executionFile, 'utf8');
  try {
    const parsed = JSON.parse(raw);
    const msgs = Array.isArray(parsed) ? parsed : [parsed];
    const result = [...msgs].reverse().find((m) => m && m.type === 'result' && typeof m.result === 'string');
    if (result) text = result.result;
    if (!text) {
      const assistant = [...msgs].reverse().find((m) => m && m.type === 'assistant');
      const blocks = assistant?.message?.content ?? [];
      text = blocks.filter((b) => b.type === 'text').map((b) => b.text).join('\n');
    }
  } catch {
    text = raw;
  }
  return extractJson(text);
}

function extractJson(text) {
  if (!text) return null;
  const fenced = /```(?:json)?\s*([\s\S]*?)```/.exec(text);
  for (const c of [fenced?.[1], text]) {
    if (!c) continue;
    const start = c.indexOf('{');
    const end = c.lastIndexOf('}');
    if (start === -1 || end <= start) continue;
    try {
      return JSON.parse(c.slice(start, end + 1));
    } catch {
      /* try next */
    }
  }
  return null;
}

function normalizeLlm(obj) {
  if (!obj || !Array.isArray(obj.endpoints)) return null;
  return obj.endpoints
    .filter((e) => e && typeof e.file === 'string')
    .map((e) => ({
      source: 'llm',
      file: e.file.replace(/^\.?\//, ''),
      line: Number.isInteger(e.line) && e.line > 0 ? e.line : null,
      method: typeof e.method === 'string' ? e.method.slice(0, 10) : '',
      route: typeof e.route === 'string' ? e.route.slice(0, 120) : '',
      auth: AUTH_LEVELS.has(e.auth) ? e.auth : 'unclear',
      sensitive: e.sensitive === true,
      confidence: ['high', 'medium', 'low'].includes(e.confidence) ? e.confidence : 'low',
      issue: typeof e.issue === 'string' ? e.issue.slice(0, 400) : '',
      fix: typeof e.fix === 'string' ? e.fix.slice(0, 300) : '',
    }));
}

const isLlmHigh = (e) => (e.auth === 'none' || e.auth === 'weak') && e.sensitive && e.confidence !== 'low';

const firstSentence = (s) => {
  const m = /^(.+?[.!?])(\s|$)/.exec(s);
  return (m ? m[1] : s).slice(0, 260);
};
const cell = (s) => String(s ?? '').replace(/\|/g, '\\|').replace(/\n/g, ' ');

/**
 * Check-run conclusion (pure; unit-tested).
 *  failure — unresolved findings, a newly added suppression, or the rules could not run
 *  neutral — rules ran clean but the AI review failed
 *  success — nothing to report
 */
function conclusionFor({ securityHigh, suppressionAdded, scannerError, llmStatus }) {
  if (securityHigh || suppressionAdded || scannerError) return 'failure';
  if (llmStatus === 'failed') return 'neutral';
  return 'success';
}

module.exports = async function report({ github, context, core, workDir = '.', llmExecutionFile, llmRan, scanOutcome }) {
  const owner = context.repo.owner;
  const repo = context.repo.repo;
  const issue_number = context.payload.pull_request.number;
  const headSha = context.payload.pull_request.head.sha;
  const w = (f) => path.join(workDir, f);
  const link = (file, line) =>
    `[\`${file}${line ? `:${line}` : ''}\`](https://github.com/${owner}/${repo}/blob/${headSha}/${file}${line ? `#L${line}` : ''})`;

  const det = readJson(w('endpoint-auth-result.json'), null);
  const fullFiles = new Set(readList(w('full-changed-files.txt')));
  const changedNow = new Set(readList(w('changed-files.txt')));
  const scannerError = det ? det.scanner_error : `rules scan did not produce a result (step outcome: ${scanOutcome || 'unknown'})`;

  // ---- existing comment (also carries forward the previous AI review)
  const { data: comments } = await github.rest.issues.listComments({ owner, repo, issue_number, per_page: 100 });
  const existing = comments.find((c) => c.body.includes(MARKER) && c.user.login === 'github-actions[bot]');

  let llmStatus = 'not_needed';
  let llmFindings = [];
  if (llmRan) {
    const parsed = normalizeLlm(parseLlmOutput(llmExecutionFile));
    if (parsed) {
      llmStatus = 'ran';
      llmFindings = parsed;
    } else {
      llmStatus = 'failed';
    }
  }
  let llmCarried = false;
  if (llmStatus !== 'ran' && existing) {
    const m = LLM_DATA_RE.exec(existing.body);
    if (m && m[1]) {
      try {
        const prev = normalizeLlm(JSON.parse(Buffer.from(m[1], 'base64').toString('utf8'))) ?? [];
        llmFindings = prev.filter((e) => fullFiles.has(e.file));
        llmCarried = llmFindings.length > 0;
      } catch {
        /* ignore corrupt data */
      }
    }
  }

  const detFindings = det?.findings ?? [];
  const detHigh = detFindings.filter((f) => f.gate === 'high' && !f.suppressed);
  const detSuppressed = detFindings.filter((f) => f.suppressed);
  const detInfo = detFindings.filter((f) => f.gate !== 'high' && !f.suppressed);
  const suppressionAdded = detSuppressed.some((f) => f.suppression_added && changedNow.has(f.file));
  const llmHigh = llmFindings.filter(isLlmHigh);
  const securityHigh = detHigh.length > 0 || llmHigh.length > 0;
  const conclusion = conclusionFor({ securityHigh, suppressionAdded, scannerError, llmStatus });

  const final = {
    version: 1,
    conclusion,
    security_high: securityHigh,
    suppression_added: suppressionAdded,
    high_files: [...new Set([...detHigh.map((f) => f.file), ...llmHigh.map((f) => f.file)])],
    scanner_error: scannerError,
    llm_status: llmCarried ? `${llmStatus}+carried` : llmStatus,
    deterministic: detFindings,
    llm: llmFindings,
  };
  fs.writeFileSync(w('endpoint-auth-final.json'), JSON.stringify(final, null, 2));
  core.setOutput('conclusion', conclusion);
  core.setOutput('security_high', String(securityHigh));
  if (scannerError) core.warning(`Endpoint auth rules problem: ${String(scannerError).slice(0, 300)}`);
  if (llmStatus === 'failed') core.warning('Endpoint auth AI review returned no usable JSON (see the AI step log).');

  // ---- summary text (shared by check run + comment)
  const issueCount = detHigh.length + llmHigh.length;
  let headline;
  if (securityHigh) headline = `⚠️ ${issueCount} potential unauthenticated / weakly-authenticated endpoint issue(s)`;
  else if (suppressionAdded) headline = '🟡 New suppression of an endpoint-auth finding — please confirm the justification';
  else if (scannerError) headline = '⚠️ Endpoint auth rules could not run — results incomplete';
  else if (llmStatus === 'failed') headline = 'ℹ️ No rule findings; the AI endpoint review did not complete';
  else headline = '✅ No endpoint-auth issues found';

  const body = [];
  if (detHigh.length > 0) {
    body.push('**Rule findings** (lines added/changed in this PR):', '', '| Where | Rule | Problem |', '|---|---|---|');
    for (const f of detHigh) body.push(`| ${link(f.file, f.line)} | \`${f.rule}\` | ${cell(firstSentence(f.message))} |`);
    body.push('');
  }
  if (llmHigh.length > 0) {
    body.push('**AI endpoint review** (advisory — verify before acting):', '', '| Where | Endpoint | Auth | Problem | Suggested fix |', '|---|---|---|---|---|');
    for (const e of llmHigh)
      body.push(
        `| ${link(e.file, e.line)} | ${cell(`${e.method} ${e.route}`.trim() || '—')} | \`${e.auth}\` (${e.confidence}) | ${cell(e.issue)} | ${cell(e.fix)} |`,
      );
    body.push('');
  }
  if (detSuppressed.length > 0) {
    body.push(
      suppressionAdded ? '**🟡 New inline suppression(s) in this push** — reviewer: please confirm the justification:' : '<details><summary>Suppressed findings</summary>',
      '',
    );
    for (const f of detSuppressed) body.push(`- ${link(f.file, f.line)} — \`${f.rule}\` — reason: ${cell(f.suppression_reason || '(none given)')}`);
    body.push(suppressionAdded ? '' : '\n</details>\n');
  }
  if (detInfo.length > 0) {
    body.push('<details><summary>Exposure notes (informational)</summary>', '');
    for (const f of detInfo) body.push(`- ${link(f.file, f.line)} — \`${f.rule}\`: ${cell(f.message)}`);
    body.push('', '</details>', '');
  }
  const notes = [];
  if (scannerError) notes.push(`⚠️ Rules scanner: \`${cell(scannerError).slice(0, 200)}\``);
  if (llmStatus === 'failed') notes.push('⚠️ The AI endpoint review did not return a usable result this run.');
  if (llmCarried) notes.push('ℹ️ No route/handler changes in the latest push; AI findings carried over from the previous review.');
  if (llmStatus === 'ran') notes.push(`ℹ️ AI reviewed ${det?.route_files_full?.length ?? 0} route/handler file(s); ${llmFindings.length} endpoint(s) assessed.`);
  if (notes.length) body.push(...notes, '');
  if (securityHigh || suppressionAdded) {
    body.push(
      '**How to resolve**',
      '- Fix the code (verify tokens / signatures in code, fail closed when a secret is missing, check the caller owns the requested tenant/resource), **or**',
      '- If a rule finding is a reviewed false positive, add `// nosemgrep: <rule-id> -- <reason>` (Python: `# nosemgrep: ...`) on the flagged line.',
      '- AI findings are advisory. This check is **non-blocking** — a reviewer decides.',
      '',
    );
  }
  body.push(`**Resources:** [Endpoint auth rules & guidance](${RULES_URL})`);

  // ---- check run (non-blocking; carries inline annotations on the PR diff)
  const annotations = [];
  for (const f of detHigh)
    annotations.push({ path: f.file, start_line: f.line, end_line: f.line, annotation_level: 'failure', title: f.rule, message: f.message.slice(0, 1000) });
  for (const e of llmHigh)
    if (e.line)
      annotations.push({
        path: e.file,
        start_line: e.line,
        end_line: e.line,
        annotation_level: 'failure',
        title: `AI review: ${e.method} ${e.route}`.trim(),
        message: `${e.issue}\nFix: ${e.fix}`.slice(0, 1000),
      });
  for (const f of detSuppressed.filter((x) => x.suppression_added))
    annotations.push({ path: f.file, start_line: f.line, end_line: f.line, annotation_level: 'warning', title: `suppressed: ${f.rule}`, message: `Reason given: ${f.suppression_reason || '(none)'}` });
  for (const f of detInfo)
    annotations.push({ path: f.file, start_line: f.line, end_line: f.line, annotation_level: 'notice', title: f.rule, message: f.message.slice(0, 1000) });

  const output = { title: headline.replace(/^\S+\s/, ''), summary: body.join('\n').slice(0, 65000) };
  try {
    const { data: check } = await github.rest.checks.create({
      owner,
      repo,
      name: CHECK_NAME,
      head_sha: headSha,
      status: 'completed',
      conclusion,
      output: { ...output, annotations: annotations.slice(0, 50) },
    });
    // The API accepts at most 50 annotations per request.
    for (let i = 50; i < annotations.length; i += 50)
      await github.rest.checks.update({ owner, repo, check_run_id: check.id, output: { ...output, annotations: annotations.slice(i, i + 50) } });
  } catch (e) {
    core.warning(`Could not create the "${CHECK_NAME}" check run: ${e.message}`);
  }

  // ---- comment (only when there is something to say, or to update a previous one)
  const nothingToSay = conclusion === 'success' && detInfo.length === 0;
  if (!(nothingToSay && !existing)) {
    const resolved = !securityHigh && !suppressionAdded && existing ? ' (previous issues resolved)' : '';
    const lines = [MARKER, `🔐 **PhishFort Endpoint Auth Check** — ${headline}${resolved}`, ''];
    if (securityHigh)
      lines.push(
        `This PR changes code that may expose data or actions without proper authentication. The **${CHECK_NAME}** check is red and the PR is labelled \`${LABEL}\`. It does not block merging — a reviewer should check these first.`,
        '',
      );
    lines.push(...body);
    const llmData = llmFindings.length > 0 ? Buffer.from(JSON.stringify({ endpoints: llmFindings })).toString('base64') : '';
    lines.push(`<!-- endpoint-auth-llm:${llmData} -->`);
    const text = lines.join('\n');
    if (existing) await github.rest.issues.updateComment({ owner, repo, comment_id: existing.id, body: text });
    else await github.rest.issues.createComment({ owner, repo, issue_number, body: text });
  }

  // ---- label
  const { data: labels } = await github.rest.issues.listLabelsOnIssue({ owner, repo, issue_number });
  const hasLabel = labels.some((l) => l.name === LABEL);
  if (securityHigh && !hasLabel) await github.rest.issues.addLabels({ owner, repo, issue_number, labels: [LABEL] });
  else if (!securityHigh && hasLabel) await github.rest.issues.removeLabel({ owner, repo, issue_number, name: LABEL }).catch(() => {});

  core.info(
    `Endpoint auth: conclusion=${conclusion} (rules high=${detHigh.length}, info=${detInfo.length}, suppressed=${detSuppressed.length}; ai high=${llmHigh.length}, status=${final.llm_status})`,
  );
  return final;
};

module.exports.parseLlmOutput = parseLlmOutput;
module.exports.extractJson = extractJson;
module.exports.normalizeLlm = normalizeLlm;
module.exports.isLlmHigh = isLlmHigh;
module.exports.conclusionFor = conclusionFor;
