#!/usr/bin/env bash
# End-to-end test of the endpoint auth gate scripts (no GitHub, no LLM).
#
# Mimics .github/workflows/endpoint-auth-required.yml: the PR branch adds vulnerable code,
# the base branch moves on in the SAME file, the checkout is the PR head, and the scan
# diffs from the merge-base. Then: endpoint-auth-scan.mjs -> endpoint-auth-report.cjs
# (mocked GitHub: check run, comment, label).
#
# Usage: security/endpoint-auth/tests/e2e.sh   (from repo root; needs node + semgrep)
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }
REPORT="$ROOT/scripts/endpoint-auth-report.cjs"
MOCK="$ROOT/security/endpoint-auth/tests/mock-report.cjs"

cd "$TMP" && git init -q -b main && git config user.email ci@example.com && git config user.name ci
mkdir -p src worker tests
cat > src/server.ts <<'TS'
export default {
  async fetch(request: Request, env: any): Promise<Response> {
    const url = new URL(request.url);
    if (url.pathname === "/health") return new Response("ok");
    return new Response("not found", { status: 404 });
  },
};
TS
printf 'name = "demo"\nmain = "src/server.ts"\nworkers_dev = false\n' > worker/wrangler.toml
git add . && git commit -qm base

# ---- PR branch: spoofable-header route + fail-open auth, drops workers_dev=false
git checkout -q -b feature
cat > src/server.ts <<'TS'
export default {
  async fetch(request: Request, env: any): Promise<Response> {
    const url = new URL(request.url);
    if (url.pathname === "/health") return new Response("ok");
    if (url.pathname === "/v1/files") {
      const who = request.headers.get("Cf-Access-Authenticated-User-Email");
      return Response.json({ who });
    }
    if (url.pathname === "/v1/admin" && !isAllowed(request, env)) return new Response("no", { status: 401 });
    return new Response("not found", { status: 404 });
  },
};
function isAllowed(request: Request, env: any): boolean {
  if (!env.ADMIN_API_KEY) {
    return true;
  }
  return request.headers.get("x-api-key") === env.ADMIN_API_KEY;
}
TS
printf 'name = "demo"\nmain = "src/server.ts"\n' > worker/wrangler.toml
echo 'const h = (r: Request) => r.headers.get("Cf-Access-Authenticated-User-Email");' > tests/server.test.ts
git add . && git commit -qm feature && HEAD_SHA=$(git rev-parse HEAD)

# ---- base moves on in the same file (must NOT be attributed to the PR)
git checkout -q main
{ printf '// header 1\n// header 2\n// header 3\n'; cat src/server.ts; } > s.tmp && mv s.tmp src/server.ts
git commit -qam "base moves" && BASE_SHA=$(git rev-parse HEAD)

# ---- workflow: checkout PR head, gate in .endpoint-auth-gate, diff from merge-base
git checkout -q --detach "$HEAD_SHA"
MB=$(git merge-base "$BASE_SHA" "$HEAD_SHA")
ln -s "$ROOT" .endpoint-auth-gate-src && RUN="$TMP/run" && mkdir -p "$RUN"
printf 'run/\n.endpoint-auth-gate-src\n' >> .git/info/exclude # gate scratch, never part of the PR
git diff --name-only "$MB" "$HEAD_SHA" > "$RUN/full-changed-files.txt" && cp "$RUN/full-changed-files.txt" "$RUN/changed-files.txt"

scan() {
  node .endpoint-auth-gate-src/scripts/endpoint-auth-scan.mjs --base "$MB" \
    --full "$RUN/full-changed-files.txt" --changed "$RUN/changed-files.txt" \
    --rules .endpoint-auth-gate-src/security/endpoint-auth/rules \
    --out "$RUN/endpoint-auth-result.json" --diff-out "$RUN/endpoint-auth-diff.patch" >/dev/null
}
scan

node -e '
const fs = require("fs");
const r = JSON.parse(fs.readFileSync(process.argv[1] + "/endpoint-auth-result.json", "utf8"));
const rules = r.findings.map(f => f.rule).sort().join(",");
const want = "access-identity-header-trusted,auth-fails-open-when-secret-unset,worker-reachable-on-workers-dev";
if (r.scanner_error) throw new Error("scanner error: " + r.scanner_error);
if (rules !== want) throw new Error("findings " + rules + " != " + want);
if (r.findings.some(f => f.file.startsWith("tests/"))) throw new Error("test file was scanned");
if (JSON.stringify(r.route_files_full) !== "[\"src/server.ts\"]") throw new Error("route detection: " + r.route_files_full);
// Line numbers must match the PR head file (annotations attach to head_sha).
const src = fs.readFileSync("src/server.ts", "utf8").split("\n");
const hdr = r.findings.find(f => f.rule === "access-identity-header-trusted");
if (hdr.line !== 6 || !/Cf-Access-Authenticated-User-Email/.test(src[hdr.line - 1])) throw new Error("line mapping off: L" + hdr.line);
' "$RUN" || fail "scan output"

# ---- report with an AI result (claude-code-action execution-file format)
cat > "$RUN/exec.json" <<'JSON'
[{"type":"result","subtype":"success","result":"```json\n{\"endpoints\":[{\"file\":\"src/server.ts\",\"line\":5,\"method\":\"GET\",\"route\":\"/v1/files\",\"auth\":\"weak\",\"sensitive\":true,\"confidence\":\"high\",\"issue\":\"spoofable header\",\"fix\":\"verify JWT\"}]}\n```"}]
JSON
OUT=$(node "$MOCK" "$REPORT" "$RUN" "$RUN/exec.json")
node -e '
const o = JSON.parse(process.argv[1]);
if (o.final.conclusion !== "failure" || o.final.security_high !== true) throw new Error("expected failure conclusion");
if (o.final.llm_status !== "ran" || o.final.llm.length !== 1) throw new Error("llm parse: " + o.final.llm_status);
for (const c of ["checks.create", "createComment", "addLabels"]) if (!o.calls.includes(c)) throw new Error("missing call " + c + " in " + o.calls);
if (o.check.name !== "Endpoint auth findings" || o.check.head_sha !== "headsha") throw new Error("check run " + JSON.stringify(o.check));
const failures = o.check.annotations.filter(a => a.annotation_level === "failure").map(a => a.path + ":" + a.start_line).sort().join(",");
if (failures !== "src/server.ts:14,src/server.ts:5,src/server.ts:6") throw new Error("annotations " + failures);
if (!o.body.includes("endpoint-auth-gate") || !o.body.includes("does not block merging")) throw new Error("comment text");
// Job summary lists every AI-assessed endpoint and the files in scope.
if (!o.summary.includes("/v1/files") || !o.summary.includes("`weak`") || !o.summary.includes("`src/server.ts`")) throw new Error("job summary: " + o.summary);
' "$OUT" || fail "report"

# ---- carry-forward: AI skipped on a later push -> previous AI findings kept from the comment
PREV=$(node -e 'const o=JSON.parse(process.argv[1]); console.log(JSON.stringify([{id:1,body:o.body,user:{login:"github-actions[bot]"}}]))' "$OUT")
OUT2=$(node "$MOCK" "$REPORT" "$RUN" none "$PREV")
node -e 'const o=JSON.parse(process.argv[1]); if (o.final.llm_status!=="not_needed+carried"||o.final.llm.length!==1) throw new Error(o.final.llm_status)' "$OUT2" || fail "carry-forward"

# ---- carry-forward still works when the gate comment is past the first page of PR comments
PREV_LONG=$(node -e 'const o=JSON.parse(process.argv[1]); const f=[...Array(120)].map((_,i)=>({id:1000+i,body:"filler "+i,user:{login:"someone"}})); console.log(JSON.stringify([...f,{id:1,body:o.body,user:{login:"github-actions[bot]"}}]))' "$OUT")
OUT2B=$(node "$MOCK" "$REPORT" "$RUN" none "$PREV_LONG")
node -e '
const o = JSON.parse(process.argv[1]);
if (o.final.llm_status !== "not_needed+carried" || o.final.llm.length !== 1) throw new Error("carried: " + o.final.llm_status);
if (!o.calls.includes("updateComment") || o.calls.includes("createComment")) throw new Error("should update the existing comment: " + o.calls);
' "$OUT2B" || fail "carry-forward past page 1"

# ---- a newly added nosemgrep suppression is honoured but surfaced (red check, warning annotation)
sed -i.bak 's|const who = request.headers.get("Cf-Access-Authenticated-User-Email");|const who = request.headers.get("Cf-Access-Authenticated-User-Email"); // nosemgrep: access-identity-header-trusted -- verified upstream|' src/server.ts && rm -f src/server.ts.bak
scan
OUT3=$(node "$MOCK" "$REPORT" "$RUN" none)
node -e '
const o = JSON.parse(process.argv[1]);
const f = o.final.deterministic.find(x => x.rule === "access-identity-header-trusted");
if (!f || !f.suppressed || !f.suppression_added) throw new Error("suppression not tracked");
if (o.final.suppression_added !== true || o.final.conclusion !== "failure") throw new Error("suppression should keep check red");
if (!o.check.annotations.some(a => a.annotation_level === "warning" && /suppressed/.test(a.title))) throw new Error("no warning annotation");
' "$OUT3" || fail "nosemgrep tracking"

# ---- a nosemgrep naming a different rule, or no rule, does not suppress; a list naming the rule does
nosem() {
  sed -i.bak -E "s|(const who = request.headers.get\(\"Cf-Access-Authenticated-User-Email\"\);).*|\1 $1|" src/server.ts && rm -f src/server.ts.bak
  scan
  node -e '
const r = require(process.argv[1] + "/endpoint-auth-result.json");
const f = r.findings.find(x => x.rule === "access-identity-header-trusted");
if (!f || String(f.suppressed) !== process.argv[2]) throw new Error(process.argv[3] + ": suppressed=" + (f && f.suppressed));
' "$RUN" "$2" "$1" || fail "nosemgrep rule match: $1"
}
nosem "// nosemgrep: some-other-rule -- unrelated" false
nosem "// nosemgrep" false
nosem "// nosemgrep: some-other-rule, access-identity-header-trusted -- verified upstream" true

# ---- clean PR: no findings, no previous comment -> green check, no comment, no label
git checkout -q -- src/server.ts worker/wrangler.toml 2>/dev/null || true
git checkout -q main && git checkout -q -b clean && echo "// docs tweak" >> src/server.ts && git commit -qam clean
MB2=$(git merge-base main HEAD); git diff --name-only "$MB2" HEAD > "$RUN/full-changed-files.txt" && cp "$RUN/full-changed-files.txt" "$RUN/changed-files.txt"
MB="$MB2" scan
OUT4=$(node "$MOCK" "$REPORT" "$RUN" none)
node -e '
const o = JSON.parse(process.argv[1]);
if (o.final.conclusion !== "success") throw new Error("expected success, got " + o.final.conclusion);
if (o.calls.includes("createComment") || o.calls.includes("addLabels")) throw new Error("should stay quiet: " + o.calls);
' "$OUT4" || fail "clean PR"

# ---- a `// ruleid:` comment alone must not hide code (only real fixtures next to a rule .yml)
git checkout -q -b evade main && cat > src/evade.ts <<'TS'
// ruleid: nothing-to-see
export function who(request: Request) {
  return request.headers.get("Cf-Access-Authenticated-User-Email");
}
TS
git add . && git commit -qm evade
MB3=$(git merge-base main HEAD); git diff --name-only "$MB3" HEAD > "$RUN/full-changed-files.txt" && cp "$RUN/full-changed-files.txt" "$RUN/changed-files.txt"
MB="$MB3" scan
node -e 'const r=require(process.argv[1]+"/endpoint-auth-result.json"); if(!r.findings.some(f=>f.file==="src/evade.ts")) throw new Error("ruleid comment hid a finding")' "$RUN" || fail "fixture-skip bypass"

# ---- route tables + route objects count as route changes (AI review triggers); outbound client calls do not
git checkout -q -b table main && mkdir -p src/api && cat > src/api/routes.js <<'JS'
export const routes = [
  ['GET', /^\/v1\/things$/, listThings],
  ['POST', /^\/v1\/things\/([^/]+)\/share$/, shareThing, { public: true }],
];
JS
cat > src/api/objroutes.js <<'JS'
export const objRoutes = [{ method: 'GET', path: '/v1/widgets', handler: listWidgets }];
JS
cat > src/api/client.js <<'JS'
export const load = (url) => fetch(url, { method: "GET", headers: {} });
export const getThing = (env, id) => apiRequest(env, { method: 'GET', path: `/v1/things/${id}` });
export const post = (body) => axios({ method: 'POST', url: '/v1/things', data: body });
JS
git add . && git commit -qm table
MB4=$(git merge-base main HEAD); git diff --name-only "$MB4" HEAD > "$RUN/full-changed-files.txt" && cp "$RUN/full-changed-files.txt" "$RUN/changed-files.txt"
MB="$MB4" scan
node -e 'const r=require(process.argv[1]+"/endpoint-auth-result.json"); const got=JSON.stringify([...r.route_files_full].sort()); if(got!=="[\"src/api/objroutes.js\",\"src/api/routes.js\"]") throw new Error("route table/object detection: "+got)' "$RUN" || fail "route table"

# ---- formatter-wrapped route-table entries (bracket, method and pattern on separate lines)
git checkout -q -b wrapped main && mkdir -p src/api && cat > src/api/routes.js <<'JS'
export const routes = [
  [
    'GET',
    /^\/v1\/clients\/([^/]+)\/things\/([^/]+)\/attachments\/([^/]+)$/,
    getAttachment,
  ],
];
JS
git add . && git commit -qm wrapped
MB5=$(git merge-base main HEAD); git diff --name-only "$MB5" HEAD > "$RUN/full-changed-files.txt" && cp "$RUN/full-changed-files.txt" "$RUN/changed-files.txt"
MB="$MB5" scan
node -e 'const r=require(process.argv[1]+"/endpoint-auth-result.json"); if(JSON.stringify(r.route_files_full)!=="[\"src/api/routes.js\"]") throw new Error("wrapped route table: "+r.route_files_full)' "$RUN" || fail "wrapped route table"

# ---- shared auth code / permission tables: any change (even deletion-only) is in scope
git checkout -q -b authbase main && mkdir -p src/lib && cat > src/lib/auth.ts <<'TS'
export function requireUser(request: Request, env: any): boolean {
  const key = request.headers.get("x-api-key");
  if (!key) return false;
  return key === env.ADMIN_API_KEY;
}
TS
printf '{ "admin": ["DELETE /v1/things/:id"] }\n' > src/policy.json
echo 'export const authors = ["a"];' > src/authors.ts
git add . && git commit -qm authbase
git checkout -q -b authpr && sed -i.bak '/if (!key) return false;/d' src/lib/auth.ts && rm -f src/lib/auth.ts.bak
printf '{ "admin": ["DELETE /v1/things/:id"], "viewer": ["DELETE /v1/things/:id"] }\n' > src/policy.json
echo 'export const authors = ["a", "b"];' > src/authors.ts
git commit -qam authpr
MB6=$(git merge-base authbase HEAD); git diff --name-only "$MB6" HEAD > "$RUN/full-changed-files.txt" && cp "$RUN/full-changed-files.txt" "$RUN/changed-files.txt"
MB="$MB6" scan
node -e '
const fs = require("fs");
const r = require(process.argv[1] + "/endpoint-auth-result.json");
const want = "[\"src/lib/auth.ts\",\"src/policy.json\"]";
if (JSON.stringify([...r.auth_files].sort()) !== want) throw new Error("auth_files: " + r.auth_files);
if (JSON.stringify([...r.route_files_full].sort()) !== want) throw new Error("route_files_full: " + r.route_files_full);
if (JSON.stringify([...r.route_files_increment].sort()) !== want) throw new Error("route_files_increment: " + r.route_files_increment);
const diff = fs.readFileSync(process.argv[1] + "/endpoint-auth-diff.patch", "utf8");
if (!diff.includes("-  if (!key) return false;") || !diff.includes("viewer")) throw new Error("auth diff missing for the AI reviewer");
' "$RUN" || fail "auth files"

echo "endpoint-auth e2e: OK"
