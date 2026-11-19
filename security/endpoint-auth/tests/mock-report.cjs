// Runs scripts/endpoint-auth-report.cjs against a mocked GitHub client.
// Usage: node mock-report.cjs <report.cjs> <workDir> <llm-exec-file|none> [existing-comments-json]
// Prints one JSON line: {final, outputs, calls, body, check}
const report = require(process.argv[2]);
const workDir = process.argv[3];
const exec = process.argv[4];
const comments = JSON.parse(process.argv[5] || '[]');
let labels = [];
const calls = [];
let check = null;
const github = {
  rest: {
    issues: {
      listComments: async () => ({ data: comments }),
      createComment: async (a) => {
        calls.push('createComment');
        comments.push({ id: 1, body: a.body, user: { login: 'github-actions[bot]' } });
      },
      updateComment: async (a) => {
        calls.push('updateComment');
        comments[0].body = a.body;
      },
      listLabelsOnIssue: async () => ({ data: labels }),
      addLabels: async (a) => {
        calls.push('addLabels');
        labels.push(...a.labels.map((name) => ({ name })));
      },
      removeLabel: async (a) => {
        calls.push('removeLabel');
        labels = labels.filter((l) => l.name !== a.name);
      },
    },
    checks: {
      create: async (a) => {
        calls.push('checks.create');
        check = { name: a.name, head_sha: a.head_sha, conclusion: a.conclusion, title: a.output.title, annotations: a.output.annotations };
        return { data: { id: 99 } };
      },
      update: async (a) => {
        calls.push('checks.update');
        check.annotations.push(...a.output.annotations);
        return { data: {} };
      },
    },
  },
};
const context = { sha: 'mergecommit', repo: { owner: 'acme', repo: 'demo' }, payload: { pull_request: { number: 1, head: { sha: 'headsha' } } } };
const outputs = {};
const core = { setOutput: (k, v) => (outputs[k] = v), info: () => {}, warning: () => {} };
(async () => {
  const final = await report({ github, context, core, workDir, llmExecutionFile: exec, llmRan: exec !== 'none', scanOutcome: 'success' });
  console.log(JSON.stringify({ final, outputs, calls, body: comments[0]?.body ?? '', check }));
})();
