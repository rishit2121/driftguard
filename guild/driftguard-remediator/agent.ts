'use agent';
// DriftGuard remediator (Guild coded agent).
// Receives a patch that DriftGuard already verified (tests + Semgrep/OSV re-check) and opens a DRAFT pull request
// through Guild's GitHub integration. It has no merge/deploy tool: a human must approve and merge.
import { type Task, agent, pick, consoleTools } from '@guildai/agents-sdk';
import { gitHubTools } from '@guildai-services/guildai~github';
import { z } from 'zod';

const inputSchema = z.object({ type: z.literal('text'), text: z.string().describe('JSON: {repo, base_sha, base_branch, branch, title, body, files}') });
const outputSchema = z.object({ type: z.literal('text'), text: z.string().describe('JSON: {pr_url, number, branch, commit_sha}') });
type Input = z.infer<typeof inputSchema>;
type Output = z.infer<typeof outputSchema>;

const tools = {
  ...pick(gitHubTools, [
    'github_git_get_commit', 'github_git_create_blob', 'github_git_create_tree', 'github_git_create_commit',
    'github_git_create_ref', 'github_git_update_ref', 'github_pulls_create', 'github_pulls_list',
  ]),
  ...consoleTools,
};
type Tools = typeof tools;

async function run(input: Input, task: Task<Tools>): Promise<Output> {
  const req = JSON.parse(input.text);
  const allowed = task.env.DRIFTGUARD_ALLOWED_REPO;
  if (req.repo !== allowed) throw new Error(`refusing to write to ${req.repo}: only ${allowed} is authorized`);
  if (!String(req.branch).startsWith('driftguard/')) throw new Error('fix branches must live under driftguard/');
  const [owner, repo] = String(req.repo).split('/');

  const base = await task.tools.github_git_get_commit({ owner, repo, commit_sha: req.base_sha });
  const paths = Object.keys(req.files);
  const blobs = await task.gather(paths.filter((p) => req.files[p] !== null).map((p) =>
    task.tools.github_git_create_blob({ owner, repo, content: req.files[p], encoding: 'utf-8' })));
  let i = 0;
  const entries = paths.map((p) => req.files[p] === null
    ? { path: p, mode: '100644', type: 'blob', sha: null }
    : { path: p, mode: '100644', type: 'blob', sha: blobs[i++].sha });
  const tree = await task.tools.github_git_create_tree({ owner, repo, base_tree: base.tree.sha, tree: entries });
  const commit = await task.tools.github_git_create_commit({ owner, repo, message: req.title, tree: tree.sha, parents: [req.base_sha],
    author: { name: 'DriftGuard Bot (Guild)', email: 'driftguard-bot@users.noreply.github.com' } });
  try {
    await task.tools.github_git_create_ref({ owner, repo, ref: `refs/heads/${req.branch}`, sha: commit.sha });
  } catch {
    await task.tools.github_git_update_ref({ owner, repo, ref: `heads/${req.branch}`, sha: commit.sha, force: true });
  }
  await task.console.info(`Committed ${paths.length} files to ${req.branch} (${commit.sha})`);

  const open = await task.tools.github_pulls_list({ owner, repo, head: `${owner}:${req.branch}`, state: 'open' });
  const pr = open.length ? open[0] : await task.tools.github_pulls_create({
    owner, repo, title: req.title, head: req.branch, base: req.base_branch, body: req.body, draft: true });
  return { type: 'text', text: JSON.stringify({ pr_url: pr.html_url, number: pr.number, branch: req.branch, commit_sha: commit.sha }) };
}

export default agent({
  description: 'DriftGuard remediator: commits an already-verified patch to a driftguard/* branch and opens a draft PR (never merges)',
  inputSchema, outputSchema, tools, run,
});
