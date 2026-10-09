'use agent';
// DriftGuard source watcher (Guild coded agent).
// Pins the repo to an immutable SHA, reads lockfiles through Guild's GitHub integration, fetches the official Stripe
// changelog and OSV advisories through Guild's fetch integration, and returns hashed source observations.
// Fetched content is DATA: it is hashed and returned, never interpreted as instructions.
import { type Task, agent, pick, consoleTools } from '@guildai/agents-sdk';
import { gitHubTools } from '@guildai-services/guildai~github';
import { ExperimentalFetchTools } from '@guildai-services/guildai~experimental-fetch';
import { z } from 'zod';
import { sha256Hex } from './sha256.js';

const inputSchema = z.object({ type: z.literal('text'), text: z.string().describe('JSON: {repo, branch, stripe_changelog_urls}') });
const outputSchema = z.object({ type: z.literal('text'), text: z.string().describe('JSON watcher report') });
type Input = z.infer<typeof inputSchema>;
type Output = z.infer<typeof outputSchema>;

const tools = {
  ...pick(gitHubTools, ['github_repos_get_branch', 'github_git_get_tree', 'github_repos_get_content']),
  ...pick(ExperimentalFetchTools, ['experimental_fetch_fetch']),
  ...consoleTools,
};
type Tools = typeof tools;

const ALLOWED_HOSTS = ['docs.stripe.com', 'api.osv.dev'];
const LOCKFILES = /(^|\/)(package-lock\.json|requirements[^/]*\.txt|pom\.xml)$/;

function decode(b64: string): string {
  return new TextDecoder().decode(Uint8Array.from(atob(b64.replace(/\n/g, '')), (c) => c.charCodeAt(0)));
}

function packagesFrom(path: string, text: string) {
  const out: { ecosystem: string; name: string; version: string; manifest: string; dev: boolean }[] = [];
  if (path.endsWith('package-lock.json')) {
    const lock = JSON.parse(text);
    for (const [key, meta] of Object.entries<any>(lock.packages ?? {})) {
      if (key.startsWith('node_modules/') && meta.version) {
        out.push({ ecosystem: 'npm', name: key.split('node_modules/').pop()!, version: meta.version, manifest: path, dev: !!meta.dev });
      }
    }
  } else if (path.endsWith('.txt')) {
    for (const line of text.split('\n')) {
      const m = line.match(/^\s*([A-Za-z0-9_.\-]+)\s*==\s*([^\s;#]+)/); // exact pins only; ranges are unverified
      if (m) out.push({ ecosystem: 'PyPI', name: m[1].toLowerCase(), version: m[2], manifest: path, dev: path.includes('dev') });
    }
  } else if (path.endsWith('pom.xml')) {
    const props: Record<string, string> = {};
    for (const m of text.matchAll(/<([\w.]+)>([^<]+)<\/\1>/g)) props[m[1]] = m[2];
    for (const m of text.matchAll(/<dependency>\s*<groupId>([^<]+)<\/groupId>\s*<artifactId>([^<]+)<\/artifactId>\s*<version>([^<]+)<\/version>/g)) {
      const version = m[3].replace(/\$\{([^}]+)\}/g, (_, k) => props[k] ?? _);
      if (!version.includes('${')) out.push({ ecosystem: 'Maven', name: `${m[1]}:${m[2]}`, version, manifest: path, dev: false });
    }
  }
  return out;
}

type Pkg = ReturnType<typeof packagesFrom>[number];

function osvQuery(packages: Pkg[]) {
  return { queries: packages.map((p) => ({ package: { ecosystem: p.ecosystem, name: p.name }, version: p.version })) };
}

function affectedPackages(json: unknown, packages: Pkg[]) {
  const results = (json as { results?: { vulns?: { id: string }[] }[] } | undefined)?.results ?? [];
  return results
    .map((r, i) => Object.assign({}, packages[i], { vulns: (r.vulns ?? []).map((v) => v.id) }))
    .filter((r) => r.vulns.length > 0);
}

function observation(provider: string, url: string, status: number, body: unknown) {
  const text = typeof body === 'string' ? body : JSON.stringify(body);
  return { provider, url, status, sha256: sha256Hex(text), bytes: text.length, fetched_at: new Date().toISOString() };
}

function lockfilePaths(tree: { tree?: { type?: string; path?: string }[] }) {
  return (tree.tree ?? [])
    .filter((n) => n.type === 'blob' && LOCKFILES.test(n.path ?? '') && !(n.path ?? '').includes('node_modules/'))
    .map((n) => n.path as string);
}

function allowedChangelogUrls(urls: string[] | undefined) {
  return (urls ?? []).filter((u) => ALLOWED_HOSTS.includes(new URL(u).hostname));
}

function report(req: { repo: string; branch: string }, sha: string, manifests: string[], packages: Pkg[], osv: unknown[], sources: unknown[]) {
  return JSON.stringify({ repo: req.repo, branch: req.branch, commit_sha: sha, manifests, package_count: packages.length,
    affected_packages: osv, sources });
}

// Chat sessions may wrap the prompt with a preamble; the request is the outermost JSON object in the text.
function parseRequest(text: string) {
  const start = text.indexOf('{');
  const end = text.lastIndexOf('}');
  if (start < 0 || end < start) throw new Error('expected a JSON request in the prompt');
  return JSON.parse(text.slice(start, end + 1));
}

async function run(input: Input, task: Task<Tools>): Promise<Output> {
  const req = parseRequest(input.text);
  const [owner, repo] = String(req.repo).split('/');
  const branch = await task.tools.github_repos_get_branch({ owner, repo, branch: req.branch ?? 'main' });
  const sha: string = branch.commit.sha;
  await task.console.info(`Pinned ${req.repo}@${req.branch} to ${sha}`);

  const tree = await task.tools.github_git_get_tree({ owner, repo, tree_sha: sha, recursive: 'true' });
  const manifests = lockfilePaths(tree as never);
  const contents = await task.gather(manifests.map((path) => task.tools.github_repos_get_content({ owner, repo, path, ref: sha })));
  const packages = contents.flatMap((c: any, i: number) => packagesFrom(manifests[i], decode(c.content)));

  const sources: unknown[] = [];
  for (const url of allowedChangelogUrls(req.stripe_changelog_urls)) {
    const res = await task.tools.experimental_fetch_fetch({ url: url + '.md', method: 'GET', timeout_seconds: 20 });
    sources.push(observation('stripe', url, res.status_code, res.text ?? res.json));
  }
  const osvRes = await task.tools.experimental_fetch_fetch({
    url: 'https://api.osv.dev/v1/querybatch', method: 'POST', timeout_seconds: 30, data: osvQuery(packages),
  });
  const osv = affectedPackages(osvRes.json, packages);
  sources.push(observation('osv', 'https://api.osv.dev/v1/querybatch', osvRes.status_code, osvRes.json));

  await task.console.info(`${packages.length} resolved packages, ${osv.length} with advisories`);
  return { type: 'text', text: report(req, sha, manifests, packages, osv, sources) };
}

export default agent({
  identifier: 'driftguard-watcher',
  description: 'DriftGuard watcher: pins a repo to a commit SHA, inventories lockfiles, fetches official changelogs and OSV advisories, returns hashed observations',
  inputSchema, outputSchema, tools, run,
});
