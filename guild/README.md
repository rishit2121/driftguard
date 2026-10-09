# DriftGuard Guild agents

| Agent | Role | Guild integrations |
|---|---|---|
| `driftguard-watcher` | Source discovery: pins repo to a SHA, inventories lockfiles, fetches the official Stripe changelog + OSV querybatch, returns SHA-256-hashed observations | `guildai~github` (read), `guildai~experimental-fetch` |
| `driftguard-remediator` | Opens the **draft** PR for a patch DriftGuard already verified (blob → tree → commit → ref → pull). No merge tool. | `guildai~github` (contents + pull requests write) |

Both are deterministic coded agents (`'use agent'`): no LLM decides which tool to call, and fetched text is never
treated as instructions.

## Deploy

```bash
npm install -g @guildai/cli
guild auth login                       # browser device flow; also configures the private npm registry
guild workspace select <your-workspace>
# Guild UI > Credentials > GitHub > authorize the Guild GitHub App on rishit2121/driftguard-demo-monorepo only
guild workspace variable set DRIFTGUARD_ALLOWED_REPO=rishit2121/driftguard-demo-monorepo

for a in driftguard-watcher driftguard-remediator; do
  (cd $a && guild agent init --owner <you> --name $a --template BLANK && npm install && npm run build \
     && guild agent save --message "v1" --wait --publish)
done

# Scheduled watcher (daily) + manual runs from the DriftGuard UI/CLI
guild trigger create --type time --frequency DAILY --time 09:00 --agent <you>~driftguard-watcher \
  --input '{"type":"text","text":"{\"repo\":\"rishit2121/driftguard-demo-monorepo\",\"branch\":\"main\",\"stripe_changelog_urls\":[\"https://docs.stripe.com/changelog/basil/2025-03-31/deprecate-subscription-current-period-start-and-end\"]}"}'
```

Then run the platform with:

```bash
export DRIFTGUARD_PR_EXECUTOR=guild
export GUILD_REMEDIATOR_AGENT=<you>~driftguard-remediator
export GUILD_WATCHER_AGENT=<you>~driftguard-watcher
```

`driftguard/guild_bridge.py` creates sessions with `guild session create`, waits for completion and pulls the session
trace (`guild session events --mode json`) so the Guild trace is linked from the finding page and the PR.
