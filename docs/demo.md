[← Documentation](../README.md#documentation) · Previous: [Tested behaviour](testing.md) · Next: [Development →](development.md)

# Try it with Docker Compose

```bash
cd examples/compose
docker compose up -d --build
```

| URL | What it is |
|---|---|
| http://localhost:9400 | Dashboard (`admin` / `demo`, set in `.env`) |
| http://localhost:9599 | Demo webhook sink: alerts as they arrive (auto-refresh) |

The demo stack runs:

- **loggen** writes `app.log` and `access.log` into a shared volume. It adds random errors and rotates `app.log` every ~5 minutes.
- **app-1, app-2, app-3** (`app-server-1..3`) **connect out** to the dashboard. They enroll with the token from `.env` and have the labels `role=app`, `env=demo`.
- **setup** runs once. It creates the group **app-servers**, which:
  - adds agents labelled `role=app`
  - reads its rules from [git-repo/rules.yaml](../examples/compose/git-repo/rules.yaml)
  - has staged rollout on: 1 agent → 50% → all, watching each stage for 1 minute

  It also points the ops webhook at the sink.
- **app-server-1** also has **local rules**, seeded from [config/app-server-1.local.yaml](../examples/compose/config/app-server-1.local.yaml): a `slow-requests` rule only it runs.
- **agent-2** (`edge-proxy-1`) is a **direct** agent: the dashboard connects to it. It starts with its own nginx-5xx rule.
- **webhook-sink** receives the alerts. It also serves `git-repo/` over HTTP as a stand-in for a GitHub/GitLab repository.

To walk through it:

1. **app-servers already has three agents.** They enrolled by themselves and joined by label, and they run the rules from git. Nobody entered an address.
2. **Staged rollout.** Edit `git-repo/rules.yaml`, for example change the first `window: 1m` to `2m`. Then click **Sync from git**, or wait a minute.
   - The group page shows the rollout: app servers on the new version vs the previous one, the next check, and a log.
   - One server gets the change first, then half, then all.
   - Add a noisy rule instead (`pattern: INFO`) and the rollout stops itself: every server goes back, and an ops alert arrives in the sink.
3. **Dry run.** In the group's **Rules** tab, click **Show latest from git**, then **Dry run**, to see how many alerts the rules in git would have sent in the last hour.
4. **History.** The **History** tab lists every version. **View** shows the diff, and **Roll back to this** sends a version to all servers at once.
   - Rolling back pauses git sync. Otherwise the next fetch would bring the bad version back.
   - **Sync from git** resumes it.
5. **Local rules.** Open **app-server-1 → Rules**. Its local rules are below the group's rules, and the overview marks the rule *local*.
6. **Direct agent.** **Connect agent** → URL `http://agent-2:9300`, token `demo-agent-token` → **Test connection** → **Connect**, and choose *No group*. Its own rules stay, editable under its **Rules** tab.
7. **Enrollment tokens.** Under **Agent enrollment**, create a token to see the agent config it generates.
8. **Agent down.** `docker compose stop app-3`: an agent-down alert reaches the sink after a minute, and an agent-back alert follows `docker compose start app-3`.
9. **Silences.** Under **Silences**, silence group `app-servers` for 30 minutes. Its alerts show as *silenced* under **Alert history** instead of reaching the sink.

To stop the demo:

```bash
docker compose down        # add -v to also delete logs, rules and saved positions
```

To build a single image yourself: `docker build --target agent .` or `docker build --target dashboard .`. The dashboard image builds the web UI in a Node stage first.
