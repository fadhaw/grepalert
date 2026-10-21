<p align="center"><img src="docs/assets/logo.svg" width="88" height="88" alt="grepalert logo"></p>

<h1 align="center">grepalert</h1>

<p align="center"><b>Alerts from your logs in five minutes. No Loki, no Elasticsearch, no database.</b></p>

Tail a file or the pods a Kubernetes label selector picks, match a pattern, post a clean message to Slack, Teams or any webhook. Run it on one server, or manage a whole fleet from the dashboard.

📖 **Documentation: [opreklabs.github.io/grepalert](https://opreklabs.github.io/grepalert/)**

**On its own.** One agent and a rules file on the server is all it takes:

![A standalone agent: it reads rules.yaml from the server, matches a log line, pulls out values and posts the message straight to the webhook; editing rules.yaml reloads it without a restart; repeats are suppressed and summed up once](docs/assets/standalone.gif)

**With the dashboard.** Manage many agents: rules come from git, and the same alert from many servers becomes one:

![How grepalert works: rules go from git through the dashboard to every agent; an agent matches a log line, pulls values out of it and sends your message to a webhook; the same alert from many servers becomes one; repeats are suppressed](docs/assets/how-it-works.gif)

## How it works

grepalert is two small programs, each a single static file with no database and no queue:

| Program | Runs on | What it does |
|---|---|---|
| `grepalert-agent` | every server with logs | Follows log files (or Kubernetes pods), matches each line against your rules, and posts alerts to webhooks. Works on its own. |
| `grepalert-dashboard` | anywhere, optional | A web UI for many agents: groups that share one rule set (edited in the UI or synced from git), safe rule rollout, one alert across many hosts, silences, sign-in with SSO and an audit log. |

An agent needs two files:

- **`agent.yaml`**: settings of the agent itself, such as where its rules are and whether to connect to a dashboard.
- **`rules.yaml`**: what to watch (a file and a pattern) and where to send alerts (webhooks). This is the file you edit most.

```
 your logs ──► grepalert-agent ──► webhook (Slack, Teams, Discord, PagerDuty, …)
                   ▲    │
         rules     │    │ alerts (optional: through the dashboard,
                   │    ▼          to combine them across hosts)
             grepalert-dashboard ◄── rules from the UI or from GitHub/GitLab
```

## Quick start: your first alert

This takes about five minutes on Linux or macOS; Windows works the same with `grepalert-agent.exe`.

**1. Get the agent.** Download it from [Releases](https://github.com/OprekLabs/grepalert/releases); other platforms and containers are in [Install](docs/install.md).

```bash
mkdir grepalert && cd grepalert
curl -fsSL https://github.com/OprekLabs/grepalert/releases/download/v0.1.0/grepalert_0.1.0_linux_amd64.tar.gz | tar xz --strip-components=1
```

**2. Write `agent.yaml`.** This is the smallest useful one: rules from `rules.yaml` in this folder, and the agent's API on this machine only.

```yaml
rules_file: rules.yaml
listen: "127.0.0.1:9300"
```

**3. Write `rules.yaml`.** One webhook, and one rule that alerts on lines containing `ERROR` in `app.log`:

```yaml
webhooks:
  - name: chat
    url: ${WEBHOOK_URL}                      # your Slack/Teams/Mattermost incoming webhook
    template: '{"text": {{ json .Text }}}'

rules:
  - name: errors
    files: [app.log]                         # the log to watch (here: app.log in this folder)
    pattern: 'ERROR (?P<what>.+)'            # lines with ERROR; the rest of the line is captured
    severity: critical
    webhooks: [chat]
    suppress: {window: 1m, group_by: what}   # the same error at most once a minute
```

`${WEBHOOK_URL}` is read from the environment, so the URL stays out of the file. No chat webhook at hand? Use a free test URL from a request bin such as webhook.site.

**4. Run it, and write an error to the log:**

```bash
export WEBHOOK_URL=https://hooks.slack.com/services/...
./grepalert-agent -config agent.yaml
```

```bash
echo "2026-10-15 12:00:00 ERROR payment gateway timeout" >> app.log
```

Within a couple of seconds your chat shows:

> CRITICAL [your-host] errors matched in app.log: 2026-10-15 12:00:00 ERROR payment gateway timeout

**5. Change the rules while it runs.** Edit `rules.yaml` and save:
- **Applied automatically:** the agent applies the new version within 10 seconds, with no restart, and logs `rules applied`.
- **Mistakes are rejected:** a file with a mistake is not applied. The agent logs why and keeps running the previous rules.
- **Check before saving:** run the same check yourself:

```bash
./grepalert-agent -check rules.yaml
```

From here:
- **[Writing rules](docs/rules.md):** your own message built from the captured values (*"Critical, DS1 is suspended"*), suppression, and alerts when a line stops appearing.
- **[Configuration reference](docs/config-agent.md):** every setting of `agent.yaml`.
- **[Install](docs/install.md):** running the agent as a service.

## Add the dashboard

With more than a few servers, the dashboard manages their rules in one place. It also turns the same alert from many servers into one.

**1. Start the dashboard.** It is in the same download. Its smallest useful `dashboard.yaml` has an admin account and an enrollment token, which agents use to join:

```yaml
listen: ":9400"
data_file: dashboard-data.json
auth:
  username: admin
  password: ${GREPALERT_DASHBOARD_PASSWORD}
enrollment_token: ${GREPALERT_ENROLL_TOKEN}
```

```bash
export GREPALERT_DASHBOARD_PASSWORD=change-me-please GREPALERT_ENROLL_TOKEN=$(openssl rand -hex 16)
./grepalert-dashboard -config dashboard.yaml
```

Open http://localhost:9400 and sign in as `admin`.

**2. Connect the agent.** Give the agent a `dashboard` section and a label, then restart it with the same `GREPALERT_ENROLL_TOKEN` in its environment:

```yaml
rules_file: rules.yaml
labels:
  role: demo
dashboard:
  url: http://localhost:9400
  enrollment_token: ${GREPALERT_ENROLL_TOKEN}
```

The agent **connects out** to the dashboard, so servers need no open port. It appears under **All agents**.

**3. Manage its rules from a group:**
1. Click **New group**, set *Auto-add agents with labels* to `role=demo`, and start from *A copy of the agent's current rules*.
2. Every agent labelled `role=demo` (now and later) joins the group and runs its rules.
3. Edit the rules in the group's **Rules** tab, or keep them in GitHub or GitLab and let the group sync them.

**4. Change rules safely.**
- **[Staged rollout](docs/rollout.md):** a change reaches a few agents first, and stops by itself if they start alerting far more than the others.
- **Dry run:** replays the last hour of real logs through draft rules.
- **History:** every version is kept, with one-click rollback.

![Staged rollout: a rule change goes to one agent first, is watched, then goes to half of the agents and then all; a bad change makes its first agent alert far more than the others, so the rollout stops, every agent goes back, and ops is told](docs/assets/staged-rollout.gif)

**If the dashboard goes down,** agents keep alerting. They work from the rules, read positions and silences on their own disk, even across a restart:

![The dashboard goes down: the agent keeps running from its disk and, after 15 seconds, alerts the webhook directly while silenced rules stay silent; the agent restarts during the outage, resumes from its saved position so a line written meanwhile still alerts; the dashboard comes back and the agent reconnects on its own](docs/assets/dashboard-down.gif)

## Try everything with Docker Compose

A complete demo includes:
- the dashboard
- three agents that join a group by label
- rules from a stand-in git repository, with staged rollout
- a log generator, and a page that shows the alerts as they arrive

```bash
git clone https://github.com/OprekLabs/grepalert.git
cd grepalert/examples/compose
docker compose up -d --build
```

Open http://localhost:9400 (`admin` / `demo`); alerts arrive at http://localhost:9599. The [demo walkthrough](docs/demo.md) shows what to try.

## Install

| Way | How |
|---|---|
| **Binaries** | Linux, macOS and Windows (amd64/arm64) on [Releases](https://github.com/OprekLabs/grepalert/releases), with a systemd unit in `examples/` |
| **Containers** | `ghcr.io/opreklabs/grepalert-agent` and `ghcr.io/opreklabs/grepalert-dashboard`, configured with environment variables |
| **Kubernetes** | Follow the pods a label selector picks, or log files on a shared volume: [Kubernetes](docs/kubernetes.md) |
| **From source** | `make build` (Go 1.26+, and Node.js 20+ for the dashboard's UI) |

All of it in detail: [Install](docs/install.md).

## Documentation

Also on the documentation site, with search: [opreklabs.github.io/grepalert](https://opreklabs.github.io/grepalert/). Read in this order, or jump to what you need.

**Setting up**
1. [Install](docs/install.md): binaries, running the agent as a service, containers, building from source.
2. **Configuration reference:** every setting, with a complete annotated example of each file:
   - [agent.yaml](docs/config-agent.md)
   - [rules.yaml](docs/config-rules.md)
   - [dashboard.yaml](docs/config-dashboard.md)

**Using it**

3. [Writing rules](docs/rules.md): patterns and captured values, your own alert messages, suppression, absence rules, testing rules.
4. [Rule cookbook](docs/cookbook.md): complete, tested recipes: access logs, JSON logs, Java exceptions, thresholds, SSH brute force, Opsgenie and Slack Block Kit payloads.
5. [Running agents](docs/agents.md): standalone or connected, enrollment and labels, changing rules, files on disk, rotation and restarts, the dashboard being down.
6. [Dashboard and groups](docs/dashboard.md): agents, groups, rules from the UI or GitHub/GitLab.
7. [Safe rule rollout](docs/rollout.md): versions and rollback, staged rollout, dry run, local rules per machine.
8. [Fleet alerting](docs/fleet-alerting.md): one alert across many hosts, silences, agent-down alerts.
9. [Kubernetes](docs/kubernetes.md): pod logs by label selector, or log files on a volume.
10. [Sign-in, roles and security](docs/security.md): SSO, roles, audit log, hardening.

**Reference**

11. [Agent API](docs/api.md)
12. [Memory and performance](docs/performance.md)
13. [Tested behaviour](docs/testing.md): every edge case that is tested, such as log rotation, restarts, Kubernetes streams and the dashboard going down.
14. [Demo walkthrough](docs/demo.md)

**Project**

15. [Development](docs/development.md)
16. [Releasing](docs/releasing.md)
17. [Release notes](docs/releases/)

## License

Apache License 2.0. See [LICENSE](LICENSE).
