[← Documentation](../README.md#documentation) · Previous: [dashboard.yaml](config-dashboard.md) · Next: [Rule cookbook →](cookbook.md)

# Writing rules

This guide goes from a first rule to custom messages, suppression and absence rules. Every setting is listed in the [rules.yaml reference](config-rules.md).

## A rule has three parts

```yaml
webhooks:                                  # 1. where alerts go
  - name: chat
    url: ${CHAT_WEBHOOK_URL}
    template: '{"text": {{ json .Text }}}'

rules:
  - name: payment-errors
    files: [/var/log/shop/app.log]         # 2. what to read
    pattern: 'ERROR .*payment'             # 3. which lines alert
    severity: critical
    webhooks: [chat]
```

1. **A webhook:** an incoming-webhook URL of Slack, Teams, Mattermost, Google Chat, Discord, PagerDuty, or any HTTP endpoint. `${CHAT_WEBHOOK_URL}` is read from the agent's environment, so the URL stays out of the file and out of git.
2. **What to read:**
   - **Files**, including globs such as `/var/log/shop/*.log`. New files are picked up within 10 seconds, and rotated files are followed.
   - **Kubernetes pods:** a [`kubernetes:` source](kubernetes.md) instead of `files`.
3. **A pattern:** a regular expression ([RE2 syntax](https://github.com/google/re2/wiki/Syntax)). Every line that matches alerts. Add `exclude:` for lines that must never alert, e.g. `exclude: 'GET /healthz'`.

Save the file and the agent applies it within 10 seconds, with no restart.

## Patterns that are fast and precise

- **Anchor on literal text.** `ERROR code=\w+` is checked with a fast substring search first; a rule with no literal text, such as `\d{3}ms$`, runs the full regexp on every line. See [performance](performance.md).
- **Case-insensitive:** start with `(?i)`, e.g. `(?i)exception|panic`.
- **Quote patterns with single quotes** in YAML, so backslashes stay as they are: `pattern: '" (?P<status>5\d\d) '`.

## Capture values, and write your own message

Name parts of the line with `(?P<name>...)`. Each captured value is available to the webhook's template as `.Groups.name`, and can drive suppression (next section).

For the line `Datasource DS1 is suspended because the pool is exhausted`:

```yaml
webhooks:
  - name: chat
    url: ${CHAT_WEBHOOK_URL}
    template: '{"text": {{ json (printf "%s, %s is suspended" (title .Severity) .Groups.datasource) }}}'

rules:
  - name: datasource-suspended
    files: [/var/log/app/app.log]
    pattern: 'Datasource (?P<datasource>\S+) is suspended because (?P<reason>.+)'
    severity: critical
    webhooks: [chat]
```

The webhook receives `{"text": "Critical, DS1 is suspended"}`, and `.Groups.reason` holds `the pool is exhausted`.

**Try it before deploying.** In the dashboard, open **Tools → Rule playground**, paste your rules and some log lines. As you type, it shows:
- which line matched which rule
- what each `(?P<name>...)` captured
- whether each match alerts, is suppressed or is excluded
- the exact body each webhook would receive

### Webhook payload

**Without a `template`,** the agent POSTs the whole alert as JSON:

```json
{"kind":"match","agent":"web-01","host":"web-01","rule":"nginx-5xx","severity":"critical",
 "labels":{"team":"web"},"file":"/var/log/nginx/access.log","line":"…","groups":{"status":"502"},
 "group_key":"502","time":"2026-10-12T20:41:37+07:00","suppressed":0,"text":"CRITICAL [web-01] nginx-5xx matched in …"}
```

**With a `template`** (a Go [text/template](https://pkg.go.dev/text/template)), you build the body from these fields:

| Field | Meaning |
|---|---|
| `.Text` | a ready-made message, e.g. `CRITICAL [web-01] nginx-5xx matched in /var/log/nginx/access.log: …` |
| `.Kind` | `match`, `summary` (a suppression window closed), `absent`, `recovered`; from a dashboard also `fleet_summary`, `agent_down`, `agent_up`, `rollout` |
| `.Rule`, `.Description`, `.Severity`, `.Labels` | from the rule |
| `.Agent`, `.Host`, `.File`, `.Line`, `.Time` | where and when it matched |
| `.Groups` | the values the pattern captured, e.g. `.Groups.status` |
| `.GroupKey`, `.Suppressed` | the `group_by` value, and how many matches a summary stands for |
| `.Group`, `.Hosts`, `.HostCount`, `.Via`, `.ID` | set by a dashboard: the agent's group, the hosts an alert covers, `dashboard` or `agent`, and an ID to drop duplicates |

**Helpers:**

| Helper | Does |
|---|---|
| `json` | a safely quoted JSON string; use it for every value inside a JSON body |
| `upper`, `lower` | change case |
| `title` | capitalize the first letter: `critical` → `Critical` |
| `trunc N` | cut to N characters, e.g. `{{ trunc 1900 .Text }}` for Discord |
| `printf` | Go's formatting, e.g. `printf "%s on %s" .Rule .Host` |

To word summaries differently: `{{ if eq .Kind "summary" }}…{{ else }}…{{ end }}`.

## Suppression: don't alert on every line

Without a `suppress` block, every matching line sends an alert. An error that repeats a thousand times would send a thousand messages. With one:

```yaml
    suppress:
      window: 5m          # per 5 minutes...
      max_alerts: 1       # ...send at most 1 alert...
      group_by: code      # ...for each distinct value of the "code" capture
```

- **Within a window,** matches after `max_alerts` are counted, not sent.
- **`group_by`** gives each captured value its own window, so a `DB_TIMEOUT` doesn't hide a `PAYMENT_DECLINED`.
- **When a window closes** after holding matches back, one summary follows: *"49 more matches were suppressed (DB_TIMEOUT). Last: …"*. It renders with the same template, using the captured values of the last held-back line. Turn it off with `summary: false`.
- **Across servers:** agents connected to a dashboard also get [fleet alerting](fleet-alerting.md), so the same alert from 50 servers becomes one message.

## Absence rules: alert when something stops

Error rules can't catch an app that hangs, or a job that stopped running: those write nothing. An absence rule alerts when an expected line has **not** appeared for a while:

```yaml
  - name: no-heartbeat
    files: [/var/log/myapp/app.log]
    absent: 'heartbeat OK'    # instead of pattern
    for: 10m
    severity: critical
    webhooks: [chat]
```

It alerts once after `for` passes without a matching line, and once more ("recovered") when the line shows up again. A newly loaded rule waits its full `for` before it can fire.

## Rules for one machine: local rules

When a [dashboard group](dashboard.md) manages an agent's rules, the agent can still have extra rules of its own, for example for a file only that server has.
- **Where:** put them in `rules.local.yaml` next to the rules file, or edit them in the dashboard (agent → Rules → Local rules).
- **What they may do:** they may use the group's webhooks, but may only **add** rules.
- **Groups never touch them.**

## Test before you deploy

| Tool | Where | Checks |
|---|---|---|
| `grepalert-agent -check rules.yaml` | command line, CI | the file is valid; exit code 1 and every problem otherwise |
| Rule playground | dashboard → Tools | what pasted lines match and capture, and the exact webhook bodies |
| Test a line | dashboard → agent → Test a line | which of an agent's running rules match a line |
| Dry run | dashboard → group → Rules | how many alerts draft rules would have sent on the last hours of real logs ([Safe rule rollout](rollout.md)) |
| Debug log | the agent's own log | every line a running rule matches, and whether it alerted, was suppressed or excluded ([below](#debugging-rules)) |

### Debugging rules

When a rule doesn't alert as expected on a running agent, turn on debug logging: `log_level: debug` in [agent.yaml](config-agent.md#logging), `GREPALERT_LOG_LEVEL=debug` for the container image, or `grepalert-agent -debug`. The agent then logs every line a rule matches, with what it captured and what happened next:

```
level=DEBUG msg="rule matched, sending alert" rule=deploy-failed file=/var/log/app/app.log line="ERROR Failed to deploy \"billing\"" groups=map[app:billing]
level=DEBUG msg="rule matched, alert suppressed" rule=deploy-failed file=/var/log/app/app.log line="ERROR Failed to deploy \"billing\"" groups=map[app:billing] suppressed_in_window=1
level=DEBUG msg="rule matched, but the line is excluded" rule=deploy-failed file=/var/log/app/app.log line="ERROR Failed to deploy \"smoke-test\""
```

- **No `rule matched` line at all:** the pattern doesn't match the line as the agent reads it, or the agent doesn't follow the file. Check the `following file` lines it logs at start ([Which files an agent follows](agents.md#which-files-an-agent-follows)), and try the line in the Rule playground.
- **`alert suppressed`:** the rule's `suppress` window already sent its alerts; the rest come as one summary when the window ends.
- **`excluded`:** the line also matches the rule's `exclude`.

Lines are cut at 1 KB in the log. Debug logging writes a line for every match, so turn it off again on busy logs; at the default level, matching costs nothing extra.

More examples: the [Rule cookbook](cookbook.md), and [examples/rules.yaml](../examples/rules.yaml).
