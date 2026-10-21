[← Documentation](../README.md#documentation) · Previous: [Install](install.md) · Next: [rules.yaml reference →](config-rules.md)

# agent.yaml reference

`agent.yaml` holds the settings of the agent itself: its name, where its rules are, whether it connects to a dashboard, and how it reads files. What to watch and where to send alerts is in a separate file, [rules.yaml](config-rules.md).

```bash
grepalert-agent -config /etc/grepalert/agent.yaml
```

Every setting is optional. The smallest useful file is two lines (see the [quick start](../README.md#quick-start-your-first-alert)).

**Environment variables:** `$VAR` and `${VAR}` are replaced with environment variables when the file is loaded, so tokens can stay out of it. Durations are written like `500ms`, `10s`, `5m` or `1h`; sizes like `64MiB`.

## Complete example

Every setting, with its default ([examples/agent.yaml](../examples/agent.yaml)):

```yaml
# grepalert agent configuration: every setting, with its default.
# Reference: docs/config-agent.md
#
#   grepalert-agent -config /etc/grepalert/agent.yaml
#
# $VAR and ${VAR} are replaced with environment variables when this file is
# loaded, so tokens can stay out of it. Durations look like 500ms, 10s, 5m.

# --- Identity ------------------------------------------------------------
name: web-01                    # default: the hostname. Shown in alerts and the dashboard.
labels:                         # optional. Dashboard groups can add agents by label.
  role: web
  env: prod

# --- Rules ---------------------------------------------------------------
# What to watch and where to send alerts (see examples/rules.yaml). Edits are
# applied without a restart; a dashboard group overwrites this file with its
# own rules.
rules_file: /etc/grepalert/rules.yaml      # default: rules.yaml in the working directory
# Extra rules for this machine only, on top of rules_file. Groups never touch
# this file. Default: rules.local.yaml next to rules_file; "off" disables.
# local_rules_file: /etc/grepalert/rules.local.yaml

# --- Dashboard (optional) ------------------------------------------------
# Without this section the agent runs standalone. With it, the agent connects
# OUT to the dashboard (no inbound port needed) and can be managed there.
# dashboard:
#   url: https://grepalert.example.com
#   enrollment_token: ${GREPALERT_ENROLL_TOKEN}  # used once, at first start
#   ca_file: /etc/grepalert/ca.pem              # optional: private CA of the dashboard
#   insecure_skip_verify: false                 # skip TLS checks (testing only)
#   fallback_after: 15s                         # dashboard unreachable this long: send alerts directly
# Where an enrolled agent keeps its credential. Default: next to rules_file.
# identity_file: /var/lib/grepalert/grepalert.identity.json

# --- The agent's own API -------------------------------------------------
# Used by a dashboard that connects IN to the agent ("Connect agent"), and by
# scripts. Default ":9300", or "off" when dashboard.url is set.
listen: "127.0.0.1:9300"
token: ${GREPALERT_AGENT_TOKEN}           # Bearer token for the API; empty = no authentication
# tls_cert: /etc/grepalert/agent.crt      # serve the API over HTTPS
# tls_key: /etc/grepalert/agent.key

# --- Reading files -------------------------------------------------------
start_from: end                 # end | beginning: where to start in files that have no saved position
poll_interval: 500ms            # how often busy files are checked for new lines
idle_poll_interval: 2s          # idle files back off to this (saves CPU with many files)
read_workers: 4                 # files read in parallel; also caps the CPU cores used to catch up
rescan_interval: 10s            # how often globs are re-scanned and rules files re-read
max_line_bytes: 16384           # longer lines are cut, never buffered whole

# --- Saved read positions ------------------------------------------------
# A restart resumes where the agent stopped. Default: grepalert.state.json
# next to rules_file; "off" disables.
# state_file: /var/lib/grepalert/grepalert.state.json
state_interval: 5s              # how often positions are saved (also on shutdown)

# --- Sending alerts ------------------------------------------------------
queue_size: 1000                # alerts waiting for delivery; when full, new ones are dropped and counted
workers: 2                      # webhook deliveries in parallel
retries: 2                      # retries of a failed delivery

# --- Kubernetes (only for rules with a `kubernetes:` source) -------------
# kubernetes:
#   kubeconfig: /etc/grepalert/kubeconfig   # default: the pod's service account (in-cluster)
#   context: prod                           # default: the kubeconfig's current-context
#   max_streams: 200                        # most container logs followed at once

# --- Limits --------------------------------------------------------------
event_buffer: 500               # recent events kept for the dashboard
memory_limit: 64MiB             # soft memory limit of the Go runtime

# --- Logging -------------------------------------------------------------
log_level: info                 # debug | info | warn | error; debug also logs every line a rule matches
```

## Settings

### Identity

| Setting | Default | Meaning |
|---|---|---|
| `name` | the hostname | Shown in alerts and in the dashboard. Must be unique among the agents of a dashboard. |
| `labels` | none | Key/value pairs, e.g. `role: web`. Dashboard groups can add every agent with given labels. Every agent also gets `os`. |

### Rules

| Setting | Default | Meaning |
|---|---|---|
| `rules_file` | `rules.yaml` | The [rules](config-rules.md) to run. Checked every `rescan_interval` and applied without a restart; an invalid version is rejected and the previous rules keep running. A dashboard group overwrites this file with its own rules. |
| `local_rules_file` | `rules.local.yaml` next to `rules_file` | Extra rules for this machine only, run on top of `rules_file`. They may use its webhooks, but may only add rules. Groups never touch this file. `off` disables it. |

### Dashboard

Without a `dashboard` section the agent runs on its own. With one, it connects **out** to the dashboard: it enrolls once, then keeps one HTTPS connection open, so servers need no inbound port. See [Running agents](agents.md#connected-to-a-dashboard).

| Setting | Default | Meaning |
|---|---|---|
| `dashboard.url` | none | The dashboard's address, e.g. `https://grepalert.example.com`. |
| `dashboard.enrollment_token` | none | Used once, at the first start, to enroll. The agent then has its own credential (see `identity_file`). |
| `dashboard.ca_file` | system CAs | A PEM file with the CA of the dashboard's certificate, for private CAs. |
| `dashboard.insecure_skip_verify` | `false` | Skip TLS certificate checks. For testing only. |
| `dashboard.fallback_after` | `15s` | When the dashboard can't be reached for this long, the agent sends alerts to the webhooks itself. |
| `identity_file` | `grepalert.identity.json` next to `rules_file` | Where an enrolled agent keeps its credential (mode 0600). |

HTTP proxies are used from `HTTPS_PROXY` / `NO_PROXY`.

### The agent's own API

The agent can serve a small [HTTP API](api.md): status, rules, test a line. A dashboard uses it when it connects **in** to the agent ("Connect agent" with an address), and scripts can use it too.

| Setting | Default | Meaning |
|---|---|---|
| `listen` | `:9300`, or `off` when `dashboard.url` is set | Address of the API. `127.0.0.1:9300` keeps it on this machine; `off` turns it off. |
| `token` | none | Bearer token the API requires. Without one, anyone who can reach the API can change the rules: set it whenever `listen` is not local. |
| `tls_cert`, `tls_key` | none | Serve the API over HTTPS with this certificate and key (PEM files). |

### Reading files

| Setting | Default | Meaning |
|---|---|---|
| `start_from` | `end` | Where to start in a file the agent has no saved position for: `end` (only new lines, so old history doesn't fire alerts) or `beginning`. Files that appear later are always read from their start. |
| `poll_interval` | `500ms` | How often a busy file is checked for new lines. |
| `idle_poll_interval` | `2s` | Files without new data back off to this, which saves CPU with many files. At least `poll_interval`. |
| `read_workers` | `4` | Files read in parallel. Also caps the CPU cores used to catch up on a backlog. |
| `rescan_interval` | `10s` | How often globs (`*.log`) are re-scanned for new files, and the rules files are re-read. |
| `max_line_bytes` | `16384` | Longer lines are cut to this length, never buffered whole. |

### Saved read positions

| Setting | Default | Meaning |
|---|---|---|
| `state_file` | `grepalert.state.json` next to `rules_file` | Where the read position of every file (and Kubernetes container) is saved, so a restart resumes where the agent stopped. `off` disables it. |
| `state_interval` | `5s` | How often positions are saved; they are also saved on shutdown. After a crash, at most this much is read twice. |

### Sending alerts

| Setting | Default | Meaning |
|---|---|---|
| `queue_size` | `1000` | Alerts waiting for delivery. When full, new alerts are dropped and counted (shown as *dropped* in the dashboard), so a slow webhook can't make the agent grow. |
| `workers` | `2` | Webhook deliveries in parallel. |
| `retries` | `2` | Retries of a failed delivery, with backoff. |

### Kubernetes

Only used by rules with a [`kubernetes:` source](kubernetes.md).

| Setting | Default | Meaning |
|---|---|---|
| `kubernetes.kubeconfig` | the pod's service account | A kubeconfig file, to reach a cluster from outside it. Token and client-certificate logins are supported. |
| `kubernetes.context` | the kubeconfig's current-context | Which context of the kubeconfig to use. |
| `kubernetes.max_streams` | `200` | The most container logs followed at once. |

### Limits

| Setting | Default | Meaning |
|---|---|---|
| `event_buffer` | `500` | Recent events (alerts, rule changes, errors) kept for the dashboard's Events tab. |
| `memory_limit` | `64MiB` | Soft memory limit of the Go runtime: it collects garbage harder as memory nears this. See [Memory and performance](performance.md). |

### Logging

| Setting | Default | Meaning |
|---|---|---|
| `log_level` | `info` | `debug`, `info`, `warn` or `error`. At `debug` the agent also logs every line a rule matches, with its captured values and what happened to it: sent as an alert, suppressed, or excluded. See [Debugging rules](rules.md#debugging-rules). |

## Command line

| Flag | Meaning |
|---|---|
| `-config <file>` | The agent.yaml to use (default `agent.yaml`). |
| `-check <rules file>` | Validate a rules file and exit: `OK: …` and exit code 0, or the errors and exit code 1. Use it in CI on your rules repository. |
| `-debug` | Log every line a rule matches, like `log_level: debug`. |
| `-version` | Print the version and exit. |
