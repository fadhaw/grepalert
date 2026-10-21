[← Documentation](../README.md#documentation) · Next: [agent.yaml reference →](config-agent.md)

# Install

| | Agent | Dashboard |
|---|---|---|
| [Binaries](#binaries) | Linux, macOS, Windows | Linux, macOS, Windows |
| [As a Linux service](#run-the-agent-as-a-service-systemd) | systemd unit included | any process manager |
| [Containers](#containers) | `ghcr.io/fadhaw/grepalert-agent` | `ghcr.io/fadhaw/grepalert-dashboard` |
| [Kubernetes](kubernetes.md) | pod logs, or files on a volume | as a container |
| [From source](#from-source) | Go 1.26+ | Go 1.26+, Node.js 20+ |

## Binaries

Each archive on [Releases](https://github.com/fadhaw/grepalert/releases) holds:
- `grepalert-agent` and `grepalert-dashboard`
- the README, release notes and license
- `examples/`: complete `agent.yaml`, `rules.yaml` and `dashboard.yaml`, and a systemd unit

| System | Archive |
|---|---|
| Linux, Intel/AMD | `grepalert_<version>_linux_amd64.tar.gz` |
| Linux, ARM (Graviton, Raspberry Pi 4/5) | `grepalert_<version>_linux_arm64.tar.gz` |
| macOS, Apple silicon | `grepalert_<version>_darwin_arm64.tar.gz` |
| macOS, Intel | `grepalert_<version>_darwin_amd64.tar.gz` |
| Windows | `grepalert_<version>_windows_amd64.zip` |

```bash
curl -fsSLO https://github.com/fadhaw/grepalert/releases/download/v0.1.0/grepalert_0.1.0_linux_amd64.tar.gz
curl -fsSLO https://github.com/fadhaw/grepalert/releases/download/v0.1.0/checksums.txt
sha256sum --check --ignore-missing checksums.txt
tar xzf grepalert_0.1.0_linux_amd64.tar.gz && cd grepalert_0.1.0_linux_amd64
./grepalert-agent -version
```

The programs are static: no runtime, libraries or installer needed. The dashboard's web UI is built into its binary.

## Run the agent as a service (systemd)

1. Install the binary, and give the agent a user that can read your logs. On Debian and Ubuntu that's the `adm` group; adjust it for your logs.

   ```bash
   sudo install -m 0755 grepalert-agent /usr/local/bin/
   sudo useradd --system --no-create-home --shell /usr/sbin/nologin grepalert
   sudo usermod -aG adm grepalert
   ```
2. Put the configuration in `/etc/grepalert`. Start from the complete examples, and see the [agent.yaml](config-agent.md) and [rules.yaml](config-rules.md) references.

   ```bash
   sudo mkdir -p /etc/grepalert
   sudo cp examples/agent.yaml examples/rules.yaml /etc/grepalert/
   sudo chown -R grepalert: /etc/grepalert
   ```
3. Put secrets such as webhook URLs in `/etc/grepalert/agent.env`; the unit reads it.

   ```bash
   echo 'SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...' | sudo tee /etc/grepalert/agent.env
   sudo chmod 600 /etc/grepalert/agent.env
   ```
4. Install and start the unit:

   ```bash
   sudo cp examples/grepalert-agent.service /etc/systemd/system/
   sudo systemctl daemon-reload
   sudo systemctl enable --now grepalert-agent
   journalctl -u grepalert-agent -f
   ```

The unit runs the agent as `grepalert` with a 128 MB memory ceiling. It lets the agent write only to `/etc/grepalert`, where it keeps its read positions and, when connected to a dashboard, its credential and the rules it receives.

The dashboard is a single process too: run `grepalert-dashboard -config /etc/grepalert/dashboard.yaml` the same way, or use its container.

## Containers

Images for linux/amd64 and linux/arm64. Each has a built-in config driven by environment variables, so `docker run` works without a config file:

**Dashboard**, on http://localhost:9400, signed in as `admin`:

```bash
docker run -d --name grepalert-dashboard -p 9400:9400 \
  -e GREPALERT_DASHBOARD_PASSWORD=change-me-please \
  -e GREPALERT_ENROLL_TOKEN=$(openssl rand -hex 16) \
  -v grepalert-dashboard:/var/lib/grepalert-dashboard \
  ghcr.io/fadhaw/grepalert-dashboard:0.1.0
```

**Agent connected to that dashboard.** It enrolls itself, and gets its rules from the group it joins. Use the same enrollment token:

```bash
docker run -d --name grepalert-agent \
  -e GREPALERT_DASHBOARD_URL=http://dashboard-host:9400 \
  -e GREPALERT_ENROLL_TOKEN=<the same token> \
  -v /var/log:/var/log:ro \
  -v grepalert-agent:/var/lib/grepalert \
  ghcr.io/fadhaw/grepalert-agent:0.1.0
```

**Agent on its own.** Put your `rules.yaml` in a folder and mount it at `/var/lib/grepalert`. Edits to it are applied without a restart:

```bash
docker run -d --name grepalert-agent \
  -e SLACK_WEBHOOK_URL=https://hooks.slack.com/services/... \
  -v $PWD/grepalert:/var/lib/grepalert \
  -v /var/log:/var/log:ro \
  ghcr.io/fadhaw/grepalert-agent:0.1.0
```

The environment variables of the built-in configs:

| Image | Variable | Meaning |
|---|---|---|
| dashboard | `GREPALERT_DASHBOARD_PASSWORD` | password of the built-in `admin` user (without it, the dashboard is open to anyone) |
| dashboard | `GREPALERT_ENROLL_TOKEN` | a fixed token agents can enroll with (optional; tokens can also be made in the UI) |
| agent | `GREPALERT_DASHBOARD_URL` | the dashboard to connect to; empty runs the agent on its own |
| agent | `GREPALERT_ENROLL_TOKEN` | the dashboard's enrollment token |
| agent | `GREPALERT_AGENT_NAME` | the agent's name (default: the container's hostname) |
| agent | `GREPALERT_AGENT_TOKEN` | a token for the agent's own API (port 9300) |
| agent | `GREPALERT_LOG_LEVEL` | `debug` to log every line a rule matches (default `info`) |
| agent | anything your rules use | e.g. `SLACK_WEBHOOK_URL` for `url: ${SLACK_WEBHOOK_URL}` |

The built-in configs are [examples/container/agent.yaml](../examples/container/agent.yaml) and [examples/container/dashboard.yaml](../examples/container/dashboard.yaml). For labels, SSO, TLS and everything else, mount your own file over them, at `/etc/grepalert/agent.yaml` or `/etc/grepalert/dashboard.yaml`.

## From source

```bash
git clone https://github.com/fadhaw/grepalert.git && cd grepalert
make build                              # the web UI and both binaries, into bin/
```

`make build` needs Go 1.26+ and, for the dashboard's web UI, Node.js 20+. The agent alone needs only Go: `go build ./cmd/grepalert-agent`. See [Development](development.md) for working on the code.
