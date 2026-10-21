[← Documentation](../README.md#documentation) · Previous: [Demo walkthrough](demo.md) · Next: [Releasing →](releasing.md)

# Development

Code layout, building from source, and working on the web UI.

## Layout

```
cmd/grepalert-agent       agent binary
cmd/grepalert-dashboard   dashboard binary
internal/rules            rule format, validation, compilation (shared)
internal/agent            tailer, matching/suppression engine, notifier, API
internal/alert            alert format, webhook rendering and bounded sender (agent + dashboard)
internal/dashboard        agent/group store, group sync, git fetch, fleet alerting, rollouts; embeds the built UI (web/dist)
ui/                       dashboard web UI: React + TypeScript, built with Vite
examples/                 agent.yaml, rules.yaml, dashboard.yaml, systemd unit
```

## Working on the web UI

The UI lives in `ui/`:

| Path | What |
|---|---|
| `src/pages/` | one component per page: group, agent, alerts, silences, settings, access, audit |
| `src/dialogs/` | the forms in dialogs |
| `src/state.tsx` | the signed-in user, the polled overview, navigation |
| `src/api.ts` | the API client |
| `src/types.ts` | the API's JSON shapes |

`make ui` builds it into `internal/dashboard/web/dist`, which `go build` embeds. The build output is not committed. A dashboard built without it still runs its API, and its page explains how to build the UI.

For hot reload while editing:

```bash
grepalert-dashboard -config dashboard.yaml   # API on :9400
make ui-dev                                  # UI on http://localhost:5173, calling that API
```

Type-check with `cd ui && npm run typecheck`.

## The documentation site

The site at [fadhaw.github.io/grepalert](https://fadhaw.github.io/grepalert/) is built from the README and `docs/` with [MkDocs Material](https://squidfunk.github.io/mkdocs-material/). Edit those Markdown files, and keep them readable on GitHub too.

`scripts/build_site.py` prepares them for the site:
- the README becomes the home page
- links to repository files become GitHub links
- release notes of tagged versions are published

Navigation is in `mkdocs.yml`; add new pages there.

To preview it with live reload on http://127.0.0.1:8000:

```bash
pip install -r docs/requirements.txt
python scripts/build_site.py && mkdocs serve
```

After editing a page, run `build_site.py` again. `mkdocs build --strict` fails on any broken link or anchor; CI runs it on every pull request. `go test ./examples` checks the links on GitHub too, and that the example configs load.

