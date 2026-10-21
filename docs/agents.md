[← Documentation](../README.md#documentation) · Previous: [Rule cookbook](cookbook.md) · Next: [Dashboard and groups →](dashboard.md)

# Running agents

An agent runs on every server with logs. It reads its settings from [agent.yaml](config-agent.md) and its rules from [rules.yaml](config-rules.md).

## Three ways to run an agent

| | On its own | Connected to a dashboard | Reached by a dashboard |
|---|---|---|---|
| **Set up** | no `dashboard` section | a `dashboard` section | `listen` + `token`; added with **Connect agent** |
| **Rules come from** | its `rules_file` | its group in the dashboard | its group, or its own file |
| **Network** | none | the agent connects **out**; no open port | the dashboard connects **in** to port 9300 |
| **Alerts** | sent by the agent | through the dashboard (one alert across hosts), or directly while it is down | sent by the agent |
| **Use it for** | one server, or rules managed with your own tools | most fleets, also behind NAT and firewalls | servers the dashboard can reach directly |

### On its own

Nothing else is needed: the [quick start](../README.md#quick-start-your-first-alert) shows the two files. Rules are changed by editing `rules_file`; see [changing rules](#changing-rules) below.

### Connected to a dashboard

The usual way for a fleet. In most company networks the dashboard can't reach the servers (NAT, firewalls, separate VPCs), so the agent connects **out** instead, and needs no open port:

```yaml
# /etc/grepalert/agent.yaml
rules_file: /etc/grepalert/rules.yaml
labels:
  role: web
  env: prod
dashboard:
  url: https://grepalert.example.com
  enrollment_token: ${GREPALERT_ENROLL_TOKEN}
```

1. **Enroll.** On its first start the agent presents the enrollment token.
   - The dashboard gives it a credential of its own, which the agent keeps in `identity_file` (next to the rules file, mode 0600).
   - After that, the token is no longer needed. A restarted agent reuses its credential, so it never shows up twice.
2. **Connect.** The agent keeps one HTTPS long-poll open to the dashboard. The dashboard sends its requests (status, rules, events) down that connection.
   - Nothing listens on the server, unless you set `listen`.
   - Proxies are used from `HTTPS_PROXY`, and private CAs from `dashboard.ca_file`.
3. **Join a group by label.** A group set to *Auto-add agents with labels* `role=web,env=prod` picks up every agent with those labels and pushes them its rules, including agents that enroll later.
   - If several groups match, the first by name wins.
   - An admin can choose an agent's group by hand instead (agent → Settings → Group).
   - Every agent also gets an `os` label.

**Enrollment tokens:**
- **In the UI:** create them under **Agent enrollment**, with an optional expiry. They are stored only as hashes and shown once.
- **For automation** (Ansible, Terraform, VM images): set a fixed `enrollment_token` in [dashboard.yaml](config-dashboard.md) instead.

**Revoking:**
- **A token:** revoking it stops *new* enrollments with it.
- **An agent that already enrolled:** use **Revoke access** in its Settings; the dashboard then refuses it. **Allow again** restores it within about 15 seconds.

Measured with 10 VMs that the dashboard could not reach directly:
- **Enrolling:** all 10 enrolled within a second of starting.
- **Pushing rules:** a new group reached all 10 in 111 ms, and a rules edit in 72 ms.
- **Reconnecting:** after a dashboard restart, all 10 were back online in 7.6 s.

### Reached by a dashboard

When the dashboard **can** reach the server, it can connect to the agent's API instead:
1. Give the agent `listen: ":9300"` and a `token`.
2. In the dashboard, use **Connect agent** with its address (`http://10.0.0.5:9300`) and the token.

Use TLS (`tls_cert`, `tls_key`) or a private network: whoever can reach the API with the token can change the agent's rules.

## Changing rules

Every way of changing rules validates them first. An invalid version is rejected, the agent reports why, and the previous rules keep running.

| Way | How |
|---|---|
| Edit the file | Save `rules_file`; the agent applies it within `rescan_interval` (10 s). Check first with `grepalert-agent -check`. |
| A dashboard group | Edit the group's rules in the UI, or change them in git and sync. They reach every member, all at once or [in stages](rollout.md). |
| An ungrouped agent | In the dashboard: agent → Rules → Validate, then Save & apply. |
| The API | `curl -X PUT -H "Authorization: Bearer $TOKEN" --data-binary @rules.yaml http://agent:9300/api/v1/rules` ([Agent API](api.md)) |
| Local rules | `rules.local.yaml`, or agent → Rules → Local rules in the dashboard: extra rules for this machine, on top of the others. |

**What carries over:**
- **Saved:** rules pushed by a dashboard or the API are written to `rules_file`, so they survive a restart.
- **Files:** files the new rules no longer use are released, and new files are opened.
- **Suppression:** suppression windows of rules that stay carry on.

## What an agent keeps on disk

| File (next to `rules_file`) | What it is |
|---|---|
| `rules.yaml` (`rules_file`) | The rules the agent runs: its own, or its group's once it joins one |
| `rules.local.yaml` | Extra rules for this machine only. Groups never touch it |
| `rules.before-group.yaml` | The agent's own rules, saved when a group first replaced them |
| `grepalert.state.json` | Read positions, so restarts neither miss nor repeat lines |
| `grepalert.identity.json` | The credential of an enrolled agent |
| `grepalert.silences.json` | The last silences received from the dashboard |

**Joining and leaving a group:**
- **Joining:** the group's rules replace the agent's own in `rules.yaml`. Before the first replacement, the agent saves its own rules to `rules.before-group.yaml`.
- **Leaving:** the agent keeps running the group's rules. When you move it out of its group, the dashboard offers to restore its own rules; you can also do it later from the agent's **Rules** tab.
- **Editing instead of restoring:** if you edit the agent's rules directly, those become its own rules, and the saved copy is dropped.

## If the dashboard is down

![The dashboard goes down, then the agent restarts during the outage](assets/dashboard-down.gif)

- **Rules:** agents keep running the rules on their disk, including across a restart.
- **Alerts:** after `fallback_after` (15 s) without the dashboard, agents send them straight to the webhooks.
- **Silences:** they still hold, even across an agent restart.
- **Recovery:** when the dashboard is back, agents reconnect by themselves (backoff up to 30 s) and are brought up to date.
- **Lost dashboard data:** if the dashboard's data is lost, agents notice they are unknown and enroll again with their token.

## Log rotation

The agent polls each file (every 500 ms by default, `poll_interval`), which works the same on Linux, macOS and Windows:

- **rename + create** (logrotate's default): the agent finishes reading the old file, then reads the new one from its start.
  - It keeps reading the old file for **30 seconds** after switching. Some programs keep writing to it until they reopen their log: nginx until it gets `USR1`, or programs with buffered writes. Those last lines are alerted on too.
  - A line the program had not finished when the file was rotated stays with the old file; it is never joined to the first line of the new one.
- **copytruncate:** the agent notices the file was emptied and starts again from offset 0. This works even when the program writes more than the file held before the agent's next check: the agent compares the start of the file with what it read, not only the size.
- **Deleted files:** the agent keeps reading a file whose path is gone for 30 seconds, then closes it, so its disk space is freed. If the file comes back, it is read from the start.
- **Files that don't exist yet:** the agent waits for them, then reads them from the start.
- **First start:** files are read from the end (`start_from: end`), so old history doesn't set off a burst of alerts.

### Files are held open, read-only

The agent keeps each file it follows open between checks, the way `tail -F` does. There are two reasons:
- **Speed:** each check reads only the bytes added since the last one, from where it stopped.
- **No lost lines:** an open file stays readable after it is renamed or deleted, because it refers to the file itself, not to its name. That is how the agent finishes a rotated file.

It opens files **read-only and never locks them**, so the program writing the log and your log rotation work as usual:

| Someone else… | Linux and macOS | Windows |
|---|---|---|
| writes the file | works | works (opened with write sharing) |
| renames it (rotation) | works; the agent reads the old file 30 s more | works (opened with delete sharing) |
| truncates it (copytruncate) | works | works |
| deletes it | works; the disk space is freed when the agent closes it, within 30 s | works; on some systems the name stays reserved until the agent closes it, within 30 s |

**How many files are open:** one per file a rule follows, plus each rotated file for 30 seconds. Files no rule uses any more are closed when the rules change, and files that don't exist hold nothing. With a glob over hundreds of files, check the process's open-file limit (`ulimit -n`, `LimitNOFILE=` in systemd); the agent raises its soft limit to the hard limit when it starts.

**Disk space:** a deleted log file keeps using disk space while any program has it open; `lsof | grep deleted` lists such files. The agent lets go of a deleted file 30 seconds after its name disappears, so it never keeps disk space for long.

**Prefer rename + create over copytruncate** when your program can reopen its log (most can, on a signal or by themselves). With `copytruncate`, logrotate first copies the file and then empties it. A line written in the moment between the two is in neither file, and no tool can read it afterwards; logrotate's manual warns about this. The agent reads new lines within `poll_interval`, so it usually catches such a line before it is erased, but not always.

```
/var/log/app/*.log {
    daily
    rotate 7
    compress
    delaycompress          # keep app.log.1 uncompressed: an agent restarted after rotation catches up from it
    create 0640 app app    # rename + create, instead of copytruncate
    postrotate
        systemctl kill -s USR1 app.service    # tell the program to reopen its log
    endscript
}
```

## Restarts don't miss lines

Every 5 seconds (`state_interval`), and again on shutdown, the agent saves its read position for each file to `state_file`. Each position records:

- the offset just past the last complete line, so a half-written line is read in full after a restart
- the file's identity (inode, or the Windows file index)
- a hash of the first 1 KB of the file

On restart the agent checks whether the file is still the one it was reading:

- **Same file:** it resumes at the saved offset, and lines written while it was down are alerted on.
- **Rotated while down:** it finds the old file under its rotated name (`app.log.1`, `app.log-20261012`, …, but not compressed `.gz` files), reads the rest of it, then reads the new file from the start.
- **Replaced, with the old file gone:** it reads the new file from the start.

**Delivery is at-least-once:**
- **After a crash,** lines read since the last save (at most `state_interval` of them) are processed again and can alert twice.
- **A clean shutdown** saves exact positions, and spends up to 5 seconds delivering alerts that are still queued.
- **Suppression windows** are kept in memory, so they start fresh after a restart.
