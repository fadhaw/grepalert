[← Documentation](../README.md#documentation) · Previous: [Memory and performance](performance.md) · Next: [Demo walkthrough →](demo.md)

# Tested behaviour

What grepalert is tested to do, especially in the edge cases where log tools tend to lose lines or send alerts twice. Each row names the test that checks it.

- **Automated tests** (`go test ./...`) run on every push and pull request, on Linux ([CI](../.github/workflows/ci.yml)), and again before every release. They use real files, real HTTP servers and a fake Kubernetes API.
- **Measured tests** (load, soak, Docker comparisons) were run by hand on real hardware; their numbers are in [Memory and performance](performance.md) and below.

## Reading log files

| Behaviour | Test |
|---|---|
| On first start, a file is read from its end, so old history doesn't alert. A line written in two parts is joined before it is matched, and Windows line endings (`
`) are handled. | `TestTailerStartsAtEndAndReadsPartialLines` |
| A file that doesn't exist yet is read from its first line once it appears. | `TestTailerFileCreatedLater` |
| A `*.log` rule follows files created later, and ignores files that don't match. | `TestGlobPicksUpNewFiles` |
| On start the agent logs each file it follows and from where, waits visibly for files that don't exist yet, and explains a pattern that matches nothing, such as a directory it may not list (checked as a non-root user on Linux). | `TestAgentLogsTheFilesItFollows` |
| A huge line (100 KB) is cut at `max_line_bytes`, and the buffer doesn't stay large. | `TestTailerLongLineIsTruncated` |
| **Rename rotation:** the old file is read to its end, including a line written to it after the rename, then the new file from its start. | `TestTailerRotation` |
| **Rename rotation, program still writing to the old file** (nginx until `USR1`): those lines are read for 30 seconds after the switch. | `TestTailerReadsOldFileAfterRotation` |
| The unfinished last line of the rotated file is never joined to the first line of the new one. | `TestTailerRotationKeepsPartialLineApart` |
| **copytruncate:** the file shrinks, and the agent reads it again from the start. | `TestTailerTruncation` |
| **copytruncate followed by a burst** that makes the file larger than before, all between two checks: detected by the file's head, not its size. | `TestTailerTruncatedAndRefilledBetweenSteps` |
| **Deleted file, not recreated:** closed after 30 seconds, so its disk space is freed; read from the start if it comes back. | `TestTailerLetsGoOfDeletedFile` |
| A file with a large backlog doesn't delay the others, even with one reader worker. | `TestSchedulerIsFair` |
| Lines written just before the agent stops are still read (final read). | `TestSchedulerManyFilesAndFinalRead` |
| A file that no rule uses any more is closed, and can be deleted, also on Windows. | `TestSchedulerRemoveClosesFile` |

How the agent keeps files open while it reads them, and what that means for rotation and disk space, is explained in [Running agents](agents.md#files-are-held-open-read-only).

**Measured in Docker on Linux,** against the agent before these cases were handled, five rotations each:

| Scenario | Before | Now |
|---|---|---|
| Rename rotation, program writing to the old file for 2 s after each rotation | 570 of 650 lines | **650 of 650** |
| copytruncate, then right away a burst larger than the old file | 40 of 135 lines | **135 of 135** |
| Log file deleted | held open for good | closed after 30 s |

## Restarts

| Behaviour | Test |
|---|---|
| A restarted agent alerts on exactly the lines written while it was down: none missed, none twice. | `TestRestartDoesNotMissLines` |
| It resumes at the saved position, and a line half-written at shutdown is read in full. | `TestResumeAfterRestart` |
| **Rotated while down (rename):** the rest of the old file is read from `app.log.1`, then the new file. Compressed `.gz` files are skipped. | `TestResumeAfterRenameRotation` |
| **Rotated while down (copytruncate):** the missed lines are read from the copy (`app.log-20261012`), then the new content. | `TestResumeAfterCopyTruncate` |
| **Replaced while down, old file gone:** the new file is read from the start. | `TestResumeWhenFileReplacedAndOldOneGone` |
| A file missing at start keeps its saved position until it returns. | `TestPositionKeptWhileFileMissing` |
| Silences received from the dashboard still apply after a restart while the dashboard is down; expired ones are dropped. | `TestSilencesSurviveRestart` |

## Kubernetes pods

All in `TestKubernetesSource`, against a fake Kubernetes API:

- Lines logged before the agent started don't alert.
- A pod that appears later is read from its first line; a pod that is gone stops being followed.
- A dropped log stream resumes after its last line, without repeating one.
- After an agent restart, each stream resumes from its saved position (`sinceTime`).
- A sidecar container that is still waiting is skipped.

Bad kubeconfig files give a clear error (`TestKubeconfigErrors`).

## Rules and alerts

| Behaviour | Test |
|---|---|
| Valid rules load; mistakes such as unknown settings are reported, and an empty file is valid. | `TestParseValid`, `TestParseErrors`, `TestEmptyDocumentIsValid`, `TestAbsenceRuleValidation` |
| A broken rules file is reported once, the previous rules keep running, and a fixed file is applied. | `TestBrokenRulesFileReportedOnce` |
| Captured values reach the webhook template. | `TestTemplateUsesCapturedValues` |
| With `log_level: debug`, every matching line is logged once, as sent, suppressed or excluded; non-matching lines aren't, and at the default level nothing is. | `TestDebugLogsMatches` |
| Suppression windows and the summary after them; absence rules and their recovery alert. | `TestSuppression`, `TestAbsenceRule` |
| Suppression state never grows past its cap, the event log is a fixed ring, and a reload frees the state of removed rules. | `TestSuppressionKeysAreBounded`, `TestRingIsBounded`, `TestReloadDropsStateOfRemovedRules` |
| The fast prefilter never skips a line the pattern matches: 200,000 random lines per pattern, plus a fuzz test. | `TestPrefilterNeverRejectsAMatch`, `FuzzPrefilter` |
| Every [Rule cookbook](cookbook.md) recipe sends exactly the webhook bodies it shows. | `TestCookbook` |
| Every example config, including those in the Kubernetes manifests, loads; the docs show them as they are; every doc link resolves. | `TestExampleConfigs`, `TestDocsShowTheExamples`, `TestDocLinks` |

## Dashboard and fleet

| Behaviour | Test |
|---|---|
| **Enrollment:** a wrong token never enrolls; an agent joins its group by label; a restarted agent reuses its identity; a revoked agent is refused; after the dashboard's data is lost, agents enroll again by themselves. | `TestConnectedAgentLifecycle`, `TestEnrollmentTokens` |
| **One alert across hosts:** 50 hosts reporting the same error give one alert, then one summary; a different error is a different alert. | `TestFleetDedupe` |
| Silences, including one that starts while a fleet window is open. | `TestFleetSilence`, `TestSilenceCoversOpenWindow` |
| Agent-down and agent-up alerts; revoked agents never alert. | `TestAgentDownAlerts` |
| **Dashboard down:** agents deliver alerts directly, still honouring the dashboard's silences. | `TestAlertsThroughDashboardWithFallback` |
| A stopped agent first finishes what its dashboard connection is doing, such as saving a file, before it exits. | `TestRunWaitsForDashboardConnection` |
| **Staged rollout:** canary first, then 50%, then everyone; a rule that fires a lot halts it and rolls everyone back; rules the agents refuse halt at the canary; rollback is immediate. | `TestStagedRolloutVersionsAndRollback` |
| Dry run of draft rules, and local rules on top of a group's. | `TestDryRunAndLocalRules`, `TestDryRunWindowAndSuppression` |
| An agent's own rules are saved when a group first replaces them, and can be restored after it leaves. | `TestOwnRulesSavedOnFirstGroupPush`, `TestRestoreOwnRulesAfterLeavingGroup` |
| Sign-in: sessions, login rate limit, roles, OIDC, safe redirects, a strict CSP on every response. | `TestLocalLoginAndSessions`, `TestLoginRateLimit`, `TestRBAC`, `TestOIDCLogin`, `TestSafeNext` |

## Load and soak

Measured by hand; details in [Memory and performance](performance.md).

- **Memory doesn't grow:** 1,000,000 lines, each with a new `group_by` value: heap 3–5 MB throughout, suppression state back to 0 afterwards.
- **Big files:** a 5 GB file read in 18 s at 11–17 MB of memory; tailing an existing 5 GB file starts in 164 ms.
- **Fast logs with rotation:** 100 MB/s for 60 s, rotating every 2 GB: all 27.0M lines read, to the exact last byte.
- **Fleets:** 10 VMs at 10 MB/s each, rotating at 1 GB: every agent read to the exact end of its file.
- **Many files:** 500 files on one agent at 1.3% CPU when idle.

## Run the tests yourself

```bash
go test ./...                                      # everything that runs in CI
go test -race ./internal/...                       # with the race detector (needs cgo)
go test -run '^$' -fuzz FuzzPrefilter ./internal/rules
go test -bench . ./internal/agent                  # 0 allocations for lines that don't match
```

See [Development](development.md) for building the UI and the documentation site.
