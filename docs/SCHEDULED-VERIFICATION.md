# Scheduled integrity verification

The `scheduled-verification` GitHub Actions workflow runs daily at 03:17 UTC, can be
started manually, and runs on pull requests that change its entry points. It seeds
isolated synthetic databases and runs the actual `verify-projection --all` and
`verify-snapshots --all` CLI commands as a restricted runtime login. Negative controls
change a node projection and then an immutable snapshot under a disposable database
owner; both must make the scheduled entry point exit 1 and call a local alert sink.
The clean fixture must pass, backfill its historical receipt and produce no alert.
No production URL, credentials or documents are used in this workflow.

A failed or timed-out Actions job fails the workflow and emits an error annotation.
The repository owner must enable GitHub email notifications for failed workflows and
verify delivery with a failed manual run. An annotation alone does not page anyone.
Scheduled Actions run the workflow on the default branch after merge; submission of
this PR does not install a production monitor or establish alert delivery.

## Operator installation on Linux

Install the reviewed `engine-cli` and `scripts/verify-scheduled.sh`, GNU `timeout`, a
protected environment file and an executable failure notifier owned by the operator.
The notifier receives only a generic failure summary on stdin; it must synchronously
hand off a page or email to the responsible owner and exit nonzero if handoff fails.
Set `DYNODOC_VERIFY_ALERT` to its absolute path. Test the notifier's delivery and the
scheduler's failure/timeout path on a disposable restored fixture before installation.
A notifier failure is itself an actionable error in the host log. No delivery mechanism
or recipient is provisioned by this repository.

Example environment file, mode 0600; the operator supplies the actual database URL:

```sh
ENGINE_CLI=/opt/dynodoc/bin/engine-cli
DYNODOC_VERIFY_ALERT=/usr/local/libexec/dynodoc-page-owner
DYNODOC_VERIFY_TIMEOUT=30m
# DATABASE_URL is supplied here by the operator's approved secret mechanism.
```

Use a login with the documented runtime grants and the privileges required by the
verification/backfill commands; never put the migration owner's credential in cron.
`verify-projection` is read-only, but `verify-snapshots` replays under document locks
and can insert verification receipts. A hot standby or read-only replica cannot run
the latter unchanged. Choose a window and timeout appropriate to the dataset, measure
lock waits, and monitor impact before increasing frequency. This is an application-level
check, not independent evidence against a malicious database owner or a backup strategy.

An illustrative daily operator crontab entry (host timezone must be accounted for):

```cron
17 3 * * * umask 077; set -a; . /etc/dynodoc/verification.env; set +a; /opt/dynodoc/scripts/verify-scheduled.sh >> /var/log/dynodoc/verification.log 2>&1
```

Pre-create that log with restricted ownership, rotate it, and monitor missed runs as well
as failures. Verification output can contain node fields; keep it on the restricted host
and do not upload it to GitHub or include it in pages. A service manager with an independent
failure/missed-run alarm is preferable where available. A missing environment file or
broken notifier configuration must also be caught by the host scheduler's own monitoring.

## Failure response

The wrapper attempts both checks even if one fails. Either a nonzero check result or a
timeout makes it invoke the notifier and exit 1; clean runs exit 0 without a notification.
Do not append `|| true`. `verify-snapshots --all` stops on its first bad document and
rolls back receipts for that document; it does not promise a list of every bad snapshot.
`verify-projection --all` visits each document and reports unexplained differences.

Page the owner, preserve the restricted log and a database backup, and investigate the
first failing document using the documented independent verification tools. Restore
availability only after a reviewed repair or recovery plan. Never repair canonical
history automatically, rewrite applied migrations, delete failed receipts, or equate a
later passing run with proof that an earlier alarm was harmless. Record the engine commit,
schema version, commands, exit codes and actual notification delivery in the operator log.
