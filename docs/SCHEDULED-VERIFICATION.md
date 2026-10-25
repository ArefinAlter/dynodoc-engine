# Scheduled integrity verification

Runs daily at 03:17 UTC via `.github/workflows/verification.yml` and locally via
`scripts/verify-scheduled.sh`. Executes `verify-projection --all` (read-only) and
`verify-snapshots --all` (replays under locks; backfills receipts) using restricted
runtime privileges. Negative controls assert that projection corruption or tampered
snapshots exit 1 and invoke the alert sink; clean fixtures exit 0 silently.

## Operator configuration

Requires `engine-cli`, `scripts/verify-scheduled.sh`, and GNU `timeout`. Set
`DYNODOC_VERIFY_ALERT` to an executable notifier that reads failure summaries on
stdin and exits nonzero on delivery failure.

Environment (`/etc/dynodoc/verification.env`, mode `0600`):
```sh
ENGINE_CLI=/opt/dynodoc/bin/engine-cli
DYNODOC_VERIFY_ALERT=/usr/local/libexec/dynodoc-page-owner
DYNODOC_VERIFY_TIMEOUT=30m
# DATABASE_URL supplied via restricted runtime login credentials.
```

Crontab (runs daily, restricted log):
```cron
17 3 * * * umask 077; set -a; . /etc/dynodoc/verification.env; set +a; /opt/dynodoc/scripts/verify-scheduled.sh >> /var/log/dynodoc/verification.log 2>&1
```

## Failure response

The wrapper executes both checks before exiting. Any non-zero exit code or timeout
invokes `$DYNODOC_VERIFY_ALERT` and exits 1. Never append `|| true`.

On failure: preserve restricted logs and database backup. Investigate the failing
document with independent verification tools before restoring availability. Never
repair canonical history automatically, rewrite applied migrations, or delete receipts.
