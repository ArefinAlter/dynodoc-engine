#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

if [[ ! -f .env ]]; then
  echo "error: .env not found; run 'task setup' first" >&2
  exit 1
fi

database_url="$(awk -F= '/^DATABASE_URL=/{sub(/^DATABASE_URL=/, ""); print; exit}' .env)"
if [[ -z "$database_url" ]]; then
  echo "error: DATABASE_URL is not set in .env" >&2
  exit 1
fi

# Strictly scope this helper to the local Docker Compose database on 127.0.0.1:5548.
if [[ ! "$database_url" =~ ^postgres(ql)?://dynodoc_runtime:([^@]+)@127\.0\.0\.1:5548/dynodoc_engine(\?.*)?$ ]]; then
  echo "error: dev-bootstrap-runtime only supports the local Compose DATABASE_URL" >&2
  echo "       expected: postgres://dynodoc_runtime:<password>@127.0.0.1:5548/dynodoc_engine" >&2
  exit 1
fi

raw_pw="${BASH_REMATCH[2]}"
if [[ "$raw_pw" == "REPLACE_WITH_RUNTIME_PASSWORD" || -z "$raw_pw" ]]; then
  echo "error: DATABASE_URL still contains the placeholder password; run 'task setup' or set a password in .env" >&2
  exit 1
fi

# URL-decode percent-encoded characters if present, using python3 if needed.
if [[ "$raw_pw" == *%* ]]; then
  if command -v python3 >/dev/null 2>&1; then
    runtime_pw="$(python3 -c 'import sys, urllib.parse; print(urllib.parse.unquote(sys.argv[1]), end="")' "$raw_pw")"
  else
    echo "error: DATABASE_URL password contains percent-encoding and python3 is unavailable to decode it" >&2
    exit 1
  fi
else
  runtime_pw="$raw_pw"
fi

# Escape single quotes for SQL string literal; pass SQL over stdin so the password never appears in argv.
escaped_pw="${runtime_pw//\'/\'\'}"

docker compose exec -T postgres psql -v ON_ERROR_STOP=1 -q -U dynodoc -d dynodoc_engine <<SQL
DO \$\$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'dynodoc_runtime') THEN
    CREATE ROLE dynodoc_runtime LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
  END IF;
END
\$\$;
ALTER ROLE dynodoc_runtime WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD '${escaped_pw}';
SQL

echo "[db:bootstrap-runtime] ensured restricted role dynodoc_runtime in local PostgreSQL"
