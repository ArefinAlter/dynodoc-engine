#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

# shellcheck source=scripts/dev-port.sh
source "$repo_root/scripts/dev-port.sh"

gen_hex32() {
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -hex 32
  elif command -v python3 >/dev/null 2>&1; then
    python3 -c 'import secrets; print(secrets.token_hex(32))'
  else
    echo "error: need openssl or python3 to generate local development secrets" >&2
    exit 1
  fi
}

if [[ -f .env ]]; then
  echo "[setup] preserved existing .env"
else
  if [[ ! -f .env.example ]]; then
    echo "error: .env.example not found in $repo_root" >&2
    exit 1
  fi
  paseto_key="$(gen_hex32)"
  web_key="$(gen_hex32)"
  runtime_pw="$(gen_hex32)"
  api_port="$(find_free_local_port 127.0.0.1 8080)"

  umask 077
  tmp_env="$(mktemp .env.tmp.XXXXXX)"
  trap 'rm -f "$tmp_env"' EXIT

  while IFS= read -r line || [[ -n "$line" ]]; do
    case "$line" in
      DATABASE_URL=*REPLACE_WITH_RUNTIME_PASSWORD*)
        printf '%s\n' "${line/REPLACE_WITH_RUNTIME_PASSWORD/$runtime_pw}" >> "$tmp_env"
        ;;
      API_PORT=8080)
        printf 'API_PORT=%s\n' "$api_port" >> "$tmp_env"
        ;;
      PASETO_LOCAL_KEY=)
        printf 'PASETO_LOCAL_KEY=%s\n' "$paseto_key" >> "$tmp_env"
        ;;
      WEB_SERVICE_KEY=)
        printf 'WEB_SERVICE_KEY=%s\n' "$web_key" >> "$tmp_env"
        ;;
      *)
        printf '%s\n' "$line" >> "$tmp_env"
        ;;
    esac
  done < .env.example

  chmod 600 "$tmp_env"
  mv "$tmp_env" .env
  trap - EXIT
  echo "[setup] created .env with generated local development keys (mode 0600)"
  if [[ "$api_port" != "8080" ]]; then
    echo "[setup] port 8080 is in use; configured API_PORT=${api_port} in .env"
  fi
fi

if [[ -f .env.migrate ]]; then
  echo "[setup] preserved existing .env.migrate"
else
  if [[ ! -f migration.env.example ]]; then
    echo "error: migration.env.example not found in $repo_root" >&2
    exit 1
  fi
  umask 077
  cp migration.env.example .env.migrate
  chmod 600 .env.migrate
  echo "[setup] created .env.migrate from migration.env.example (mode 0600)"
fi
