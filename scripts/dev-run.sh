#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

# shellcheck source=scripts/dev-port.sh
source "$repo_root/scripts/dev-port.sh"

host="${API_HOST:-127.0.0.1}"
port="${API_PORT:-8080}"

if [[ "$port" == "8080" ]]; then
  free_port="$(find_free_local_port "$host" 8080)"
  if [[ "$free_port" != "8080" ]]; then
    echo "[run] port 8080 is in use; starting engine-api on ${host}:${free_port} (set API_PORT in .env to pin a port)"
    export API_PORT="$free_port"
  fi
fi

exec cargo run --locked -p engine-api --bin engine-api
