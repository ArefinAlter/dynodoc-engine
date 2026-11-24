#!/usr/bin/env bash
# Shared helper to select a free local TCP port starting from a preferred port.

find_free_local_port() {
  local host="${1:-127.0.0.1}"
  local start_port="${2:-8080}"
  local max_offset="${3:-20}"

  if command -v python3 >/dev/null 2>&1; then
    python3 - "$host" "$start_port" "$max_offset" <<'PY'
import socket
import sys

host = sys.argv[1]
start = int(sys.argv[2])
count = int(sys.argv[3])

for port in range(start, start + count):
    if port > 65535:
        break
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except OSError:
        continue
    free = True
    for family, socktype, proto, _, sockaddr in infos:
        sock = socket.socket(family, socktype, proto)
        try:
            sock.bind(sockaddr)
        except OSError:
            free = False
            break
        finally:
            sock.close()
    if free:
        print(port)
        sys.exit(0)

print(start)
PY
    return 0
  fi

  local probe_host="$host"
  if [[ "$probe_host" == "0.0.0.0" || "$probe_host" == "::" ]]; then
    probe_host="127.0.0.1"
  fi

  local i port
  for ((i = 0; i < max_offset; i++)); do
    port=$((start_port + i))
    if (( port > 65535 )); then
      break
    fi
    if ! (exec 3<>"/dev/tcp/${probe_host}/${port}") 2>/dev/null; then
      printf '%s\n' "$port"
      return 0
    fi
    exec 3>&- 2>/dev/null || true
  done

  printf '%s\n' "$start_port"
}
