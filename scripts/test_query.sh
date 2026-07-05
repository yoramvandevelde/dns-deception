#!/usr/bin/env bash
set -euo pipefail

show_usage() {
  cat <<EOF
Usage: $(basename "$0") <server> <port> <hostname> [count]

Perform random DNS queries (A, AAAA, MX, TXT) against a given resolver.

Arguments:
  server    DNS server IP address
  port      DNS server port
  hostname  Domain name to query
  count     Number of queries to run (default: 1)

Example:
  $(basename "$0") 1.1.1.1 53 example.com 5
EOF
  exit 1
}

[[ $# -lt 3 ]] && show_usage

server=$1
port=$2
hostname=$3
count=${4:-1}

types=(A AAAA MX TXT)

for ((i = 1; i <= count; i++)); do
  type=${types[$RANDOM % ${#types[@]}]}
  printf "▶  Query %d — %s %s @%s:%s\n" "$i" "$type" "$hostname" "$server" "$port"
  if ! dig +short "$type" @"$server" -p"$port" "$hostname"; then
    echo "  (query failed)" >&2
  fi
  echo
done
