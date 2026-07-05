# DNS Deception PoC

A tiny DNS proxy that makes subdomain bruteforcing harder by lying about
non-existent records instead of returning `NXDOMAIN`.

## Concept

Subdomain bruteforce tools (gobuster, ffuf, amass, puredns, massdns, ...)
usually probe a couple of random hostnames first to detect wildcard DNS —
naive tools just check whether those randoms resolve to the same IP, and
skip the target (or abort) if they do.

This server sits in front of your real (authoritative) nameserver:

- If a queried name **actually exists** upstream, the real answer is passed
  through unchanged.
- If it **doesn't exist**, instead of `NXDOMAIN` it returns a fake A/AAAA
  record, deterministically derived from the query name (`HMAC-SHA256(secret,
  name)`). Same name → same fake IP every time; different names → different
  IPs.

Net effect: the "are two random names equal?" wildcard check fails to detect
anything, the tool proceeds to bruteforce, and every single guess "resolves"
— burying real hits in noise. It's aimed at simpler/naive tooling, not at
defeating advanced set-based wildcard detection.

Only domains you explicitly configure are served; everything else gets a
plain `REFUSED`.

## Build

```sh
go build -o dns-deception .
```

## Usage

```sh
export DECEPTION_SECRET_KEY=$(openssl rand -hex 32)

./dns-deception \
  --listen :5353 \
  --domain example.com=203.0.113.10:53 \
  --domain other.org=198.51.100.5:53
```

| Flag          | Env                        | Description                                                           |
|---------------|----------------------------|-----------------------------------------------------------------------|
| `--listen`    | `DECEPTION_LISTEN`         | Address to listen on (UDP + TCP). Default `:5353`.                    |
| `--domain`    | `DECEPTION_DOMAINS`        | `zone[=upstream_host:port]`, repeatable or comma-separated. Required.|
| `--upstream`  | `DECEPTION_UPSTREAM`       | Default upstream for `--domain` entries without their own.           |
| `--ttl`       | `DECEPTION_TTL`            | TTL on synthesized records. Default `60`.                             |
| `--http`      | `DECEPTION_HTTP`           | HTTP listen address for `/healthz` and `/readyz`. Default `:8080`.  |
| `--key`       | `DECEPTION_SECRET_KEY`     | Secret key as hex (insecure fallback — prefer the env var).         |

All flags have a corresponding environment variable. CLI flags take
precedence over env vars. The secret key should always be set via
`DECEPTION_SECRET_KEY` (`openssl rand -hex 32`). Use `--key` only if you
cannot set environment variables.

## Examples

```sh
# Real record -> passed through as-is
dig @127.0.0.1 -p 5353 example.com A +short

# Non-existent name -> consistent fake IP, not NXDOMAIN
dig @127.0.0.1 -p 5353 asdkjhqwe123.example.com A +short
dig @127.0.0.1 -p 5353 asdkjhqwe123.example.com A +short   # same IP again

# Domain not in --domain list -> REFUSED
dig @127.0.0.1 -p 5353 not-my-domain.com A
```

## Notes

- Fake IPs can land on arbitrary public addresses — by design, this isn't
  restricted to a subnet you own. Only first-octet/first-byte values that
  look obviously reserved (`10`/`127`/`172`/`192` for IPv4; loopback/link-
  local/ULA/multicast-ish bytes for IPv6) get swapped for a fixed fallback.
- TXT and MX queries on non-existent names are also synthesized (SPF-like
  TXT and a plausible MX target). NS, SOA, CNAME and other types relay the
  upstream's real response code.

## TODO

- [x] **More fake record types** — synthesize TXT (SPF-like) and MX in
  addition to A/AAAA for non-existent names.
- [x] **Health endpoint** — HTTP `/healthz` for K8s liveness/readiness probes.
- [x] **Graceful shutdown** — catch SIGTERM/SIGINT, drain in-flight queries
  before exiting.
- [x] **Dual-source configuration** — every option available via environment
  variable *and* CLI flag (container-first, developer-friendly).
- [ ] **Structured JSON logging** — machine-parseable output for Loki/Elastic
  aggregation.
- [ ] **Prometheus metrics endpoint** — expose `queries_total` counter
  labelled by record type, fake vs real, and rcode.
