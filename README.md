# mini-dns

A lightweight DNS server implementation in Rust. It serves an authoritative zone file and can optionally forward unknown names to an upstream resolver (recursion), over both **UDP and TCP**.

**Features**

- Record types: `A`, `AAAA`, `CNAME`, `MX`, `TXT`, `NS`, `SOA`, `SRV`, `PTR`, `CAA`
- Wildcard records (`*.example.com`)
- CNAME chaining (resolves the alias target within the zone in a single response)
- Case-insensitive lookups, correct `AA` / `NXDOMAIN` / `NODATA` handling
- **EDNS(0)** — honours the client's UDP payload size (responses beyond 512 bytes)
- UDP with truncation (`TC` bit) and TCP fallback
- Name compression on responses
- **Recursive forwarding** to an upstream resolver with a **TTL cache** (positive *and* negative/NXDOMAIN caching)
- **Prometheus metrics** at `/metrics` (plain HTTP)
- **Encrypted transports**: DNS-over-TLS (DoT) and DNS-over-HTTPS (DoH over HTTP/1.1 and HTTP/2)
- **Per-client rate limiting** to mitigate floods/amplification
- **Hot zone reload** on `SIGHUP` (no restart needed)
- In-process **metrics** logged periodically
- Configurable via CLI flags or environment variables, structured logging via `tracing`

**Performance**

- **`SO_REUSEPORT`**: one UDP socket per core so the kernel load-balances ingress across cores instead of funnelling through a single receive loop
- **Fast path**: local and cached answers are resolved synchronously and sent inline — no task spawn or per-packet allocation; only forwarded queries spawn a task
- **Thread-per-core**: runtime workers are pinned to CPU cores (best-effort), one per core
- **Lock-free / sharded state**: zone via `arc-swap`, cache and rate limiter via `DashMap`, metrics sharded and cache-line padded
- **Single-flight forwarding**: concurrent identical cache misses collapse into one upstream query; upstream sockets are pooled and bounded by a semaphore

> Not yet implemented: `io_uring` + `recvmmsg` batching and a thread-per-core runtime such as `monoio` — these are Linux-only and would replace the Tokio runtime; left as future work.

## How to run it in production

### 1. Configure the zone file

The server loads DNS records from a zone file. The path defaults to `zones/example.zone` and can be overridden with the `MINI_DNS_ZONE` environment variable (see step 3).

The zone file should have the following format, with each record on a new line:

```
<domain> <ttl> <type> <data>
```

For example:

```
example.com.     3600 SOA   ns1.example.com. admin.example.com. 1 7200 3600 1209600 3600
example.com.     3600 NS    ns1.example.com.
example.com.     3600 A     192.0.2.1
example.com.     3600 AAAA  2001:db8::1
www.example.com. 3600 CNAME example.com.
example.com.     3600 MX    10 mail.example.com.
example.com.     3600 TXT   "v=spf1 -all"
*.example.com.   3600 A     192.0.2.9
```

Lines that are blank or start with `;` are ignored. A malformed line is logged with its line number and skipped, so one bad entry won't stop the rest of the zone from loading.

### 2. Build the project

Build the project in release mode:

```bash
cargo build --release
```

### 3. Run the server

Once built, you can run the server using the following command:

```bash
./target/release/mini-dns
```

The server will start and listen on `127.0.0.1:8888` (UDP and TCP) for DNS queries.

#### Configuration

Settings can be supplied via CLI flags or environment variables (flags take precedence):

| Flag             | Env var             | Description                                  | Default              |
| ---------------- | ------------------- | -------------------------------------------- | -------------------- |
| `-z`, `--zone`   | `MINI_DNS_ZONE`     | Path to the zone file                        | `zones/example.zone` |
| `-a`, `--addr`   | `MINI_DNS_ADDR`     | Address to bind (UDP + TCP)                  | `127.0.0.1:8888`     |
| `-u`, `--upstream`| `MINI_DNS_UPSTREAM`| Upstream resolver for recursion (`host:port`)| `8.8.8.8:53`         |
| `--no-recurse`   | —                   | Disable forwarding; serve only the local zone| off                  |
| `--rate-limit`   | `MINI_DNS_RATE_LIMIT`| Max queries/client/sec (`0` = unlimited)    | `0`                  |
| `--cache-size`   | —                   | Max cached forwarded answers                 | `1024`               |
| `--dot-addr`     | `MINI_DNS_DOT_ADDR` | Enable DNS-over-TLS on this address          | disabled             |
| `--doh-addr`     | `MINI_DNS_DOH_ADDR` | Enable DNS-over-HTTPS on this address        | disabled             |
| `--tls-cert`     | `MINI_DNS_TLS_CERT` | TLS certificate (PEM)                        | self-signed          |
| `--tls-key`      | `MINI_DNS_TLS_KEY`  | TLS private key (PEM)                         | self-signed          |
| `--metrics-addr` | `MINI_DNS_METRICS_ADDR` | Expose Prometheus `/metrics` (plain HTTP) | disabled             |
| `-v`, `--verbose`| —                   | Increase log verbosity (`-v`, `-vv`)         | INFO level           |

Log level can also be controlled with the `RUST_LOG` environment variable. For example, to serve a custom zone on port 5353, forward to Cloudflare, and rate-limit to 50 q/s per client:

```bash
./target/release/mini-dns --zone /etc/mini-dns/db.zone --addr 0.0.0.0:5353 \
    --upstream 1.1.1.1:53 --rate-limit 50 -v
```

### Recursion & caching

By default, names not found in the zone are forwarded to the upstream resolver and the answers are cached for their TTL. Use `--no-recurse` to run as a pure authoritative server (returning `NXDOMAIN` for unknown names).

### Reloading the zone

Send `SIGHUP` to reload the zone file in place, without dropping in-flight queries or restarting:

```bash
kill -HUP $(pgrep mini-dns)
```

### Encrypted transports (DoT / DoH)

Enable DNS-over-TLS and/or DNS-over-HTTPS by giving them an address. If no certificate is provided, a self-signed certificate for `localhost` is generated at startup (for local testing only):

```bash
./target/release/mini-dns --dot-addr 127.0.0.1:8853 --doh-addr 127.0.0.1:8443
```

DoH exposes `/dns-query` (RFC 8484) over HTTP/1.1 and HTTP/2 (served by `hyper`, with connection keep-alive), accepting `POST` with an `application/dns-message` body or `GET ?dns=<base64url>`.

### Querying

```bash
dig @127.0.0.1 -p 8888 example.com A
dig +tcp @127.0.0.1 -p 8888 example.com A   # force TCP
dig @127.0.0.1 -p 8888 google.com A         # forwarded recursively

# DNS-over-TLS (requires a DoT-capable client, e.g. kdig)
kdig +tls @127.0.0.1 -p 8853 example.com A

# DNS-over-HTTPS over HTTP/2 (raw DNS message via curl; -k trusts the self-signed cert)
printf '\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01' \
  | curl -sk --http2 -H 'content-type: application/dns-message' \
      --data-binary @- https://127.0.0.1:8443/dns-query | xxd
```