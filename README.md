# adguard-exporter

A minimal Prometheus exporter for [AdGuard Home](https://github.com/AdguardTeam/AdGuardHome).

- Go standard library only, no third-party modules
- One static binary in a `scratch` image, running as a non-root user
- Monitors several AdGuard Home instances from one process
- Metric names and the `ADGUARD_*` variables match
  [henrywhitaker3/adguard-exporter](https://github.com/henrywhitaker3/adguard-exporter),
  so it can replace it without changing dashboards

Each scrape of `/metrics` queries `/control/status` and `/control/stats` of every instance; there is
no background polling or state.

## Usage

```yaml
services:
  adguard-exporter:
    image: ghcr.io/akchan/adguard-exporter:latest
    environment:
      ADGUARD_SERVERS: http://192.168.1.2,http://192.168.1.3
      ADGUARD_USERNAMES: admin           # one value applies to every server
      ADGUARD_PASSWORDS: secret1,secret2
    ports:
      - "9618:9618"
```

| Variable | Default | |
|---|---|---|
| `ADGUARD_SERVERS` | (required) | Comma-separated base URLs |
| `ADGUARD_USERNAMES` | empty | Comma-separated; one entry per server, or a single entry for all |
| `ADGUARD_PASSWORDS` | empty | Same rules as `ADGUARD_USERNAMES` |
| `LISTEN_ADDR` | `:9618` | Address of the metrics server |
| `SCRAPE_TIMEOUT` | `10s` | Timeout for querying all instances |

Endpoints: `/metrics`, `/healthz`.

## Metrics

All metrics carry a `server` label with the instance URL. AdGuard Home reports totals over its
statistics window (24 hours by default), so the query counts are gauges, not counters.

| Metric | Labels | |
|---|---|---|
| `adguard_up` | | 1 if the last scrape of the instance succeeded |
| `adguard_running` | | DNS server running |
| `adguard_protection_enabled` | | DNS filtering enabled |
| `adguard_info` | `version` | Always 1 |
| `adguard_queries` | | Queries in the stats window |
| `adguard_queries_blocked` | | Queries blocked by filter lists |
| `adguard_replaced_safebrowsing` | | Queries replaced by safe browsing |
| `adguard_replaced_safesearch` | | Queries replaced by safe search |
| `adguard_replaced_parental` | | Queries replaced by parental control |
| `adguard_avg_processing_time_seconds` | | Average processing time |
| `adguard_top_clients` | `client` | Queries per top client |
| `adguard_top_queried_domains` | `domain` | Queries per top domain |
| `adguard_top_blocked_domains` | `domain` | Blocked queries per top domain |
| `adguard_top_upstreams` | `upstream` | Responses per top upstream |
| `adguard_top_upstreams_avg_response_time_seconds` | `upstream` | Average upstream response time |

## Development

```sh
go vet ./... && go test ./...
docker build -t adguard-exporter .
```

The image is built and pushed to `ghcr.io/akchan/adguard-exporter` on every push to `main`, on
`v*` tags, and weekly so that Go security releases reach the image without code changes.

## License

MIT
