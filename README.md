# VectorCore MME

LTE Mobility Management Entity (MME) written in Go. Part of the [VectorCore](https://github.com/vectorcore-mobile)


## Features

- **S1AP** - eNB registration, UE attach/detach, TAU, service request, paging, S1/X2 handover
- **NAS** - full EMM/ESM encode/decode with EIA0/1/2 integrity and EEA0/1/2 ciphering (null, SNOW 3G, AES)
- **S6a** - AIR, ULR, CLR, IDR to VectorCore HSS over Diameter
- **S11 GTPv2-C** - CSR, MBR, DSR to S-GW/P-GW
- **S10 GTPv2-C** - inter-MME context transfer (idle-mode TAU across MME pools)
- **EMM Information** - operator name and NITZ timezone push after attach/TAU
- **OAM REST API** - eNB, UE, operator, DNS cache, embedded React UI, Huma docs, and Prometheus metrics
- **Gateway selection** - DNS NAPTR-based S-GW/P-GW selection with static fallback and in-memory cache controls
- **APER codec** - hand-written, reflection-driven; no external ASN.1 library

## Requirements

- Go 1.22+
- Node.js 18+ (for the web UI)
- Linux kernel with SCTP support (`sctp` module or built-in)
- PostgreSQL 14+ or SQLite

## Build

```bash
# Build UI + binary
make all

# Binary only (skips UI rebuild)
make build

# Print the version value used by the Makefile/ldflags
make version

# Run tests
make test
```

The binary is written to `bin/mme`.

## Configuration

Copy the example config and fill in your values:

```bash
cp config/mme.yaml.example config/mme.yaml
```

Key fields:

| Field | Description |
|---|---|
| `nf.mcc` / `nf.mnc` | Your PLMN |
| `s1ap.bind_address` | IP the MME listens on for eNB SCTP connections (port 36412) |
| `s6a.peer_address` | S6a Diameter peer endpoint |
| `gateway_selection.sgw.sgw_address` | Static S-GW S11 GTP-C fallback address |
| `gateway_selection.dns.*` | DNS-based S-GW/P-GW selection and in-memory cache settings |
| `database.db_type` | Database driver: `postgres` or `sqlite` |
| `database.*` | Database connection settings. For SQLite, `database.database` is the DB file path. |
| `operator.name.*` | Full/short network name sent to UEs via EMM Information |

## Run

```bash
bin/mme -c config/mme.yaml
```

Useful flags:

| Flag | Description |
|---|---|
| `-c <path>` | Config file path. Defaults to `config/mme.yaml`. |
| `-v` | Print version information and exit. |
| `-d` | Enable debug-level console logging. File logging remains at the YAML-configured level. |

Without `-d`, startup prints only `Starting VectorCore-MME` to the console; structured logs go to the configured log file when `logging.file` is set.

## Install as a systemd service

```bash
sudo make install
```

Installs to `/opt/vectorcore/bin/mme`, config to `/opt/vectorcore/etc/mme.yaml`, and enables `vectorcore-mme.service`.

## OAM API

The REST API is available at `http://<host>:8085/api/v1` by default.

Interactive Huma docs are mounted at:

```text
http://<host>:8085/docs
```

The OpenAPI document is available at:

```text
http://<host>:8085/openapi.json
```

| Endpoint | Description |
|---|---|
| `GET /api/v1/oam/version` | MME version and NF identity |
| `GET /api/v1/oam/health` | Health, uptime, eNB/UE counts, and S6a status |
| `GET /api/v1/oam/dns-cache` | View in-memory gateway DNS cache entries |
| `POST /api/v1/oam/dns-cache/flush` | Flush gateway DNS cache entries to force fresh lookups |
| `GET /api/v1/ue` | List attached UEs |
| `GET /api/v1/ue/{imsi}` | UE detail |
| `POST /api/v1/ue/{imsi}/page` | Trigger S1AP paging for a UE |
| `GET /api/v1/enodeb` | List connected eNBs |
| `GET /api/v1/operator` | Operator identity and NITZ config |
| `GET /metrics` | Prometheus metrics |

### Gateway DNS Cache

S-GW and P-GW DNS selections are cached when `gateway_selection.dns.cache.enabled` is true. The cache stores successful selections and negative lookup results until their TTL expires.

Use `GET /api/v1/oam/dns-cache` to inspect cached query names, services, selected targets, addresses, expiry times, and errors. Use `POST /api/v1/oam/dns-cache/flush` after DNS changes to force the next S-GW/P-GW selection to query DNS again.
