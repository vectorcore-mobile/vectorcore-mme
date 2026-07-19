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
| `operator.name.encoding` | Network name encoding: `gsm7` (default) or `ucs2` |
| `operator.nitz.timezone` | IANA timezone used for EMM Information NITZ fields, preferred over static offsets |

### EMM Information Operator Names

SIB1 advertises the numeric PLMN identity, such as MCC `311` and MNC `435`. The human-readable full and short operator names are sent separately by the MME in the NAS EMM Information procedure after attach or TAU, once NAS security is active.

Example:

```yaml
operator:
  name:
    full: "VectorCore Mobile"
    short: "VectorCore"
    show_full: true
    show_short: true
    encoding: "gsm7"        # gsm7 or ucs2
    add_country_initials: false
  nitz:
    enabled: true
    timezone: "America/Chicago"
    timezone_offset_minutes: -300
    daylight_saving: 1
    include_local_time_zone: true
    include_universal_time_and_local_time_zone: true
    include_daylight_saving_time: true
  emm_information:
    enabled: true
    send_after_attach: true
    send_after_tau: true
  tau:
    # Same-MME TAU does not reallocate GUTI by default. Enable only for a
    # deliberate privacy policy or interoperability test.
    reallocate_guti: false
```

`encoding: gsm7` uses the GSM 7-bit default alphabet and septet packing required by the NAS network-name IE. Characters outside the implemented GSM 7-bit default alphabet are encoded as `?`; use `ucs2` when the operator name needs non-GSM characters. Empty names are omitted, and EMM Information is not sent when the feature is disabled or no EMM Information IEs are configured.

When `operator.nitz.timezone` is set, the MME derives the local time-zone offset and daylight-saving indicator from that IANA zone for the timestamp being sent. The static `timezone_offset_minutes` and `daylight_saving` fields are fallback values for deployments that do not configure a timezone. Each optional NITZ IE can be enabled independently for interoperability testing. If a UE returns NAS `EMM Status` after EMM Information, the MME decodes and logs the EMM cause without detaching the UE.

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
| `GET /api/v1/ue` | List registered UEs with EMM/ECM/S1 connection state |
| `GET /api/v1/ue/{imsi}` | UE detail |
| `POST /api/v1/ue/{imsi}/page` | Trigger S1AP paging for a UE |
| `GET /api/v1/enodeb` | List connected eNBs |
| `GET /api/v1/operator` | Operator identity and NITZ config |
| `GET /api/v1/mme/recovery/ues` | List UE recovery DB records (not authoritative live state) |
| `GET /api/v1/mme/recovery/ues/{imsi}` | View one UE recovery record with session/event context |
| `DELETE /api/v1/mme/recovery/ues/disconnected` | Clear disconnected/stale recovery records after live-memory safety checks |
| `GET /metrics` | Prometheus metrics |

UE API entries include `emm_state`, `ecm_state`, `registration_status`, `connection_status`, and `s1_connected`. A UE can be `registration_status=registered` with `connection_status=idle` after radio loss or inactivity release; that state retains the EPS session and is not an explicit detach.

### NAS Feature Advertisement

IMS voice-over-PS support is disabled by default. Enable it only when IMS service and the `ims` APN are available:

```yaml
nas:
  eps_network_feature_support:
    ims_voice_over_ps: true
```

When enabled, Attach Accept and TAU Accept include EPS Network Feature Support IE `64 01 01`, advertising IMS voice-over-PS session support in S1 mode. When disabled, the optional IE is omitted.

### Gateway DNS Cache

S-GW and P-GW DNS selections are cached when `gateway_selection.dns.cache.enabled` is true. The cache stores successful selections and negative lookup results until their TTL expires.

Use `GET /api/v1/oam/dns-cache` to inspect cached query names, services, selected targets, addresses, expiry times, and errors. Use `POST /api/v1/oam/dns-cache/flush` after DNS changes to force the next S-GW/P-GW selection to query DNS again.

Run S1AP codec tests with:

```bash
go test ./internal/asn1/aper ./internal/s1ap/ies ./internal/s1ap
go test -fuzz=FuzzDecodeUEIDHelpers ./internal/s1ap/ies
```

## MME State Model

VectorCore MME keeps active UE, session, and procedure state in memory. The in-memory UE context is the runtime source of truth for:

- S1AP UE association state
- MME/eNB UE S1AP IDs
- NAS procedure state and timers
- S11 in-flight transactions
- paging, handover, and service request procedure state

The database is recovery-only. It stores last-known identity, GUTI, location, security algorithm indicators, APN/session summary, TEIDs, and recovery status for restart correlation, stale-session cleanup, observability, and future MME-pool/S10 work. The database is not used to decide whether a UE is currently connected.

### Recovery Database

The recovery DB stores:

- IMSI, IMEISV, MSISDN, call/context ID
- current GUTI, old GUTI, reallocated GUTI, and GUTI reallocation pending state
- last EMM/ECM state and recovery state
- NAS integrity/ciphering algorithm indicators and NAS counts
- last TAI/TAC, ECGI/eNB ID
- APN/session summary, UE IP, default EBI
- MME and S-GW S11 TEIDs/IP, P-GW info when known
- restart epoch and timestamps

`REALLOCATED GUTI` is identity-management state. It is not a handover or S10 transaction counter.

Same-MME TAU does not reallocate GUTI by default. In that mode, TAU completes when the TAU Accept is successfully sent; the MME must not wait for TAU Complete because no new GUTI was assigned.

During TAU with GUTI reallocation, such as inter-MME TAU or an explicitly enabled same-MME privacy policy, the old GUTI remains the primary in-memory identity until a valid TAU Complete is received. The newly allocated GUTI is stored as pending and both old and pending GUTIs resolve to the same UE during the T3450 window. TAU Complete commits the pending GUTI and removes the old alias; retransmitted TAU Requests using the old GUTI continue the same UE context instead of forcing a fresh attach.

### Restart Behavior

On startup, the MME generates a new restart epoch and marks older recovery records as `STALE_AFTER_RESTART`. It does not load database rows as active UE contexts.

When the S1-MME SCTP association closes, eNodeBs release UE-associated S1AP context tied to that MME. After an MME restart, UEs must return through normal LTE procedures such as Attach, TAU, Service Request, or Detach. The MME may use the recovery DB to map old GUTI to IMSI, correlate previous APN/session data, and clean stale SGW sessions, but it always creates new live in-memory S1/NAS context.

### Recovery API

List recovery records:

```bash
curl http://127.0.0.1:8085/api/v1/mme/recovery/ues
curl "http://127.0.0.1:8085/api/v1/mme/recovery/ues?stale_only=true"
```

Response records include `active_in_memory`, which is computed from the live in-memory UE registry, not from the database row.

View one record:

```bash
curl http://127.0.0.1:8085/api/v1/mme/recovery/ues/311435300070599
```

Clear disconnected/stale recovery records:

```bash
curl -X DELETE "http://127.0.0.1:8085/api/v1/mme/recovery/ues/disconnected?dry_run=true"
curl -X DELETE http://127.0.0.1:8085/api/v1/mme/recovery/ues/disconnected
```

The clear endpoint only clears disconnected/stale recovery records and cross-checks the active in-memory UE registry before deleting. It will not delete records for UEs currently active in memory, even if the DB row is stale.
