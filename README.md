# VectorCore MME

LTE Mobility Management Entity (MME) written in Go. Part of the [VectorCore](https://github.com/vectorcore-mobile)


## Features

- **S1AP** - eNB registration, UE attach/detach, TAU, service request, paging, S1/X2 handover
- **NAS** - full EMM/ESM encode/decode with EIA0/1/2 integrity and EEA0/1/2 ciphering (null, SNOW 3G, AES)
- **S6a** - AIR, ULR, CLR, IDR to VectorCore HSS over Diameter
- **S13 / EIR** - conditional Equipment-Check (ECR/ECA) for IMEI/IMEISV validation during attach
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
| `diameter.peers` | Shared Diameter peer endpoints; capabilities are discovered with CER/CEA |
| `gateway_selection.sgw.sgw_address` | Static S-GW S11 GTP-C fallback address |
| `gateway_selection.dns.*` | DNS-based S-GW/P-GW selection and in-memory cache settings |
| `database.db_type` | Database driver: `postgres` or `sqlite` |
| `database.*` | Database connection settings. For SQLite, `database.database` is the DB file path. |
| `operator.name.*` | Full/short network name sent to UEs via EMM Information |
| `operator.name.encoding` | Network name encoding: `gsm7` (default) or `ucs2` |
| `operator.nitz.timezone` | IANA timezone used for EMM Information NITZ fields, preferred over static offsets |

### Diameter peer routing

Diameter peers are shared by S6a today and S13, SGd, and future applications
later. Configure peer endpoints once under `diameter.peers`; do not configure a
peer or application list per Diameter application. The MME learns direct
application and Relay support from CER/CEA.

```yaml
diameter:
  origin_host: mme2.epc.mnc435.mcc311.3gppnetwork.org
  origin_realm: epc.mnc435.mcc311.3gppnetwork.org
  peers:
    - name: dra-1
      address: 10.90.250.35:3868
```

This is sufficient for a single DRA. A relay-capable DRA is the default route:
it receives an application only when no healthy direct peer advertises that
application. Think of direct application support as a more-specific IP route,
Relay support as the default route, and priority/configuration order as the
route metric. A direct S6a HSS therefore always beats a DRA for S6a, even if
the DRA has a lower priority number.

For two DRAs, configuration order is active/standby when priority is omitted:

```yaml
diameter:
  peers:
    - name: dra-1
      address: 10.90.250.35:3868
    - name: dra-2
      address: 10.90.250.36:3868
```

Both peers are connected and monitored; traffic uses `dra-2` only when `dra-1`
is not usable. To set the metric explicitly, use a lower `priority` number.
Priority applies only among direct peers or only among relay peers; it never
makes a relay win over a direct application peer.

```yaml
diameter:
  peers:
    - name: dra-1
      address: 10.90.250.35:3868
      priority: 10
    - name: dra-2
      address: 10.90.250.36:3868
      priority: 20
```

Mixed direct HSS and DRA deployments need no per-app configuration:

```yaml
diameter:
  peers:
    - name: dra-1
      address: 10.90.250.35:3868
    - name: hss-1
      address: 10.90.250.40:3868
      transport: sctp
```

If `hss-1` advertises S6a and `dra-1` advertises Relay, S6a uses `hss-1`;
S13 and SGd use `dra-1` until direct peers advertise those applications. If
`hss-1` becomes unavailable, S6a falls back to the healthy DRA.

`transport` is `tcp` by default and may be `sctp`. To accept peer-initiated
Diameter connections, set both `diameter.bind_addr` and
`diameter.bind_transport` (`tcp` or `sctp`; TCP is the default). Direct requests use the learned direct peer Origin-Host as
Destination-Host. Relay requests use Destination-Realm only: the DRA's own
Origin-Host is never used as Destination-Host.

### S6a request defaults

The `s6a.air` and `s6a.ulr` blocks shape requests after a Diameter peer has
already been selected; they do not select or configure peers. They may be
omitted when the defaults are appropriate:

```yaml
s6a:
  air:
    requested_vectors: 1              # one LTE authentication vector per AIR
    immediate_response_preferred: true # request immediate HSS answer
  ulr:
    flags: 2 # S6a/S6d-Indicator (bit 2), normal LTE attach/update location
```

### S13 equipment checks

S13 queries an Equipment Identity Register during attach. It is disabled by
default; disabled S13 sends no ECR and does not advertise application
`16777252` in CER/CEA. When enabled, the shared Diameter router selects only
an S13-capable peer (or relay), optionally using `peer` as Destination-Host.

```yaml
s13:
  enabled: true
  peer: "eir.epc.mnc435.mcc311.3gppnetwork.org" # optional
  check_on_attach: true
  failure_policy: "allow" # EIR outage: allow or reject
  whitelist_policy: "allow"
  blacklist_policy: "reject"
  greylist_policy: "allow"
  timeout: "5s"
```

IMEI/IMEISV values are validated before an ECR is sent. IMEISV is a 16-digit
string: its first 14 digits form the IMEI body and its final two are software
version. S13 sends the resulting 15-digit IMEI, with its Luhn check digit
calculated from that 14-digit body, and includes the two-digit Software-Version
AVP. For example, IMEISV `0150930051491618` becomes IMEI
`015093005149164`. Equipment identities remain strings throughout so leading
zeros are preserved. The default policy
allows whitelisted and greylisted equipment and rejects blacklisted equipment
with NAS cause *IMEI not accepted*. `failure_policy: allow` is fail-open and
does not mean the EIR approved the device. Normal logs must use masked
equipment identities. When S13 attach checking is enabled, the Security Mode
Command requests IMEISV; if a UE omits it in Security Mode Complete, the MME
sends a protected NAS Identity Request for IMEISV before it sends ECR. Seeing
application `16777252` only in CER/CEA proves capability advertisement; a
successful check also has Diameter command `324` (ECR/ECA).

For a blacklist test using normalized IMEI `015093005149164`, expect
`s13: ECA received` with `equipment_status_name=blacklisted`, followed by
`s1ap: Attach Reject sent reason=s13-equipment-blacklisted` and EMM cause
`IMEI not accepted` (cause 5). No subsequent `s6a: ULR sent`, S11 Create
Session, or Initial Context Setup indicates that attach continuation was
correctly blocked.

S13 identity log fields are privacy-scoped: INFO and WARN contain only
`masked_imei="015093******164"`. DEBUG logging adds full
`imei="015093005149164"` (the normalized 15-digit EIR value) and
`imeisv="0150930051491618"` (the original 16-digit UE value). They are never
interchanged.

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

## S1AP APER Codec Notes

VectorCore currently uses a hand-written APER codec for the implemented S1AP subset. S1AP message builders should construct typed IE values through shared helpers in `internal/s1ap/ies` and `internal/s1ap/pdu`; do not manually splice nested ASN.1 CHOICE or SEQUENCE byte strings.

The UE S1AP ID helpers follow TS 36.413 constraints:

- `MME-UE-S1AP-ID ::= INTEGER (0..4294967295)`
- `ENB-UE-S1AP-ID ::= INTEGER (0..16777215)`
- `UE-S1AP-IDs` is a CHOICE; the `uE-S1AP-ID-pair` arm is packed immediately after the CHOICE selector with no byte alignment between the selector and the selected SEQUENCE.

Large constrained whole numbers use the APER constrained length determinant followed by byte alignment and the minimal non-negative-binary-integer value octets. The decoder is length-safe and accepts the Ericsson-observed padded eNB UE ID open-type form `00 00 00 01` for interop, while the encoder emits the canonical APER form.

`InitialContextSetupRequest` encodes `UESecurityCapabilities` as the TS 36.413 S1AP structure, not by copying NAS capability octets directly. The NAS EEA/EIA bitmaps from the Attach Request are mapped into the high bits of the 16-bit S1AP `encryptionAlgorithms` and `integrityProtectionAlgorithms` BIT STRINGs with the S1AP spare bit clear.

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

### EPS Detach

ECM-IDLE is not EPS detach. A UE released for radio inactivity remains `EMM-REGISTERED` and can later resume by Service Request.

For UE-originated EPS detach, including detach from ECM-IDLE, the UE may send NAS `DETACH REQUEST` (`0x45`) inside S1AP `InitialUEMessage` because there is no active UE-associated S1 signalling context. The MME resolves the existing UE by S-TMSI/GUTI, verifies NAS security with the stored EPS security context, decodes the Detach Type, and starts S11 Delete Session.

Switch-off detach suppresses NAS Detach Accept. Non-switch-off detach sends Detach Accept protected with the active NAS security context. After successful core-side teardown the active UE/session/bearer state is removed from memory and recovery records are marked detached/inactive.

Do not remove an `EMM-REGISTERED` UE merely because its S1/RRC context was released or because RF connectivity disappeared. Explicit detach and implicit detach are separate procedures.

The live UE API exposes this distinction. `s1_connected=false` with `EMM-REGISTERED` / `ECM-IDLE` means the UE is registered but not currently on a UE-associated S1 connection. `last_release_cause` records the most recent S1 release reason, for example `radio-connection-with-ue-lost`.

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
