# VectorCore MME

LTE Mobility Management Entity (MME) written in Go. Part of the [VectorCore](https://github.com/vectorcore-mobile)


## Features

- **S1AP** - eNB registration, UE attach/detach, TAU, service request, paging, S1/X2 handover
- **NAS** - full EMM/ESM encode/decode with EIA0/1/2 integrity and EEA0/1/2 ciphering (null, SNOW 3G, AES)
- **S6a** - AIR, ULR, CLR, IDR to VectorCore HSS over Diameter
- **S13 / EIR** - conditional Equipment-Check (ECR/ECA) for IMEI/IMEISV validation during attach
- **SLg** - disabled-by-default TS 29.172 Diameter PLR/PLA and LRR/LRA wire support
- **SLs / E-SMLC** - optional TS 29.171 SCTP/LCS-AP positioning interface, including bounded SLg location transactions and transparent UE-associated LPP/LPPa relay
- **SMS in MME / SGd** - EPS-only S6a SMS registration, protected SMS-over-NAS CP/RP handling, MO OFR, MT TFR, ECM-IDLE paging coordination, and Cisco `ascii_digits` SC-Address interoperability
- **SGs-AP** - TS 29.118 MME-to-VLR association (outbound SCTP, node-level Reset procedure), `smsonly`/full-CSFB config, genuine combined Attach/TAU with real VLR-assigned LAI once the SGs Location Update succeeds, SMS-over-SGs relay in both directions, and MT/MO CS Fallback paging (VLR-paged MT, Extended-Service-Request-triggered MO)
- **S11 GTPv2-C** - CSR, MBR, DSR to S-GW/P-GW
- **S8HR roaming** - verified HPLMN/VPLMN admission, home-HSS S6a routing, visited-SGW selection, and home-PGW selection over S8
- **S10 GTPv2-C** - inter-MME context transfer (idle-mode TAU across MME pools)
- **PWS / SBc-AP** - MME-side LTE public-warning interface for CBC-initiated Write-Replace and Stop Warning, S1AP eNB routing, completed/cancelled-area indications, and typed PWS Restart/Failure forwarding
- **EMM Information** - operator name and NITZ timezone push after attach/TAU
- **OAM REST API** - eNB, UE, operator, DNS cache, embedded React UI, Huma docs, and Prometheus metrics
- **Gateway selection** - DNS NAPTR-based S-GW/P-GW selection with static fallback and in-memory cache controls
- **Recovery & restart persistence** - SQLite-backed UE/session recovery store surviving MME restart, GUTI correlation (old/pending/reallocated) across TAU and re-attach, restart-epoch stale marking, and a recovery REST API
- **NB-IoT / LTE-M** - RAT determination from tracking-area config, HSS Access-Restriction-Data enforcement (NB-IoT-not-allowed, LTE-M-not-allowed, WB-E-UTRAN-except-LTE-M) on attach, TAU, and inter-MME TAU with live re-check on TAC change, and UE Capability LTE-M Indication decode triggering re-evaluation; standard LTE data path only, no CP-CIoT/Non-IP PDN optimization or PSM/eDRX yet
- **EN-DC / 5G NSA restriction control** - UE DCNR capability detection, HSS Access-Restriction-Data NR-as-secondary-RAT enforcement, NAS RestrictDCNR signaling, and Handover Restriction List propagation kept current across Attach, TAU, Handover, Path Switch, and S1 Setup refresh; no Secondary-RAT-Data-Usage-Report (TS 36.413 procedure 52) charging relay yet
- **APER codec** - hand-written, reflection-driven; no external ASN.1 library

## Planed Features:
- N26 interface - MME to AMF GTP-C
## Requirements

- Go 1.22+
- Node.js 18+ (for the web UI)
- Linux kernel with SCTP support (`sctp` module or built-in)
- SQLite (used for the UE/session recovery store)

## Build

```bash

# Clean the bin dir
make clean

# Build UI + binary
make 

# Run tests
make test
```

The binary is written to `bin/mme`.

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
