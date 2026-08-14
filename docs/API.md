# OAM API

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

## MME reachability lifecycle

`nas.timers.t3412` is the UE-facing periodic TAU timer. The MME separately
uses `emm_timers.mobile_reachable_guard_seconds` and
`emm_timers.implicit_detach_seconds`. On ECM-IDLE entry, the MME starts a
mobile-reachable timer of the effective encoded T3412 value plus the guard
(default `3240 + 240` seconds). Its expiry marks the UE unreachable and starts
the implicit-detach grace period (default 300 seconds); it does not release
S1 resources or delete PDNs. A verified UE return cancels the grace period and
keeps bearer state. If the grace period expires, one S11 Delete Session Request
is issued per remaining PDN and ordinary detached-context cleanup finalizes the
indexes after responses. A zero guard is valid; implicit detach must be
positive. In-memory contexts do not survive restart; database recovery remains
the existing stale-session recovery mechanism. UE API responses expose the
reachability state, timer deadlines/remaining values, refresh reason, and
terminal-cleanup flag.

Reachability snapshots are written and restored only when `database.mode` is
not `memory`. In-memory mode writes no reachability recovery records and an
MME restart discards UE state after normal shutdown stops all UE timers.

## NAS Feature Advertisement

IMS voice-over-PS support is disabled by default. Enable it only when IMS service and the `ims` APN are available:

```yaml
nas:
  eps_network_feature_support:
    ims_voice_over_ps: true
```

When enabled, Attach Accept and TAU Accept include EPS Network Feature Support IE `64 01 01`, advertising IMS voice-over-PS session support in S1 mode. When disabled, the optional IE is omitted.

## Gateway DNS Cache

S-GW and P-GW DNS selections are cached when `gateway_selection.dns.cache.enabled` is true. The cache stores successful selections and negative lookup results until their TTL expires.

Use `GET /api/v1/oam/dns-cache` to inspect cached query names, services, selected targets, addresses, expiry times, and errors. Use `POST /api/v1/oam/dns-cache/flush` after DNS changes to force the next S-GW/P-GW selection to query DNS again.
