# Configuration

Copy the example config and fill in your values:

```bash
cp config/mme.yaml.example config/mme.yaml
```

Key fields:

| Field | Description |
|---|---|
| `nf.mcc` / `nf.mnc` | Your PLMN |
| `s1ap.bind_address` | IP the MME listens on for eNB SCTP connections (port 36412) |
| `sbcap.*` | Optional CBC-initiated LTE public-warning SCTP listener (port 29168, PPID 24) |
| `diameter.peers` | Shared Diameter peer endpoints; capabilities are discovered with CER/CEA |
| `sgd.*` | SMS-in-MME/SGd enablement, S6a registration behavior, SMSC address encoding, and transaction timeout |
| `slg.*` | Optional SLg Diameter application enablement and bounded in-memory transaction lifetime |
| `sls.*` | Optional outbound E-SMLC SCTP association, positioning transaction limits, and LCS-AP PDU size limit |
| `gateway_selection.sgw.sgw_address` | Static S-GW S11 GTP-C fallback address |
| `gateway_selection.dns.*` | DNS-based S-GW/P-GW selection and in-memory cache settings |
| `*.qos.dscp` | Optional fixed outbound control-plane DSCP (0–63); `24` is CS3 |
| `database.*` | SQLite-backed recovery store settings. `database.database` is the DB file path. |
| `operator.name.*` | Full/short network name sent to UEs via EMM Information |
| `operator.name.encoding` | Network name encoding: `gsm7` (default) or `ucs2` |
| `operator.nitz.timezone` | IANA timezone used for EMM Information NITZ fields, preferred over static offsets |
| `roaming.*` | Home-routed roaming admission and HSS destination policy; S8 PGW selection uses HSS data or HPLMN DNS |

## Outbound control-plane DSCP

Each MME control-plane transport may set a fixed outbound DSCP value with an
optional `qos.dscp` field. The value is the unshifted six-bit DSCP number from
`0` through `63`; VectorCore writes `dscp << 2` to IPv4 `IP_TOS` or IPv6
`IPV6_TCLASS`. For example, decimal `24` (CS3) produces traffic class `0x60`.

```yaml
s1ap: {qos: {dscp: 24}}
sbcap: {qos: {dscp: 24}}
diameter: {qos: {dscp: 24}}
s10: {qos: {dscp: 24}}
s11: {qos: {dscp: 24}}
```

Omit `qos` (or `qos.dscp`) to retain the operating-system socket default.
`dscp: 0` is explicit CS0 and is different from omission. Marking applies only
to packets transmitted by the MME; VectorCore neither reads nor copies DSCP
from received packets. Diameter has exactly one common setting for all peers,
TCP/SCTP transports, applications, requests, answers, watchdogs, and retries;
peer-level or application-level Diameter QoS is not supported. DSCP 24 is an
operator policy example, not a 3GPP requirement.

## Diameter peer routing

Diameter peers are shared by S6a today and S13, SGd, and future applications
later. Configure peer endpoints once under `diameter.peers`; do not configure a
peer or application list per Diameter application. The MME learns direct
application and Relay support from CER/CEA.

## Home-routed roaming (Phase 3)

The `roaming` block is disabled by default. Phase 3 validates typed MCC/MNC
PLMNs, resolves an HPLMN only after IMSI verification, evaluates its HPLMN ACL,
and sends AIR/ULR to the selected HSS realm/optional host. The Visited-PLMN-Id
is the accepted Initial UE Message TAI PLMN; it is not the MME realm, Global
eNB ID, or configured local PLMN. MCC and MNC must be quoted strings; MNC
length and leading zeroes are preserved.

```yaml
roaming:
  enabled: false
  policy:
    default_action: deny
    plmn_acl:
      - plmn: {mcc: "310", mnc: "260"}
        action: allow
  hss_routes:
    - plmn: {mcc: "310", mnc: "260"}
      realm: epc.mnc260.mcc310.3gppnetwork.org
      host: hss01.epc.mnc260.mcc310.3gppnetwork.org
```

An exact ACL match overrides `default_action`; an HSS route never authorizes a
subscriber. A missing route realm is generated as
`epc.mnc<MNC padded to 3>.mcc<MCC>.3gppnetwork.org`.

For an allowed home-routed roamer, the MME selects a visited SGW using the
serving VPLMN/TAC and sends S11 only to that SGW. It selects the home PGW from
the HSS APN configuration first, then HPLMN-rooted NAPTR using
`x-3gpp-pgw:x-s8-gtp`; static local S5 fallback is deliberately disabled for
S8. The MME supplies the selected home PGW S5/S8-C address in its ordinary S11
Create Session Request; it does not establish S8 or carry user plane traffic.
The existing Create Session codec uses TS 29.274 combined S5/S8 PGW interface
type 7, which is applicable to this home-routed request.

The S8 DNS name is `<apn>.apn.epc.mnc<MNC padded to 3>.mcc<MCC>.3gppnetwork.org`
using the subscriber HPLMN—not the visited PLMN or custom HSS realm. An HSS
APN-OI-Replacement, when present and syntactically valid, replaces only that
operator identifier. Local breakout, persistence across restart, and live
roaming interoperability validation are not implemented.

Attach-reject mapping follows TS 24.301: disabled roaming and HPLMN ACL denial
use cause 14, *EPS services not allowed in this PLMN*, because the current
policy is VPLMN-wide. Cause 13, *roaming not allowed in this tracking area*,
is reserved for a future TAC-specific roaming policy. Unresolved, ambiguous,
or malformed IMSI identity uses cause 9, *UE identity cannot be derived by the
network*. An S8 PGW-selection failure is rejected before S11 and never falls
back to the local S5 PGW. Local breakout, persistence across restart, and live
roaming interoperability validation remain future work.

## SLs / E-SMLC positioning interface

SLs is disabled by default. When enabled, the MME maintains one outbound SCTP
association to the configured E-SMLC and uses TS 29.171 SCTP PPID 29. A valid
SLg current-location PLR for a registered UE with a serving ECGI creates one
bounded LCS-AP Location Request transaction. The E-SMLC Location Response is
correlated by the four-octet LCS correlation identifier and only an actual
returned Location Estimate is placed into the PLA. No coordinates are created
from serving-cell data.

The implementation is native Go: it extends `internal/asn1/aper`, with typed
LCS-AP PDU and protocol-IE containers. Rust, Cargo, cgo, C libraries and an
external ASN.1 encoder are not required for this feature.

```yaml
sls:
  enabled: true
  local_address: "192.0.2.20"
  local_port: 0
  remote_address: "192.0.2.30"
  remote_port: 9082
  reconnect_interval: "5s"
  request_timeout: "10s"
  max_transactions: 1024
  max_pdu_size: 1048576
```

Supported MME-side LCS-AP procedures are Location Request/Response, inbound
Location Abort, and inbound Reset with Reset Acknowledge. Error Indication,
connectionless-information, assistance-data, and full LPP/LPPa/S1AP
positioning relay procedures are unsupported and rejected safely by procedure
criticality. UE-associated LPPa is supported as an opaque relay using S1AP
Downlink/Uplink UE-Associated LPPa Transport (procedure codes 44/45, Routing-ID
IE 148 and LPPa-PDU IE 147). The MME verifies the active UE S1 binding and
Routing-ID before relaying upstream; it does not decode LPPa. Non-UE-associated
LPPa (46/47) remains unsupported. LPP is relayed transparently through EPS
Downlink/Uplink Generic NAS Transport using Generic Message Container Type
`0x01` (LPP). Downlink LPP uses the normal protected NAS/S1AP path and uplink
LPP is accepted only after normal NAS integrity verification; payloads are
bounded to the 16-bit NAS container length and are never decoded by the MME.
For an ECM-IDLE UE, LPP is retained as a bounded FIFO (four messages per UE)
owned by the active SLs transaction, and the existing S1AP pager is triggered
once. After a successful Service Request has restored the S1 binding and NAS
security context, the protected Downlink Generic NAS Transport messages are
sent in arrival order. The SLs transaction timeout bounds pending delivery;
transaction completion, cancellation, association loss, eNB loss and shutdown
discard the queue before a stale resume can send it. Live UE/eNB/E-SMLC
interoperability remains unvalidated. Association loss, timeout, cancellation
and shutdown fail the associated SLg request with positioning failure and
remove its transaction.
Unavailable E-SMLC service affects only location requests; normal EPS control
plane operation continues and reconnect uses the configured bounded interval.

## SBc-AP public warning interface

SBc-AP is disabled by default. When enabled, the MME listens for SCTP
associations initiated by configured CBC peers on port `29168` and validates
SCTP PPID `24`. Configure each CBC with its source IP address; SBc-AP has no
application setup exchange, so unlisted sources are rejected.

```yaml
sbcap:
  enabled: true
  bind_address: "192.0.2.20"
  port: 29168
  transaction_timeout: "30s"
  # Temporary compatibility only; standards-strict default is false.
  accept_legacy_ppid_zero: false
  peers:
    - name: "osmo-cbc"
      addresses: ["192.0.2.10"]
```

SBc-AP YAML fields:

| Field | Required | Description |
|---|---:|---|
| `sbcap.enabled` | No | Enables the MME-side SBc-AP SCTP server. Default: `false`. |
| `sbcap.bind_address` | When enabled | Local SCTP listen address for CBC associations. |
| `sbcap.port` | No | SBc-AP SCTP port. Default: `29168`. |
| `sbcap.transaction_timeout` | No | Maximum time to collect selected eNB Write-Replace/Kill results before sending a partial indication. |
| `sbcap.accept_legacy_ppid_zero` | No | Temporary OsmoCBC compatibility switch. Default: `false`; PPID 24 remains the normal requirement. |
| `sbcap.peers[].name` | Yes | Operational name for the admitted CBC peer. |
| `sbcap.peers[].addresses` | Yes | CBC source IP address or addresses admitted for that peer. |

The MME routes a Global eNB ID only to that connected eNB, List-of-TAIs only
to connected eNBs serving those TAs, and uses all connected eNBs only when no
target selector is provided. Warning Area List is passed through for eNB cell
selection. The CBC remains the sole owner of warning persistence, expiration,
cancellation, and reload decisions; the MME does not replay cached warnings
after a PWS restart.

3GPP SBc-AP uses SCTP PPID `24`, and VectorCore always transmits responses
and indications using PPID `24`. OsmoCBC 0.5.3 has been observed sending
client-mode SBc-AP DATA with non-standard PPID `0`; Open5GS does not validate
the inbound PPID, which can hide that defect. For a temporary migration only,
`accept_legacy_ppid_zero: true` accepts PPID `0` from an already admitted CBC
peer while retaining normal APER, procedure, and IE validation. It never
accepts other PPIDs, does not identify SBc-AP by port alone, and never mirrors
PPID `0` on outbound traffic. Disable the option after installing an upstream
OsmoCBC fix or when using a standards-correct CBC. Upstream issue: **TBD**.

PWS restart/failure forwarding and completed/cancelled-area indications are
decoded into typed LTE identities before they are re-encoded for SBc-AP. The
MME rejects malformed nested APER lists rather than forwarding their raw
open-type payloads to a CBC. Completed/cancelled reports from selected eNBs
are collected for the configured transaction timeout; partial valid cell
results are reported when that timeout expires.

## eNB Supported TA topology

During S1 Setup, an eNB supplies a Global eNB ID and one or more Supported TA
entries. Each Supported TA is a TAC plus one or more Broadcast PLMNs; a TAI is
the complete pair **PLMN + TAC**, never a TAC alone. VectorCore decodes and
stores the full advertised topology, including network-sharing Broadcast PLMNs,
then derives the accepted subset by intersecting it with `nf.tai_list`.

The Global eNB ID PLMN is not required to equal every Broadcast PLMN. S1 Setup
is accepted when at least one advertised Broadcast PLMN/TAC combination is
served by this MME; an eNB with no intersection is rejected with the S1AP
`misc: unknown-PLMN` cause. TS 36.413 defines no separate "unknown TAI" cause.
The accepted topology is used for TAI-targeted paging and SBc-AP List-of-TAIs
routing. PLMN values are compared as typed MCC/MNC values, preserving two- vs
three-digit MNCs; for example S1AP PLMN `13 41 53` is MCC `311`, MNC `435`.

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

## S6a request defaults

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

## S13 equipment checks

## SMS in MME / SGd registration

SGd is disabled by default. Enabling it advertises Diameter application
`16777313` in CER/CEA and reuses the existing direct-peer/DRA capability
selection; it does not add peer, route, Destination-Host, or realm settings.
Eligible EPS-only Attach and TAU ULRs request SMS-in-MME registration by
default. An HSS rejection leaves the EPS procedure successful but marks that
UE unavailable for SMS in MME.

```yaml
sgd:
  enabled: true
  subscribe_eps_only_attach: true
  smsc_address: "+15551230000"
  sgd_sc_address_encoding: "ascii_digits" # use "tbcd" for standards default
  transaction_timeout: "30s"
  mme_number_for_mt_sms: "+15551230001"
```

Both values are E.164 presentation numbers. `mme_number_for_mt_sms` is always
TBCD without TON/NPI, as required by S6a. SC-Address uses
`sgd_sc_address_encoding`, which defaults to standards-compliant `tbcd`; set
it to `ascii_digits` when interoperating with deployed Cisco SMSCs. Configure
the SMSC with the matching `smsc.sgd_sc_address_encoding` value.

`transaction_timeout` bounds waiting for an SGd answer or a UE MT response;
it defaults to `30s`. SMS payload content is never emitted in normal logs.
The MME exposes `mme_sms_mo_requests_total`, `mme_sms_mt_requests_total`,
`mme_sms_mt_paging_total`, `mme_sms_alert_service_centre_total`,
`mme_sms_active_transactions`, `mme_sms_timer_expirations_total`, and
`mme_sms_duplicate_messages_total` with bounded result labels. SGd configuration does
not create Diameter routes: the existing direct-peer/DRA application-capability
selection remains authoritative.

MO SMS is carried as protected Uplink NAS Transport CP/RP data. The MME
extracts the TPDU for SGd OFR and rebuilds the RP layer for the UE response.
MT SMS is accepted as TFR, converted from SGd TPDU into protected Downlink NAS
Transport CP/RP data for ECM-CONNECTED UEs, and completes TFA only after the
UE RP acknowledgement. For an ECM-IDLE UE the MME queues the deferred TFR and
uses the existing S1AP pager. Once Service Request re-establishment succeeds,
it sends Alert Service Centre to the SMSC; the SMSC retries a fresh TFR rather
than the MME retaining the original Diameter transaction through paging.

### SMS-in-MME lab checklist

1. Enable `sgd.enabled`, choose the matching SC-Address encoding on the MME
   and SMSC, then confirm the DRA observes application `16777313` from the MME.
2. Attach an EPS-only UE and verify the HSS subscriber record has
   `mme_registered_for_sms: true`, `sms_register_request: 0`, and the expected
   MME number.
3. Send MO SMS from the UE and confirm an OFR/OFA exchange without logging SMS
   payload content.
4. Send MT SMS while the UE is ECM-CONNECTED and confirm TFR/TFA is completed
   only after the UE RP acknowledgement.
5. Release the UE to ECM-IDLE, send MT SMS, confirm existing S1AP paging and
   Service Request occur, then confirm the MME sends ALR and the SMSC retries
   a fresh TFR after re-establishment.
6. Confirm only a deferred MT transaction triggers ALR; ordinary ECM-CONNECTED
   Service Requests must not create an alert.

## Interoperability and current limits

The deployed VectorCore SMSC accepts Alert Service Centre on the SGd
application during deferred MT retry. The adapter isolates that compatibility
behavior from NAS and shared SMS transaction code; operators should validate
their SMSC/DRA behavior before enabling it in production. The HSS and SMSC
source trees are used only as protocol-interoperability references: this MME
does not import, link, or require either repository at build or runtime.
See [SMS-in-MME SGd architecture](sms-in-mme-sgd.md) for the layer and
deferred-MT flow boundaries.

Active CP/RP, pending Diameter, and pending paging SMS transactions are
in-memory only. They are discarded on MME restart; the normal S6a ULR refresh
restores per-subscriber eligibility. SMS over IMS is not included in this
release. SMS over SGs is now implemented (see [SGs-AP](sgs-ap.md)) as a
transparent NAS-message-container relay, independent of the CP/RP state
machine SGd uses.

S13 queries an Equipment Identity Register during attach. It is disabled by
default; disabled S13 sends no ECR and does not advertise application
`16777252` in CER/CEA. When enabled, the shared Diameter router selects only
an S13-capable peer (or relay). Direct S13 peers receive Destination-Host from
the selected route; DRA relay requests use Destination-Realm only.

```yaml
s13:
  enabled: true
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

## EMM Information Operator Names

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
