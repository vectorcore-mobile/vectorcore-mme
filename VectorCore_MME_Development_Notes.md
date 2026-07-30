# VectorCore MME Development Notes

## 1. Interface Status and Planning

| Interface         | Connected Node       | Purpose                                                                    | Current Status                       | Required Work                                                                    | Priority     |
| ----------------- | -------------------- | -------------------------------------------------------------------------- | ------------------------------------ | -------------------------------------------------------------------------------- | ------------ |
| **S1-MME / S1AP** | eNodeB               | LTE access signaling                                                       | Implemented                          | continue interoperability testing                                                | N/A          |
| **S6a**           | HSS                  | Subscriber authentication, location management, and subscription retrieval | Implemented                          | improve peer resiliency and overload handling                                    | N/A          |
| **S10**           | MME                  | MME-to-MME context transfer and mobility                                   | Implemented or partially implemented | Complete interoperability, relocation, restart, and failure testing              | N/A	         |
| **S11**           | SGW-C                | Session and bearer control using GTPv2-C                                   | Implemented                          | continue recovery validation                                                     | N/A          |
| **S13**           | EIR                  | Equipment identity checking                                                | Implemented                          | Completed  								          | N/A          |
| **SBc-AP**        | CBC                  | Public Warning System signaling                                            | Implemented                          | warning-area handling, message lifecycle, and FSMs, testing                      | N/A          |
| **SGsAP**         | MSC/VLR              | CS fallback and SMS over SGs                                               | Not implemented                      | Research protocol, mobility state, SMS handling, and FSMs                        | Low          |
| **SGd**           | SMS-GMSC / SMS-IWMSC | SMS delivery using Diameter                                                | Implemented  	                       | Completed 								          | N/A          |
| **S3**            | S4-SGSN              | Inter-RAT mobility between LTE and 2G/3G packet-switched networks          | Not implemented                      | Plan GTPv2-C procedures, context transfer, relocation, and SGSN selection        | Very Low     |
| **SLg**           | GMLC                 | EPC Location Services signaling                                            | Implemented                          | Needs Testing once the E-SMLC is completed				          | Low          |
| **SLs**           | E-SMLC               | UE positioning and location procedures                                     | Implemented                          |  Needs Testing once the E-SMLC is completed                                      | Low          |
| **Sv**            | MSC Server           | Single Radio Voice Call Continuity                                         | Not implemented                      | LTE-to-2G/3G voice handover                                                      | Very Low     |
| **Sm**            | MBMS-GW              | MBMS session-control signaling                                             | Not implemented                      | MBMS session-start, stop, and service-area support                               | Very Low     |
| **S102**          | 3GPP2 1xCS IWS       | CDMA2000 circuit-switched fallback interworking                            | Out of scope                         | CDMA2000 interworking                                                            | Out of Scope |


### planned feature:  NB-Iot/LTE-M, N26 interface, full 5G-NSA support. 

### 1.1 S3 — SGSN Interworking

The MME-facing SGSN interface is specifically **S3**.

S3 connects the MME to an S4-SGSN and uses GTPv2-C for control-plane mobility procedures between E-UTRAN/EPS and GERAN or UTRAN packet-switched access.

Required capabilities would include:

* MME-to-SGSN context transfer
* SGSN-to-MME context transfer
* Forward Relocation Request and Response procedures
* Forward Relocation Complete procedures
* Inter-RAT Tracking Area Update
* Inter-RAT Routing Area Update
* EPS bearer-context transfer
* PDP-context and EPS-bearer mapping
* Security-context transfer
* Mapped EPS security-context handling
* Subscriber and mobility-context transfer
* SGSN selection
* Peer restart and Recovery IE handling
* GTPv2-C transaction, timer, and retransmission handling
* Interaction with existing S10 mobility logic
* Interoperability testing with an S4-SGSN

Possible configuration:

```yaml
interfaces:
  s3:
    enabled: false
    bind_address: 10.90.250.186
    port: 2123
    dscp: 24

sgsn_peers:
  - name: sgsn-01
    address: 10.90.250.70
    port: 2123
    enabled: false
```

Existing GTPv2-C codec, transaction, transport, recovery, and peer-management components should be reused where possible.

Interfaces associated with the SGSN that do **not** terminate on the MME include:

* **S4:** SGSN to SGW
* **S12:** RNC user plane to SGW
* **S16:** SGSN to SGSN
* **Gn/Gp:** Legacy GPRS core interfaces

---

## 2. Transport and Diameter Requirements

### 2.1 Diameter Transport Options

Diameter peers should support both:

* TCP
* SCTP

Transport must be configurable independently for each peer.

Example:

```yaml
diameter:
  peers:
    - name: hss-01
      interface: s6a
      host: hss.epc.mnc435.mcc311.3gppnetwork.org
      realm: epc.mnc435.mcc311.3gppnetwork.org
      address: 10.90.250.35
      port: 3868
      transport: sctp
```

Supported values:

```yaml
transport: tcp
```

```yaml
transport: sctp
```

Diameter transport requirements should include:

* Configurable TCP or SCTP per peer
* IPv4 and eventual IPv6 support
* Connection retry and exponential backoff
* CER/CEA validation
* DPR/DPA handling
* Watchdog handling
* Peer failover
* Destination-Realm routing
* Destination-Host routing
* Multiple peers per realm
* Application-ID validation
* Origin-State-Id handling
* Peer restart detection
* Diameter overload-control support
* Per-peer DSCP marking
* Metrics for connection state, retries, requests, failures, and latency

---

## 3. Active and Planned Features

### 3.1 DDN Paging

**Status:** Work in progress.

Required validation:

* Downlink Data Notification reception from the SGW
* Paging initiation for ECM-IDLE UEs
* Correct paging TAI list
* Paging across multiple TACs
* Paging retry behavior
* Paging timer behavior
* DDN acknowledgement handling
* DDN failure handling
* UE Service Request handling
* Initial Context Setup following a successful Service Request
* Restoration of S1-U bearer forwarding
* Modify Bearer Request after successful paging
* Multiple outstanding DDN events
* Duplicate DDN handling
* Interaction with Release Access Bearers
* Interaction with UE Context Release
* Paging rejection and timeout cleanup
* SGW restart during paging
* MME restart during paging
* DDN throttling and rate limiting

---

### 3.2 Recovery Database

**Status:** Implemented but requires additional testing.

Testing should include:

* Clean MME restart
* Unclean MME termination
* Process crash
* Host reboot
* Database reconnect
* Recovery of registered UE records
* Identification of stale UE contexts
* Cleanup of stale UE contexts
* Recovery-counter changes
* SGW behavior after MME restart
* HSS state reconciliation
* UE attach after stale context recovery
* UE TAU after MME restart
* UE Service Request after MME restart
* Recovery with ECM-IDLE UEs
* Recovery with ECM-CONNECTED UEs
* Recovery with active dedicated bearers
* Recovery with IMS bearers
* Recovery with pending procedures
* Recovery with an unreachable SGW
* Recovery with an unreachable HSS
* Administrative listing of recovery records
* Administrative clearing of recovery records
* Metrics and alarms for stale or failed recovery records

---

### 3.3 SMS in MME

**Status:** Planning and research required.

Dependencies:

* S1-MME / EPS NAS SMS transport
* S6a SMS subscription and serving-node extensions
* SGd
* NAS SMS transport
* SMS-specific EMM handling
* SMS transaction state machines
* SMS routing policy
* SMSC address configuration
* EPS-only attach subscription behavior
* Delivery-report handling
* Failure handling
* Subscriber authorization
* Service enablement
* IMSI-to-MSISDN resolution

Cisco-style reference:

```text
sms-in-mme preferred smsc-addr 15550000000
sms-in-mme subscribe eps-only-attach
```

Possible VectorCore configuration:

```yaml
sms_in_mme:
  enabled: true

  preferred_smsc:
    address: "15550000000"

  subscription:
    eps_only_attach: true

  interfaces:
    sgd:
      enabled: true
```

Research requirements:

* S6a SMS subscription data and serving-node registration
* S6a UE reachability procedures for MT-SMS
* SGd procedure set
* IMSI-to-MSISDN lookup
* MSISDN normalization
* E.164 formatting
* Leading `+` handling
* NAS CP-DATA handling
* CP-ACK and CP-ERROR handling
* RP-DATA handling
* RP-ACK and RP-ERROR handling
* SMS transaction identifiers
* Mobile-originated SMS
* Mobile-terminated SMS
* Store-and-forward behavior
* Delivery acknowledgements
* Delivery reports
* Retry policies
* SMSC selection
* Multiple SMSC support
* Subscriber service authorization
* EPS-only attach behavior
* SMS over SGs fallback
* SMS over IMS interaction
* Duplicate message protection
* Transaction recovery following restart

---

### 3.4 Multiple TAC Support

Required capabilities:

* Configure multiple local TACs
* Associate eNodeBs with one or more TACs
* Validate incoming TAIs
* Advertise supported TAIs
* Generate TAI lists in Attach Accept
* Generate TAI lists in TAU Accept
* Support paging across the UE’s registered TAI list
* Select SGWs by TAC
* Apply per-TAC policies
* Support inter-TAC mobility within the same MME
* Support TAC-based metrics and alarms
* Detect eNodeBs advertising unsupported TACs
* Support TAC groups or tracking-area pools
* Support per-TAC emergency policy
* Support per-TAC roaming policy

Possible configuration:

```yaml
tracking_areas:
  - tac: 1
    name: primary
    served: true

  - tac: 2
    name: secondary
    served: true

  - tac: 3
    name: lab-expansion
    served: true
```

Tracking-area pool layout:

```yaml
tracking_area_pools:
  - name: default
    tais:
      - plmn:
          mcc: "311"
          mnc: "435"
        tac: 1

      - plmn:
          mcc: "311"
          mnc: "435"
        tac: 2
```

---

### 3.5 Roaming

Default behavior should construct the destination Diameter realm from the subscriber HPLMN.

Example:

```text
IMSI: 310260xxxxxxxxx
HPLMN: MCC 310 / MNC 260
Derived realm: epc.mnc260.mcc310.3gppnetwork.org
```

Required routing modes:

1. Automatic realm construction from the subscriber HPLMN
2. Explicit PLMN-to-realm mapping
3. Static peer or routing-agent override
4. Default roaming realm fallback

Possible configuration:

```yaml
roaming:
  enabled: true

  default_realm_resolution: hplmn

  plmn_realm_map:
    - plmn:
        mcc: "310"
        mnc: "260"
      realm: epc.mnc260.mcc310.3gppnetwork.org

    - plmn:
        mcc: "310"
        mnc: "410"
      realm: roaming.partner.example.net
```

Additional requirements:

* Home versus visited subscriber identification
* S6a Destination-Realm selection
* Destination-Host policy
* Diameter routing-agent support
* Roaming subscriber restrictions
* APN access restrictions
* Visited-PLMN policy
* Regional subscription checks
* RAT restrictions
* Emergency-service handling
* Roaming-specific logging
* Roaming-specific metrics
* Partner-specific reject causes
* Per-partner gateway selection
* Per-partner DNS policy   - S8 records + Home Realm or Static Realm  from map.
* Home-routed versus local-breakout policy

---

### 3.6 Equipment Identity Register

**Interface:** S13

Required procedures:

* Query the EIR during attach
* Query the EIR during Tracking Area Update
* Support IMEI queries
* Support IMEISV queries where required
* Handle white-listed equipment
* Handle grey-listed equipment
* Handle black-listed equipment
* Define failure behavior when the EIR is unavailable
* Cache EIR decisions if configured
* Record EIR results in the UE context
* Record EIR decisions in logs and metrics

Cisco-style reference:

```text
policy attach imei-query-type imei verify-equipment-identity
policy tau imei-query-type imei verify-equipment-identity
```

Possible configuration:

```yaml
eir:
  enabled: true

  interface: s13

  policies:
    attach:
      verify_equipment_identity: true
      identity_type: imei

    tau:
      verify_equipment_identity: true
      identity_type: imei

  unavailable_action: allow-and-log
```

Possible unavailable actions:

```text
allow
reject
allow-and-log
```

---

### 3.7 5G NSA / EN-DC

Required EN-DC support:

* UE DCNR capability detection
* HSS subscription checks for NR
* NR restriction handling
* RAT restriction handling
* S1AP UE capability transfer
* E-UTRAN Radio Capability handling
* EN-DC authorization policy
* Correct NAS restriction signaling
* Secondary RAT usage reporting where applicable
* UE Context Modification handling
* Interaction with bearer QoS
* Interaction with roaming restrictions
* Interaction with regional subscription restrictions
* Per-subscriber EN-DC enablement
* Per-PLMN EN-DC policy
* Per-TAC EN-DC policy
* Logging of EN-DC authorization decisions

Possible configuration:

```yaml
endc:
  enabled: true

  require_subscription: true

  default_policy: allow

  restrictions:
    enforce_rat_restrictions: true
    enforce_regional_subscription: true
```

---

### 3.8 RAT and Access Restrictions

Required support:

* Parse RAT restrictions from subscriber data
* Store restrictions in the UE context
* Enforce restrictions during attach
* Enforce restrictions during TAU
* Enforce restrictions during Service Request where applicable
* Restrict disallowed RAT types
* Enforce roaming-specific RAT restrictions
* Enforce regional subscription restrictions
* Enforce service-area restrictions
* Enforce APN restrictions
* Enforce subscriber status
* Enforce operator-determined barring
* Include applicable restrictions in NAS signaling
* Support NR restrictions for NSA
* Log the exact policy reason
* Expose restrictions through the UE API

Possible configuration:

```yaml
rat_restrictions:
  enabled: true

  enforce_subscription_data: true
  enforce_roaming_policy: true

  default_action: allow
```

---

## 4. Core Network Scalability and Resiliency

### 4.1 MME Pooling and S1 Flex

Required capabilities:

* Multiple MMEs in an MME pool
* Configurable MME pool identity
* GUMMEI configuration
* Multiple GUMMEIs
* GUTI allocation
* GUTI reallocation
* S1 Flex support
* Relative MME Capacity
* eNodeB load distribution
* Load-aware MME selection
* MME redirection
* Context transfer over S10
* Pool-aware paging
* Pool-aware tracking-area configuration
* Restart and failover behavior
* MME selection based on served GUMMEIs
* Metrics for load, capacity, and pool membership

Possible configuration:

```yaml
mme_pool:
  enabled: false
  pool_id: 1
  relative_capacity: 100

  gummeis:
    - plmn:
        mcc: "311"
        mnc: "435"
      mme_group_id: 1
      mme_code: 1
```

---

### 4.2 MME Overload Control

Required capabilities:

* Relative MME Capacity in S1 Setup Response
* Overload Start
* Overload Stop
* Traffic-reduction indications
* Per-eNodeB overload state
* Reject or throttle selected procedures
* Preserve emergency traffic
* Preserve high-priority traffic
* Diameter overload-control handling
* GTP peer overload handling
* Internal queue-depth monitoring
* CPU and memory thresholds
* Database-health thresholds
* Configurable overload actions
* Metrics and alarms
* Graceful recovery from overload

Possible configuration:

```yaml
overload_control:
  enabled: true

  thresholds:
    cpu_percent: 85
    memory_percent: 90
    procedure_queue_depth: 10000

  actions:
    reject_new_attach: true
    allow_emergency: true
    allow_existing_ue_procedures: true
```

---

### 4.3 Peer Restart and Recovery Handling

Required across S1AP, GTPv2-C, Diameter, and future interfaces:

* Peer restart detection
* Recovery counter tracking
* Origin-State-Id tracking
* Stale transaction cleanup
* Context reconciliation
* Controlled retransmission
* Peer-specific backoff
* Alarm generation
* API visibility
* Metrics
* Duplicate-request handling
* Idempotent procedure handling

---

## 5. Emergency Services

Required capabilities:

* Emergency attach
* Emergency PDN connectivity
* Emergency APN selection
* Emergency bearer handling
* Limited-service UE handling
* Unauthenticated emergency access policy
* Emergency IMS support
* Emergency indication handling
* Emergency subscriber authorization
* Emergency-location interaction
* Priority treatment during overload
* Per-PLMN emergency policy
* Per-TAC emergency policy
* Emergency-call-related metrics and logging

Possible configuration:

```yaml
emergency_services:
  enabled: false

  allow_unauthenticated_attach: false
  allow_limited_service: true
  apn: sos

  overload_priority: highest
```

---

## 6. Idle Mode and Power Saving

Required capabilities:

* Extended idle-mode DRX
* Power Saving Mode
* Active Time
* Periodic TAU timer
* Mobile Reachable Timer
* Implicit Detach Timer
* Paging behavior during eDRX
* Paging behavior during PSM
* Subscriber-specific timer configuration
* APN-specific timer policy
* Roaming restrictions
* NAS timer encoding
* Timer persistence in the recovery database
* Metrics for unreachable and power-saving UEs

Possible configuration:

```yaml
emm:
  timers:
    periodic_tau: 54m
    mobile_reachable: 60m
    implicit_detach: 70m

  power_saving:
    psm:
      enabled: true

    edrx:
      enabled: true
```

---

## 7. Network Sharing and Multi-PLMN Support

Required capabilities:

* Multiple served PLMNs
* Multiple broadcast PLMNs
* Shared eNodeB operation
* MOCN support
* PLMN selection from the Initial UE Message
* Per-PLMN GUMMEI
* Per-PLMN HSS selection
* Per-PLMN SGW selection
* Per-PLMN PGW selection
* Per-PLMN APN policy
* Per-PLMN roaming policy
* Per-PLMN security policy
* Per-PLMN emergency policy
* Per-PLMN metrics
* PLMN-specific reject handling

Possible configuration:

```yaml
served_plmns:
  - mcc: "311"
    mnc: "435"
    primary: true

  - mcc: "001"
    mnc: "01"
    primary: false
```

---

## 8. EMM and NAS Configuration

### 8.1 Network Time Zone

Current note:

```text
timezone - hours 6 ????
```

A static UTC−6 setting would be incorrect during daylight-saving time.

Recommended configuration:

```yaml
emm:
  timezone:
    source: system
    zone: America/Chicago
```

Alternative fixed offset:

```yaml
emm:
  timezone:
    source: fixed
    utc_offset_minutes: -360
```

The named time-zone approach should generate:

* Local Time Zone IE
* Universal Time and Local Time Zone IE
* Daylight Saving Time IE where applicable

Central Time uses:

* UTC−6 during standard time
* UTC−5 during daylight-saving time

---

### 8.2 A-MSISDN Support

Research and define:

* Applicable 3GPP procedures
* Internal representation
* Data source
* Subscriber-database storage
* External lookup support
* Validation
* E.164 normalization
* Leading `+` handling
* Logging
* API representation
* Privacy masking
* SMS interaction
* Roaming interaction

Possible subscriber model:

```yaml
subscriber:
  imsi: "311435000000001"
  msisdn: "15551234567"
  a_msisdn: "15557654321"
```

The exact meaning and procedures associated with A-MSISDN must be verified before implementation.

---

## 9. NAS Security Policy

### 9.1 LTE Encryption Algorithm Priority

Cisco-style reference:

```text
encryption-algorithm-lte priority1 128-eea3 priority2 128-eea2 priority3 128-eea1 priority4 128-eea0
```

Equivalent configuration:

```yaml
nas_security:
  encryption_algorithms:
    - 128-eea3
    - 128-eea2
    - 128-eea1
    - 128-eea0
```

Requirements:

* Compare configured priorities with UE capabilities
* Select the highest-priority mutually supported algorithm
* Log the selected algorithm
* Expose the selected algorithm through the UE API
* Support policy overrides
* Permit or prohibit EEA0 by configuration
* Reject when no permitted algorithm is available

`128-EEA0` provides no encryption and should remain the lowest-priority fallback.

---

### 9.2 LTE Integrity Algorithm Priority

Cisco-style reference:

```text
integrity-algorithm-lte priority1 128-eia3 priority2 128-eia2 priority3 128-eia1
```

Equivalent configuration:

```yaml
nas_security:
  integrity_algorithms:
    - 128-eia3
    - 128-eia2
    - 128-eia1
```

Combined example:

```yaml
nas_security:
  encryption_algorithms:
    - 128-eea3
    - 128-eea2
    - 128-eea1
    - 128-eea0

  integrity_algorithms:
    - 128-eia3
    - 128-eia2
    - 128-eia1

  allow_null_encryption: true
```

---

## 10. QoS and DSCP Marking

### 10.1 MME Control-Plane Interfaces

Add configurable DSCP marking for:

* S1AP
* S6a
* S10
* S11
* S13
* SGsAP
* SGd
* SBc-AP
* S3
* SLg
* SLs
* Sv
* Sm

Possible configuration:

```yaml
qos:
  control_plane:
    s1ap:
      dscp: 24

    s6a:
      dscp: 24

    s10:
      dscp: 24

    s11:
      dscp: 24

    s13:
      dscp: 24

    sgsap:
      dscp: 24

    sgd:
      dscp: 24


    sbc_ap:
      dscp: 24

    s3:
      dscp: 24

    slg:
      dscp: 24

    sls:
      dscp: 24

    sv:
      dscp: 24

    sm:
      dscp: 24
```

Implementation requirements:

* Apply DSCP to outbound sockets
* Apply DSCP to accepted sockets where required
* Support UDP
* Support TCP
* Support SCTP
* Validate DSCP range
* Log effective DSCP values at startup
* Expose active values through the API
* Add packet-capture tests
* Support per-peer override
* Support interface default values

---

### 10.2 Cisco QCI-to-DSCP Reference Mapping

```text
qci-qos-mapping table1
 qci 1 uplink user-datagram dscp-marking 0x2e downlink user-datagram dscp-marking 0x2e
 qci 2 uplink user-datagram dscp-marking 0x22 downlink user-datagram dscp-marking 0x22
 qci 5 uplink user-datagram dscp-marking 0x28 downlink user-datagram dscp-marking 0x28
 qci 9 uplink user-datagram dscp-marking 0x00 downlink user-datagram dscp-marking 0x00
```

| QCI | Typical Use             | Hex DSCP | Decimal DSCP |
| --: | ----------------------- | -------: | -----------: |
|   1 | Conversational voice    |   `0x2e` |           46 |
|   2 | Conversational video    |   `0x22` |           34 |
|   5 | IMS signaling           |   `0x28` |           40 |
|   9 | Default Internet bearer |   `0x00` |            0 |

Possible shared configuration:

```yaml
qos:
  bearer_mapping:
    - qci: 1
      uplink_dscp: 46
      downlink_dscp: 46

    - qci: 2
      uplink_dscp: 34
      downlink_dscp: 34

    - qci: 5
      uplink_dscp: 40
      downlink_dscp: 40

    - qci: 9
      uplink_dscp: 0
      downlink_dscp: 0
```

The MME processes bearer QoS information, but actual user-plane packet marking belongs primarily in the SGW-U or PGW-U dataplane.

---

## 11. Location Services

Interfaces:

* SLg
* SLs

Required feature areas:

* GMLC connectivity
* E-SMLC connectivity
* Location-request authorization
* Subscriber privacy policy
* Emergency location
* Network-requested location
* UE-assisted positioning
* Network-assisted positioning
* Location-session state machines
* Timeout and failure handling
* Per-request auditing
* Location result delivery
* Positioning capability exchange
* Metrics and alarms

---

## 12. Public Warning System

**Interface:** SBc-AP

Required capabilities:

* ETWS support
* CMAS support
* Write-Replace Warning Request
* Write-Replace Warning Response
* Stop Warning Request
* Stop Warning Response
* Warning-area selection
* Tracking-area selection
* Cell-area selection
* eNodeB delivery status
* Message repetition
* Message expiry
* Duplicate suppression
* CBC peer management
* Per-warning audit logs
* Failure and retry behavior

---

## 13. MBMS

**Interface:** Sm

Future requirements:

* MBMS-GW connectivity
* MBMS session start
* MBMS session stop
* MBMS session update
* MBMS service-area handling
* MBMS bearer context
* Session timeout handling
* MBMS-GW restart handling
* Metrics and logging

This should remain very low priority unless MBMS or MCX broadcast operation becomes an active project requirement.

---

## 14. Trace, Diagnostics, and Operations

Required capabilities:

* IMSI-specific tracing
* IMEI-specific tracing
* MSISDN-specific tracing
* eNodeB-specific tracing
* Cell-specific tracing
* TAC-specific tracing
* Interface-specific tracing
* Procedure-specific tracing
* Configurable packet capture
* S1AP message export
* NAS message export
* GTPv2-C message export
* Diameter message export
* Redaction of authentication material
* Trace expiry
* API-controlled trace activation
* PCAP-compatible diagnostic export
* Prometheus metrics
* Structured logs
* Per-procedure latency
* Per-interface error counters
* Peer-state visibility
* UE procedure-history visibility

---

## 15. Lawful Interception Readiness

This does not require implementing a complete mediation platform in the initial MME.

The architecture should preserve clean integration points for:

* Subscriber event correlation
* Mobility-event reporting
* Session metadata
* Bearer metadata
* Target activation
* Target deactivation
* Audit trails
* Secure delivery to an external mediation function
* Strict authorization and access control

This remains a future production-readiness consideration.

---

## 16. Recommended Development Priorities

### Immediate

* Complete DDN paging
* Expand Recovery Database testing
* Complete S10 interoperability testing
* Add multiple-TAC support
* Add S1AP, S6a, and S11 DSCP marking
* Complete NAS security algorithm configuration
* Validate EN-DC behavior
* Improve peer restart and recovery handling

### High

* MME overload control
* MME pooling
* S1 Flex
* Network sharing
* Multi-PLMN support
* Subscriber access restrictions
* Emergency-service foundations
* Diameter resiliency and routing

### Medium

* Roaming
* S13 and EIR integration
* eDRX and PSM
* SMS in MME architecture
* SGd
* Time-zone handling
* A-MSISDN research

### Low

* SGsAP
* SBc-AP
* SLg
* SLs
* Public Warning System
* Location Services

### Very Low

* S3 SGSN interworking
* Sv SRVCC
* Sm MBMS

### Out of Scope Unless Required

* S102
* CDMA2000 interworking

---

## 17. Open Research Questions

1. Which S10 procedures are implemented, partially implemented, or untested?
2. Should TACs be configured individually, as ranges, or as tracking-area pools?
3. Should paging cover all TAIs assigned to the UE or a configurable subset?
4. Which control-plane DSCP value should be the default?
5. Should each peer be able to override the interface-level DSCP value?
6. Should EEA0 require an explicit insecure-fallback option?
7. What exact A-MSISDN procedures are required?
8. Should SGd connect directly to the SMSC or use a separate SMS Router?
9. Should SMS over SGs also be supported?
10. What should happen when the EIR is unavailable?
11. Should EIR results be cached?
12. Should roaming use direct Diameter peers, a DRA, or both?
13. How should partner-specific realm and host routing be configured?
14. Which emergency-attach modes are in scope?
15. Is unauthenticated emergency attach required?
16. Which MME overload thresholds should be automatic versus configured?
17. How should load be distributed across an MME pool?
18. Which network-sharing model is required: dedicated PLMN, MOCN, or both?
19. Are SLg and SLs required for initial emergency-location support?
20. What exact SBc-AP and Public Warning System capabilities are in scope?
21. Is MBMS control through Sm expected to integrate with the future VectorCore MBMS components?
22. Which SGSN implementation would be used for eventual S3 interoperability testing?
23. Should S3 use static SGSN peers, DNS-based selection, or both?
24. Is SRVCC relevant to any future legacy MSC deployment?
25. Which traces may contain subscriber-sensitive or authentication-related data, and how should they be redacted?
