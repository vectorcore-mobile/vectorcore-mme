# SMS in MME over SGd

This MME implements SMS in MME with SGd as its first core-network transport.
The HSS and SMSC repositories are interoperability references only; the MME
has no source, module, runtime, or routing dependency on either project.

## Architecture

```text
UE -- NAS SMS CP/RP -- shared SMS service -- SGd Diameter adapter -- SMSC
                             |
                             +-- SGs-AP adapter (association/LU only so far;
                                 SMS-over-SGs relay is not yet wired in -
                                 see docs/sgs-ap.md)
```

`internal/nas/sms` owns CP/RP codecs, transaction identifiers, and NAS SMS
containers. `internal/sms` owns transport-independent MO validation, deferred
MT state, and reachability notification. `internal/diameter/sgd` owns only
Diameter AVPs and command envelopes. S1AP connects the first two layers to
protected Uplink/Downlink NAS Transport and the existing paging coordinator.

## Registration and routing

When `sgd.enabled` and `subscribe_eps_only_attach` are enabled, normal
EPS-only Attach and applicable TAU ULRs include SMS-in-MME registration
information. A successful ULA marks the UE SMS-registered. A registration
rejection leaves the EPS procedure intact and prevents MO/MT SMS for that UE.

SGd application `16777313` is advertised only when enabled. Direct peer and
DRA routing both use the existing Diameter capability selection. The SGd
configuration deliberately has no peer, route, Destination-Host, or
Destination-Realm fields.

## SMS flows

For MO SMS, the MME accepts protected UL NAS CP-DATA/RP-DATA, extracts the
TPDU, and sends it as SGd OFR SM-RP-UI. It rebuilds the UE-facing RP-ACK or
RP-ERROR only after OFA processing.

For an ECM-CONNECTED MT SMS, TFR SM-RP-UI is converted into UE-facing MT
RP-DATA and CP-DATA. TFA success waits for the matching CP/RP result.

For an ECM-IDLE UE, the MME records a runtime-only deferred marker and starts
the existing paging procedure. It answers the original TFR as deferred rather
than holding a Diameter request through paging. After a successful Service
Request, it sends Alert Service Centre to request a fresh SMSC TFR. Only a
deferred marker can generate this alert.

## Addressing and interoperability

`sgd.smsc_address` is an E.164 value. `sgd_sc_address_encoding: tbcd` is the
standard default; `ascii_digits` preserves Cisco interoperability and matches
the paired SMSC's `smsc.sgd_sc_address_encoding` behavior (leading `+` is
removed and decimal digits are sent as ASCII). The MME Number for MT SMS is
always S6a TBCD without TON/NPI. MO MSISDN is encoded as local
length/TON-NPI/TBCD data for SMSC correlation.

The deployed SMSC accepts Alert Service Centre on its SGd application for the
deferred-MT retry path. This compatibility detail is isolated to the SGd
adapter and must be validated with each peer.

## Recovery and privacy

Active CP/RP, TFR/OFR/ALR Diameter requests, timers, and deferred paging
markers are never restored after restart. Normal S6a registration refresh is
the recovery path. Logs and metrics contain protocol metadata and bounded
result labels, not SMS TPDU/body content or subscriber identifiers as labels.
