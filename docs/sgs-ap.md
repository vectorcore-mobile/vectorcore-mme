# SGs-AP (TS 29.118)

This MME implements the SGs interface between the MME and a VLR/MSC Server,
used for CS Fallback and/or SMS over SGs. open5gs is an interoperability
reference only; the MME has no source, module, runtime, or routing
dependency on it.

## Architecture

```text
UE -- combined Attach/TAU -- s1ap (attach.go/tau.go/sgs.go) -- vlr.Manager -- SGs-AP SCTP -- VLR
                                        |
                                        +-- internal/sgsap (wire codec only)
```

`internal/sgsap` owns only the TS 29.118 message codec (all 22 message
types): TLV framing, IMSI/mobile-identity/TMSI/LAI/TAI/ECGI encoding, and
per-message Build/Decode functions. It has no VLR state, no SCTP, and no UE
awareness, mirroring the split already used by `internal/diameter/sgd` for
SMS over SGd.

`internal/vlr` owns the MME-initiated outbound SCTP association to each
configured VLR (TS 29.118 §6.3, PPID 0) and the node-level Reset procedure
(§5.8): sending our own Reset Indication when an association comes up,
acknowledging the VLR's, and tracking whether an association is confirmed
usable. It dispatches every VLR-originated message to a `Handler` interface,
implemented by `internal/s1ap` (`internal/s1ap/sgs.go`), the same
Handler-callback pattern already used for SGd's MT SMS delivery.

Per-UE SGs association state (SGs-NULL / LA-UPDATE-REQUESTED /
SGs-ASSOCIATED, TS 29.118 §4.3.3) lives on `uecontext.Context`
(`SGsState`, `SGsVLRName`, `SGsLAI`, `SGsRejectCause`), independent of
`EMMState`/`ECMState` and of `SMSRegistrationState` (SGd). A UE can be
registered on neither, either, or - when both `sgd.enabled` and
`sgs.enabled` are true - both simultaneously; `sms.preferred_transport`
picks which one an MO SMS uses.

## VLR topology

Configuration mirrors open5gs's split: a `sgs.vlr` list (one SCTP
association per entry) plus a `sgs.tai_lai_map` list tying each served TAI
to a LAI and to one of those VLRs. There is no TMSI/NRI-based VLR pooling -
exactly one VLR per TAI.

## Location Update and the EPS attach/TAU boundary

A VLR-side rejection or a Location Update timeout only ever reverts the
UE's SGs state to SGs-NULL - it never fails or rolls back the EPS
attach/TAU that triggered it (TS 23.272 §4.3). Concretely, the SGs
Location Update is fired **after** Attach/TAU Accept has already been sent
(`maybeSendSGsLocationUpdateRequest`, called from the Attach Accept send
paths in `internal/s1ap/nas.go` and from `sendTAUAcceptForRequest` in
`internal/s1ap/tau.go`) rather than gating it. One practical consequence:
a UE's very first Attach essentially never has a real SGs association yet
(`attachAcceptRegistration` prefers a real one over SGd's synthetic
"combined" result but there hasn't been time to establish one), so a real
combined result with a genuine VLR-assigned LAI first appears on that UE's
next TAU (`tauAcceptResultForRequest`), once `HandleLocationUpdateAccept`
has recorded `ue.SGsState = SGsUEAssociated` and `ue.SGsLAI`.

`sgs.smsonly` restricts the association to SMS relay: the MME still
performs the Location Update, but never treats the UE as CS Fallback
capable (no Extended Service Request/CSFB-indicator handling). `smsonly`
is independent of - and takes priority as a network policy over - whatever
the UE itself requested via Additional Update Type.

## PS-only subscribers (Network-Access-Mode)

`maybeSendSGsLocationUpdateRequest` also gates on the HSS-provisioned
Network-Access-Mode (TS 29.272 §7.3.21, S6a AVP 1417): a subscriber
provisioned `ONLY_PACKET` has no CS subscription at all, and TS 23.272
Annex C.8.1 states plainly that "for a PS-only subscription... the MME
shall not establish any SGs association." This is decoded from the ULA's
Subscription-Data in `internal/diameter/s6a/ulr.go` alongside
Access-Restriction-Data, carried on `gateway.SubscriberProfile` and then
`uecontext.Context.NetworkAccessMode`, and checked via
`ue.PSOnlySubscription()` as an early return in
`maybeSendSGsLocationUpdateRequest` - a silent skip, not a rejection,
the same shape as the existing `sgsCfg.Enabled`/no-VLR-mapping skips: the
EPS attach/TAU still completes normally as EPS-only, the UE just never
gets a combined result.

This is decoded from ULA only, not from mid-session
Insert-Subscriber-Data updates (`internal/diameter/s6a/clr.go`'s
`handleIDR`), and that's deliberate rather than an oversight.
go-diameter's `Unmarshal` leaves a struct field at its Go zero value when
an AVP is absent from a message, with no way to distinguish "absent" from
"present and zero." For Access-Restriction-Data, zero means "no
restrictions," so this codebase's existing IDR-driven decoding of that
AVP is safe even though most IDRs omit it - decoding a zero when it's
absent just re-asserts what was already true. For Network-Access-Mode,
zero means `PACKET_AND_CIRCUIT` - a real, meaningful value, not an
absent-sentinel - so the same pattern in `handleIDR` would silently flip
an already-known PS-only subscriber back to "allowed" on any unrelated
IDR (e.g. a bare AMBR update) that doesn't happen to carry this AVP.
Closing that gap needs a presence check against the IDR's raw AVP list
rather than trusting the unmarshalled field - separate work, not yet
done. Net effect: a subscriber changed to PS-only *after* attach keeps
any existing SGs association until they next re-attach or the HSS issues
a full Cancel-Location.

## SMS over SGs

Unlike SGd, SMS over SGs is a transparent NAS-message-container relay (TS
29.118 §9.4.15): the VLR/MSC owns the CP/RP protocol end to end, so the MME
never parses CP-DATA/CP-ACK/CP-ERROR or synthesizes an RP-ACK itself here -
it only relays the opaque NAS message container in each direction
(`internal/s1ap/sgs_sms.go`), reusing the existing transport-neutral pieces
(`sendSMSCP`, `PageUE`) unchanged. This matches how open5gs's
`sgsap_handle_downlink_unitdata` / uplink NAS transport handling behave, and
is why the SGs path needs none of `internal/sms.Service`'s SGd-specific
RP-layer validation and deferred-MT bookkeeping - it has its own, simpler
pending-map (`pendingSGsMTSMS`) keyed only on "was this UE paged for a
downlink SMS yet."

`selectSMSPath` decides which core-side transport an MO SMS uses per UE:
"sgd", "sgs", or neither, consulted only when both `sgd.enabled` and
`sgs.enabled` are true and the UE is registered/associated on both, in
which case `sms.preferred_transport` breaks the tie.

## MT CS Fallback paging

`HandlePagingRequest` implements TS 29.118 §5.1.3: if the UE already has a
NAS signalling connection, `SGsAP-SERVICE-REQUEST` is sent back immediately
(§5.1.3.3); otherwise `PageUEForCSFB` pages the UE with CN Domain=CS
(§5.1.3.2, sharing `PageUE`'s T3413 retry machinery via the new
`ue.PagingCNDomain` field so ordinary PS paging - the admin API, SGd/SGs MT
SMS - is unaffected). The pending request (`ue.SGsPendingPaging`) is
completed either by a mobile terminating CS Fallback Extended Service
Request (service type 1, TS 24.301 §9.9.3.27) or, as a fallback for
SMS-indicator pages, by a plain Service Request reconnecting - both paths
converge on `completeSGsPaging`. A paging timeout reports
`SGsAP-UE-UNREACHABLE`; an unknown IMSI or a failure to page reports
`SGsAP-PAGING-REJECT`.

For a real CS-call page, the resuming Initial Context Setup Request also
carries the S1AP CS Fallback Indicator IE (`cs-fallback-required`) so the
eNB actually redirects the UE to 2G/3G - the MME's role ends at signalling
that indicator; the redirection mechanism itself is the eNB's. `sgs.smsonly`
suppresses this even for a CS-call page, as a network-level override.

## MO CS Fallback

A UE-initiated CS call (Extended Service Request, service type 0, TS
24.301 §9.9.3.27) only becomes known to the MME after the UE already has
an established NAS signalling connection, unlike MT paging. When the UE
has a genuine SGs association (`ue.SGsState == SGsUEAssociated`, SGs
enabled, and not `smsonly`), `handleMOCSFBExtendedServiceRequest` sends
`SGsAP-SERVICE-REQUEST` (CS-call indicator) followed by
`SGsAP-MO-CSFB-INDICATION` (§8.25) to the associated VLR, then
`SendUEContextModificationForCSFB` sends the minimal UE Context
Modification Request TS 36.413 §9.1.4.8 allows purely to carry the S1AP CS
Fallback Indicator IE, so the eNB redirects the UE the same way it does
for MT CSFB. If the UE has no operational SGs association (SGs disabled,
`smsonly`, or not yet associated), the existing Service Reject
(`CauseCSDomainNotAvailable`) behavior is preserved unchanged - the MME
never fails or rolls back the underlying EPS signalling connection either
way.

## EPS/IMSI Detach Indication

A UE-initiated NAS Detach Request (`processDetach`) checks the detach
type against any existing SGs association and, via
`sendSGsDetachIndicationForUE`, sends the matching indication before
reverting the association to SGs-NULL - `SGsAP-EPS-DETACH-INDICATION`
("UE initiated", TS 29.118 §5.4) for an EPS-only detach, or
`SGsAP-IMSI-DETACH-INDICATION` (§5.5, "Explicit" for IMSI-only,
"Combined" for a combined EPS/IMSI detach) otherwise. Per §5.5.2.2, an
IMSI or combined detach not due to switch-off withholds the NAS Detach
Accept - and, with it, the S1 context release, since the eNB connection
is still needed to deliver it - until `HandleIMSIDetachAck` completes it
(`deferDetachAcceptForIMSIDetachAck`/`completeDeferredDetach`), falling
back to sending it anyway once the same SGs request timeout used
elsewhere in this package elapses (§5.5.2.3(ii)) if no ack arrives. This
MME does not implement the Ts8/Ns8/Ts9/Ns9 retransmission timers those
sections also describe.

## Remaining VLR-initiated procedures

`HandleAlertRequest` acknowledges (`SGsAP-ALERT-ACK`) if the IMSI is
known or rejects (`SGsAP-ALERT-REJECT`, "IMSI unknown") otherwise (TS
29.118 §5.3.3.1/§5.3.3.2). `HandleReleaseRequest` resets a UE's SGs
association to SGs-NULL when the cause is "IMSI unknown" or "IMSI
detached for non-EPS services" (§5.11.4), which has the same effect as
clearing the "VLR-Reliable" MM context variable that section describes -
the next combined TAU's `maybeSendSGsLocationUpdateRequest`
re-establishes it. `HandleServiceAbortRequest` cancels an in-progress
CSFB paging cycle for the VLR (T3413 and all) without reporting
`SGsAP-UE-UNREACHABLE`, since the VLR itself asked to stop (§5.9).
`HandleMMInformationRequest`/`relayMMInformationToUE` relay a VLR's MM
Information message to the UE as an EMM Information NAS message (TS
24.301 §8.2.9): the TS 24.008 MM Information IEs (Full/Short Name for
Network, time zone, daylight saving) are the exact same IEs EMM
Information reuses by reference, so the already-unwrapped SGsAP MM
Information content is relayed verbatim as the EMM Information body -
the same transparent-relay approach used for SMS over SGs.

## TMSI reallocation

If a `SGsAP-LOCATION-UPDATE-ACCEPT` includes a new VLR-assigned TMSI in
its Mobile identity IE, `HandleLocationUpdateAccept` records it on
`ue.SGsPendingNewTMSI` (TS 29.118 §5.2.2.3). It rides the same
lazily-delivered path as LAI: the next Attach or TAU Accept
(`attachAcceptRegistration`/`tauAcceptResultForRequest`) relays it to the
UE as the NAS "MS identity" IE (TS 24.301 §9.9.2.3/TS 24.008 §10.5.1.4),
promoting it to `ue.SGsSentNewTMSI` once sent. `completeSGsTMSIReallocation`
then sends `SGsAP-TMSI-REALLOCATION-COMPLETE` once delivery is confirmed:
on Attach Complete unconditionally, on TAU Complete when that TAU Accept
also reallocated the GUTI (the only case a TAU Complete is expected at
all), or immediately when no GUTI reallocation happened this cycle (no
TAU Complete will ever arrive to trigger it otherwise). An IMSI (rather
than TMSI) in that same Mobile identity IE means the VLR wants the UE to
deallocate its TMSI instead; this needs no NAS relay or SGsAP completion
message and, matching open5gs's own scope, is intentionally not modeled.

Because the TMSI relay depends on an Attach/TAU Accept happening at all,
and VLRs commonly run a short reallocation-completion timer (Ts6-2,
tens of seconds) against a UE whose next periodic TAU may be tens of
minutes away, it is expected and spec-compliant (§5.2.3.4: "the outcome
of the TMSI reallocation procedure does not change the state of the SGs
association") for that VLR-side timer to expire before delivery - the
MME still completes the reallocation whenever the UE's next Attach/TAU
actually happens.

## What's implemented vs. pending

Implemented: the full TS 29.118 wire codec, the VLR SCTP transport and
Reset procedure FSM, TAI-to-VLR/LAI selection, the SGs Location Update
request/accept/reject flow (including the "SMS only" Additional Update
Type from Attach/TAU Request, and the Network-Access-Mode PS-only gate -
see above), genuine combined Attach/TAU results carrying a real
VLR-assigned LAI, TMSI reallocation, SMS-over-SGs relay in both
directions, both MT and MO CS Fallback including eNB redirection
signalling, EPS/IMSI Detach Indication, the Alert/Release/Service
Abort/MM Information procedures, and Status logging.

Not implemented: `SGsAP-UE-ACTIVITY-INDICATION`/the NEAF flag from the
Alert procedure (§5.3.3.3) - reporting UE activity that doesn't already
lead to some other SGs procedure would require instrumenting every
E-UTRAN signalling/data activity detection point in this server, unlike
every other procedure above, which was self-contained in `sgs.go`. Held
for now: it is a VLR paging-channel timing optimization (per the note in
§5.3.3.3, it lets the VLR/SMS Service Center prioritize MT SMS
retransmission to UEs on extended DRX), not load-bearing for CSFB or SMS
correctness, and open5gs - otherwise this project's interoperability
reference - does not implement the Non-EPS Alert procedure at all (no
`ALERT_REQUEST`/`ALERT_ACK`/`ALERT_REJECT`/`UE_ACTIVITY_INDICATION` in
its `sgsap-types.h`), so there is no existing deployment behavior to
match here either.

Also not implemented: reacting to a Network-Access-Mode change delivered
via mid-session Insert-Subscriber-Data (as opposed to the initial ULA,
which is handled) - see "PS-only subscribers" above for why this is
deliberately deferred rather than an oversight.

## Recovery and privacy

SGs association state, like SMS-in-MME registration state, is never
restored after restart. A UE re-establishes its association on its next
combined TAU. Logs and metrics contain protocol metadata and bounded
result labels, not IMSI-correlated SGsAP payload content.
