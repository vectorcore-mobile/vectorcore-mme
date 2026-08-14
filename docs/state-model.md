# MME State Model

VectorCore MME keeps active UE, session, and procedure state in memory. The in-memory UE context is the runtime source of truth for:

- S1AP UE association state
- MME/eNB UE S1AP IDs
- NAS procedure state and timers
- S11 in-flight transactions
- paging, handover, and service request procedure state

The database is recovery-only. It stores last-known identity, GUTI, location, security algorithm indicators, APN/session summary, TEIDs, and recovery status for restart correlation, stale-session cleanup, observability, and future MME-pool/S10 work. The database is not used to decide whether a UE is currently connected.

## Recovery Database

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

## Restart Behavior

On startup, the MME generates a new restart epoch and marks older recovery records as `STALE_AFTER_RESTART`. It does not load database rows as active UE contexts.

When the S1-MME SCTP association closes, eNodeBs release UE-associated S1AP context tied to that MME. After an MME restart, UEs must return through normal LTE procedures such as Attach, TAU, Service Request, or Detach. The MME may use the recovery DB to map old GUTI to IMSI, correlate previous APN/session data, and clean stale SGW sessions, but it always creates new live in-memory S1/NAS context.

## EPS Detach

ECM-IDLE is not EPS detach. A UE released for radio inactivity remains `EMM-REGISTERED` and can later resume by Service Request.

For UE-originated EPS detach, including detach from ECM-IDLE, the UE may send NAS `DETACH REQUEST` (`0x45`) inside S1AP `InitialUEMessage` because there is no active UE-associated S1 signalling context. The MME resolves the existing UE by S-TMSI/GUTI, verifies NAS security with the stored EPS security context, decodes the Detach Type, and starts S11 Delete Session.

Switch-off detach suppresses NAS Detach Accept. Non-switch-off detach sends Detach Accept protected with the active NAS security context. After successful core-side teardown the active UE/session/bearer state is removed from memory and recovery records are marked detached/inactive.

Do not remove an `EMM-REGISTERED` UE merely because its S1/RRC context was released or because RF connectivity disappeared. Explicit detach and implicit detach are separate procedures.

The live UE API exposes this distinction. `s1_connected=false` with `EMM-REGISTERED` / `ECM-IDLE` means the UE is registered but not currently on a UE-associated S1 connection. `last_release_cause` records the most recent S1 release reason, for example `radio-connection-with-ue-lost`.

## Recovery API

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
