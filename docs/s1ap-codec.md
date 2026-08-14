# S1AP APER Codec Notes

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
