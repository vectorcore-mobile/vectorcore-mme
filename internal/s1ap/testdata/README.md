S1AP E-RAB Setup fixtures
=========================

These fixtures were derived from the local Cisco MME monitor trace at
`/tmp/cisco-mme.log`.

The Cisco packets were accepted by the same Ericsson eNB used during
VectorCore interoperability testing. They are sanitized regression fixtures:
runtime identifiers, TEIDs, IP addresses, and NAS payloads are retained only as
test values required to validate APER structure and bearer association. The
full Cisco log is not committed and normal CI must not depend on it.

Fixtures:

* `cisco_erab_setup_request_multi.hex`: accepted Cisco E-RAB Setup Request from
  timestamp `14:35:42:114`, carrying EBI 6, 7, and 8.
* `cisco_erab_setup_response.hex`: accepted Ericsson E-RAB Setup Response from
  timestamp `14:35:42:214`, for EBI 6, 7, and 8.
* `vectorcore_erab_setup_malformed.hex`: malformed VectorCore E-RAB Setup
  Request that Ericsson rejected with protocol/transfer-syntax-error.

The Cisco trace also contains a later single dedicated-bearer E-RAB Setup
Request at `14:35:42:886`, but that printed hex block is one byte shorter than
the S1AP open-type length declared in the same PDU and is not used as a
permanent fixture.
