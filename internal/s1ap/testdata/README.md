S1AP E-RAB Setup fixtures
=========================

These fixtures were derived from the local peer MME monitor trace at
`/tmp/peer-mme.log`.

The peer packets were accepted by the same Ericsson eNB used during
VectorCore interoperability testing. They are sanitized regression fixtures:
runtime identifiers, TEIDs, IP addresses, and NAS payloads are retained only as
test values required to validate APER structure and bearer association. The
full peer log is not committed and normal CI must not depend on it.

Fixtures:

* `peer_erab_setup_request_multi.hex`: accepted peer E-RAB Setup Request from
  timestamp `14:35:42:114`, carrying EBI 6, 7, and 8.
* `peer_erab_setup_response.hex`: accepted Ericsson E-RAB Setup Response from
  timestamp `14:35:42:214`, for EBI 6, 7, and 8.
* `vectorcore_erab_setup_malformed.hex`: malformed VectorCore E-RAB Setup
  Request that Ericsson rejected with protocol/transfer-syntax-error.

The peer trace also contains a later single dedicated-bearer E-RAB Setup
Request at `14:35:42:886`, but that printed hex block is one byte shorter than
the S1AP open-type length declared in the same PDU and is not used as a
permanent fixture.

Additional sanitized NAS fixtures:

* `legacy_iphone/pdn_disconnect_request_ebi6.hex`: UE-originated ESM
  `PDN Disconnect Request` (`0xd2`) observed in local iPhone IMS teardown logs.
  This is retained to regression-test the MME's IMS disconnect cleanup path:
  NAS deactivation, linked bearer suppression during resume, and later S11
  session deletion.
