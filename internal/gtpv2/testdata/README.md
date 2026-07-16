These fixtures are sanitized S11 GTPv2-C messages extracted from the local peer
reference traces:

- `/tmp/nokia.trace`
- `/tmp/sonim.trace`

They are retained as interoperability regression inputs only. The full peer
traces are not required for normal test runs. Runtime identifiers, TEIDs, and
packet contents are test-only values copied from the reference packets where
they affect protocol decoding.

Several peer Create Bearer Requests intentionally contain nested Bearer Context
EPS Bearer ID value `0`. The peer allocates the final dedicated EBI locally before
NAS activation and S1AP E-RAB Setup, so VectorCore must preserve this distinction
instead of treating EBI zero as an already assigned bearer.
