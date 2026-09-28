# WireScope JSON export schema

Documents the structure written by `wirescope capture.pcap --json report.json`
(see `wirescope.exporters.json_exporter.to_json_dict`). Same data model the
CSV and HTML exporters are built from, so this doubles as a field reference
for all three export formats.

## Versioning

Every export includes `"schema_version"` (currently `"0.1.0"`, tracked in
`wirescope.exporters.json_exporter.SCHEMA_VERSION`). Within a `0.x` schema
version, fields may be added but existing fields will not be renamed or
removed without a version bump. There is no automated migration between
versions yet - consumers should check `schema_version` and fail closed on
an unrecognized one rather than guess.

## Top-level keys

| Key | Type | Description |
|---|---|---|
| `schema_version` | string | See above. |
| `capture` | object | Capture-level metadata and totals. |
| `statistics` | object | ICMP/TCP-flag counters, entropy signal, collection-limit flags. |
| `hosts` | array | Per-IP activity, sorted by packet count descending. |
| `ports` | object | `{"source": [...], "destination": [...]}` PortStats arrays. |
| `conversations` | array | Normalized 5-tuple flows, sorted by byte count descending. |
| `dns` | array | DNS queries and responses, as separate entries. |
| `http` | array | Plaintext HTTP requests and responses, as separate entries. |
| `tls` | array | TLS ClientHello metadata (SNI, record version only). |
| `arp` | array | Per-IP ARP activity. |
| `findings` | array | Heuristic + IOC findings, most severe first. |

## `capture`

`file_name`, `file_size_bytes`, `capture_start`/`capture_end` (Unix
timestamps, `null` if the filtered capture matched zero packets),
`duration_seconds`, `total_packets`/`total_bytes` (post-filter),
`average_packet_size`, `packets_per_second`/`bytes_per_second` (fall back
to the raw total rather than dividing by zero when duration is 0),
`protocol_counts` (`{ipv4, ipv6, tcp, udp, icmp, arp, other}` - network-
and transport-layer buckets are not mutually exclusive, a packet can
count toward both).

## `statistics`

`icmp` (`{echo_request, echo_reply, type_code_counts}`), `tcp_flags`
(`{syn, ack, fin, rst, psh, syn_only}` - `syn_only` means SYN set, ACK
not set), `high_entropy_packet_count` (weak signal, see Detection
Philosophy in the README), `collection_limits` (per-category
`*_truncated` booleans - `true` means that collection hit its cap and
further detail records were not retained; totals elsewhere stay
accurate), `malformed_packet_count` (packets that raised during parsing
and were skipped rather than aborting the run - nonzero doesn't
necessarily mean malicious, could be an unusual encapsulation or a bug).

## `hosts[]`

`ip`, `packet_count`, `bytes_sent`, `bytes_received`, `total_bytes`,
`unique_peers` (a count, not the peer list), `ports_used` (sorted list,
source or destination).

## `ports.source[]` / `ports.destination[]`

`port`, `protocol` (`TCP`/`UDP`), `packet_count`, `service_name` (from a
small hardcoded well-known-ports map, `null` if unrecognized - a hint,
not a fact).

## `conversations[]`

`src_ip`, `src_port`, `dst_ip`, `dst_port`, `protocol`, `packet_count`,
`byte_count`, `first_seen`, `last_seen`, `duration_seconds`. The
`src`/`dst` labeling is a normalized, stable choice (lexicographically
smaller `(ip, port)` pair) - it does not indicate who initiated the
conversation. Reverse-direction packets are folded into the same entry.

## `dns[]`

`query_name`, `query_type` (`A`/`AAAA`/`CNAME`/`MX`/`TXT` or the raw
numeric type as a string), `source`, `destination`, `timestamp`,
`is_response`, `response_code` (`null` for queries), `answers` (decoded
rdata strings, empty for queries/NXDOMAIN). Queries and responses are not
linked by an id - match via `query_name`/timestamp proximity if needed.

## `http[]`

`direction` (`request`/`response`), `src_ip`, `dst_ip`, `timestamp`, then
request-only (`method`, `host`, `path`, `user_agent`) and response-only
(`status_code`, `content_type`, `server`) fields - whichever side doesn't
apply is `null`. Plaintext only; TLS is never decrypted.

## `tls[]`

`src_ip`, `dst_ip`, `timestamp`, `sni` (`null` if absent/unparseable),
`record_version` (record-layer version string - TLS 1.3 still negotiates
over a record layer claiming 1.2, so this cannot distinguish 1.2 from
1.3). No certificate data, cipher suite, or JA3/JA4 - see README Roadmap.

## `arp[]`

`ip`, `mac_addresses` (sorted list - more than one is the raw fact the
"Possible ARP inconsistency" finding is built from, not a conclusion on
its own), `requests`, `replies`.

## `findings[]`

`title`, `severity` (`INFO`/`LOW`/`MEDIUM`/`HIGH`), `description`,
`evidence` (a short, specific observed fact), `confidence`
(`low`/`medium`/`high`, free-text, not calibrated against ground truth),
`host` (nullable), `timestamp` (nullable). Every finding is a hypothesis
for an analyst to review, not a verdict.
