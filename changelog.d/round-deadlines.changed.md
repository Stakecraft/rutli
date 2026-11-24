- **The sign round 1 and round 2 deadlines are configuration** (#249). `peer_deadlines.sign_round1_ms`
  (default 2000, 500 to 5000) and `peer_deadlines.sign_round2_ms` (default 5000, 1000 to 9000) replace
  the constants, for a cluster whose burst latency leaves less than a 3x margin. A node rejects the
  section until it runs this release, so set it only after every node is upgraded. The
  `rutli_peer_call_duration_seconds` histogram gains buckets at 1.05, 2.1, 3.15 and 5.25 s, just above
  the deadlines.
