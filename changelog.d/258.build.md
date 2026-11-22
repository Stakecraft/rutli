- **The load generator reports per-call peer timings** (#249). For each `call` class of
  `rutli_peer_call_duration_seconds` its report now gives, per load, the call count, p50, p99 and
  p99.9, the deadline, the share of calls that finished within a third of it (read at the bucket
  edge there), and whether the 3× margin rule holds (at least 99.9 % within a third). This is the
  readout that decides whether a peer-call deadline stays a constant or becomes a bounded setting.
