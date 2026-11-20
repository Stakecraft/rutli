- **A cosigner that stops answering, or loses its volume, costs a signature one short deadline,
  not one or two 10 s timeouts** (#153, #174, #176). Before, peer calls had one 10 s timeout that
  started only after the connection, peer channels had no keepalive (a healed partition or a
  replaced pod left every call on a dead connection waiting the full timeout), the leader waited
  for the abort of the member that had just failed, and a leader cut off from its peers held a
  signature until the client gave up. Now:
  - peer channels run HTTP/2 keepalive (5 s, PONG within 3 s, also while idle), TCP keepalive and,
    on Linux, `TCP_USER_TIMEOUT`; a connection must be up within 3 s, and a dead one is replaced
    within about 8 s;
  - every peer call has its own deadline on the leader's clock (sign round 1 2 s, round 2 5 s,
    abort 1 s, `NodeInfo`/`KeyEpoch`/`CeremonyStatus` 3 s; ceremonies and hosted-key writes keep
    10 s), sent to the peer as `grpc-timeout`. Inside a Sign that carries a deadline the rounds fit
    it: a deadline under 1 s is refused at once with `DEADLINE_EXCEEDED`; without one a signature
    has 20 s (was 45 s). At most two subset attempts per signature (was 10);
  - each leader keeps a liveness state per peer, fed only by its own calls: a peer that is
    unreachable, whose sign rounds stop completing while it reports no progress (`rutli-load` reply
    metadata), or that answers `keystore-down` is tried last — never skipped — until a probe or a
    trial brings it back. A busy member that keeps making progress is never marked down. DKG,
    refresh and hosted-key writes do not consult it;
  - a leader that cannot reach t cosigners answers `UNAVAILABLE` with the `rutli-error: no-quorum`
    trailer before round 1; an overloaded leader (512 signatures in flight, or its own round late)
    answers `UNAVAILABLE` `overloaded`; the driver fails over on both as before;
  - a member whose round-2 store work fails with a definite I/O error marks its key store down at
    once and answers with the `rutli-error: keystore-down` trailer; store work still running after
    3 s starts a key-store probe at once. The next probe that finds the store working clears it,
    with no restart.

  New metrics `rutli_peer_call_duration_seconds{call}`, `rutli_peer_state{peer,state}`,
  `rutli_peer_breaker_transitions_total{peer,to,reason}` and
  `rutli_sign_fast_refusals_total{reason}`, and alerts `RutliPeerDown`, `RutliPeerFlapping` and
  `RutliNoQuorum` (critical). No configuration and no wire-format change; a mixed-version cluster
  works (an older member's refusals read as plain `UNAVAILABLE`). `docs/architecture.md`, "Peer
  liveness".
