- **Where a signature's time goes.** New histograms, labelled by `result` only:
  `rutli_sign_round1_duration_seconds` and `rutli_sign_round2_duration_seconds` (a member's
  rounds), `rutli_sign_journal_append_duration_seconds` (lock wait included),
  `rutli_sign_journal_fsync_duration_seconds`, `rutli_nonce_marker_duration_seconds` and
  `rutli_intent_verify_duration_seconds`. New gauges: `rutli_signs_in_flight` (signatures this
  node leads) and the async runtime's workers, alive tasks, global queue depth and busy seconds (a
  cumulative gauge: use `rate()`) (`rutli_runtime_*`), sampled from the key-store watchdog thread. The blocking-pool queue depth
  needs unstable tokio APIs and is not exported. Metrics only: nothing changes in what is signed,
  journaled or refused.
