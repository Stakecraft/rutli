- **`verify-key --sign-test` signs a version 2 message, bound to the quorum, the sharing and a fresh
  challenge.** For every call `verify-key` draws a 32-byte challenge (`CeremonySignTestRequest.challenge`,
  forwarded to the members as `SignRound1Request.sign_test_challenge`). The message is `0x1220 ‖
  SHA-256` over a domain tag and the length-prefixed ceremony id, key id, epoch, PKP digest, sorted
  signer set and challenge. The leader and every member compute it from their own live share, and a
  member joins only a quorum of exactly `t` distinct cosigners that includes it; `verify-key`
  recomputes it from the epoch and digest every node reported. The report states
  `sign_test_message_version`. A request without a challenge (a 0.4.x `verify-key`) still gets the
  version 1 message until 0.6 (#325); a 0.5 `verify-key` refuses a version 1 answer, so run
  `verify-key --sign-test` and `keyfile prove` only after every cosigner runs 0.5. Every
  `keyfile prove` marker states the message version of its report (`message_version`; a marker
  without it reads as version 1). A version 1 marker still counts for `backup-retain`, which prints a
  `BACKUP_RETENTION_WARNING … proof=version-1` line until the epoch is proven again on 0.5.
