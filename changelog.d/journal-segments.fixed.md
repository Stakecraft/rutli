- **Sign journal retention keeps the last day's entries and the newest segment.** The cosigner
  rebuilds its per-key sign rate limit from the journal's last 24 h after a restart. Retention now
  keeps what that needs:
  - the size cap (`signing_policy.journal_max_mib_per_key`) no longer deletes a segment whose
    newest entry is less than a day old. A key that writes more than the cap in a day stays above
    it until those entries age out; this is logged and counted in the new
    `rutli_sign_journal_over_cap_total`;
  - retention runs after the first entry of a new segment is written and synced, not when the
    segment is created, and never deletes the newest segment that holds entries;
  - a segment file is always created new: an existing file of that name is an error and is never
    truncated;
  - an error while listing a key's journal directory is returned instead of being read as a
    shorter listing;
  - a segment found on open that starts the hash chain afresh without being the key's first segment
    is logged and counted in the new `rutli_sign_journal_chain_restarts_total`; the journal still
    opens;
  - `check-config` reports an advisory finding when `journal_max_mib_per_key` is below about
    600 bytes × the highest daily sign limit + 8 MiB.

  No configuration change is needed. A journal that is above the cap with entries older than a day
  is trimmed on the next open or rotation, as before.
