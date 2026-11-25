- **Sign journal retention keeps the last day's entries and the newest segment.** The cosigner
  rebuilds its per-key sign rate limit from the journal's last 24 h when it opens a key's journal.
  Retention now keeps what that needs:
  - neither the size cap (`signing_policy.journal_max_mib_per_key`) nor the age limit deletes a
    segment whose newest entry is less than a day old, or whose last entry cannot be read. A key
    that writes more than the cap in a day stays above it until those entries age out; this is
    logged and counted in the new `rutli_sign_journal_over_cap_total`;
  - retention runs only right after the cosigner appended and synced an entry itself, never when a
    journal is opened, never deletes the current segment or the newest segment that holds entries,
    syncs the directory after each deletion, and stops at a segment it cannot read;
  - the rate limit is read back by each segment's newest entry, not its first;
  - a segment file is always created new: an existing file of that name is an error and is never
    truncated. A new segment's name always sorts after the current one;
  - the key directory is synced each time a journal is opened, and an error while listing it is
    returned instead of being read as a shorter listing;
  - links between segments are checked across empty segments, sequence numbers included;
  - a segment read on open that starts the hash chain afresh without being the key's first segment
    is logged and counted in the new `rutli_sign_journal_chain_restarts_total`; the journal still
    opens;
  - `check-config` reports an advisory finding when `journal_max_mib_per_key` is below an estimate
    of one day's journal at the highest daily sign limit (one share per charge, 600 bytes each,
    plus 8 MiB).

  No configuration change is needed. A journal above the cap with entries older than a day is
  trimmed after the first sign that follows a start or a rotation.
