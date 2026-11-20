<!-- Security fixes for undisclosed vulnerabilities do not go in a public PR: see SECURITY.md. -->

## What and why

## How it was tested

## Checklist

- [ ] Tests cover the change (a bug fix includes the test that reproduces it)
- [ ] Changelog fragment `changelog.d/<PR number>.<section>.md` added, if users or operators would notice (or the label `no-changelog`; see `changelog.d/README.md`)
- [ ] Docs and runbooks updated, if behaviour or configuration changed
- [ ] Compatibility stated: rolling-upgrade order, wire / key-file / config format changes, rollback
- [ ] No key material, secrets or tokens added, not even test ones (tests generate keys at run time)
- [ ] Every commit is signed off (`git commit -s`, DCO)
- [ ] Key-path change (FROST, nonces, sealing, intents, ceremonies, key routing, TLS): second, independent review done
- [ ] No infrastructure details (hosts, IPs, cluster names)
