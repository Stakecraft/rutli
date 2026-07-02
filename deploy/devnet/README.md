# Phase 0 devnet

Boots a Canton participant whose crypto is delegated to the `rutli` driver, and runs a smoke
test that proves the driver is loaded and used to generate + sign the node's identity keys.

## Prerequisites

1. **Canton 3.5.x community release.** Download the `v3.5.6` release, extract it, and point
   `CANTON_HOME` at the extracted directory:
   - https://github.com/digital-asset/canton/releases/tag/v3.5.6
   ```sh
   export CANTON_HOME=/path/to/canton-open-source-3.5.6
   ```
2. **The driver fat jar.** From the repo root:
   ```sh
   scripts/publish-canton-deps.sh v3.5.6   # first time only: resolve the Canton API artifacts
   sbt driver/assembly                     # -> driver/target/scala-2.13/rutli-driver.jar
   ```

## Run

```sh
deploy/devnet/up.sh
```

This copies the driver jar into `$CANTON_HOME/lib/` (so it's on the classpath and discovered via
`ServiceLoader`), starts the participant with `canton.conf`, and runs `bootstrap.canton`.

## What "pass" looks like

- The node reaches `initialized = true`. Reaching that state **requires** the driver to have
  generated the namespace + signing keys and signed the identity topology transactions — so a clean
  init is itself the end-to-end proof.
- With `audit-logging = true`, the driver logs each `generateSigningKeyPair` / `sign` / `getPublicKey`
  call. You should see `sign` calls for the namespace key during init.
- `participant1.keys.public.list()` shows the keys, confirming they were produced by the driver.

## Notes

- The embedded `sequencer1` / `mediator1` in `canton.conf` use the default `jce` provider. They're
  there so you can optionally extend the test to connect the participant to a synchronizer and
  exercise cross-node topology signing (see the commented block in `bootstrap.canton`).
- Node/port config schema tracks Canton 3.5.x. If the release rejects a key, compare against the
  `reference.conf` bundled in `$CANTON_HOME`.
