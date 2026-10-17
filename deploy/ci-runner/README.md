# Self-hosted CI runner

Runs this repo's `ci.yml` jobs on your own machine instead of GitHub-hosted runners. Useful when
hosted minutes are unavailable (for example, an organisation billing block), or when you need
more CPU or memory than a hosted runner has.

## Switching CI to it

Each job in `ci.yml` runs on `${{ vars.CI_RUNNER || 'ubuntu-latest' }}`. To switch:
1. Start the runner with `scripts/ci-runner-up.sh`. This needs `gh` authenticated with admin
   rights on the repo, because it fetches a one-hour registration token.
2. Point the jobs at the runner:
   ```bash
   gh variable set CI_RUNNER --body rutli-ci --repo Stakecraft/rutli
   ```

To go back to GitHub-hosted runners, run `gh variable delete CI_RUNNER --repo Stakecraft/rutli`.
To stop the runner, run `docker compose -f deploy/ci-runner/docker-compose.yml down`, then remove
it under the repo's Settings → Actions → Runners.

## Trust and limits

- **Jobs have full control of the host's Docker daemon.** They reach it through the mounted
  socket, and that amounts to root on the Docker VM. Use the runner only for this private repo
  and trusted branches. Never attach it to a public repository: fork pull requests would run
  arbitrary code on your machine.
- **One job at a time.** CI is slower than on GitHub's parallel runners. The image limits cargo
  to 4 parallel jobs with line-table debug info, so that a few-GiB Docker VM does not OOM-kill
  the linker. If you can, give Docker Desktop at least 8 GiB.
- **The runner's architecture is the host's.** On Apple silicon that is arm64. All jobs work
  there, except the `conformance` job's `dpm` download, which is amd64 only. That job runs on
  schedule or manual dispatch, not on pull requests. For full parity, run the runner on a Linux
  amd64 host.
- **`actions/cache` and artifact upload still use GitHub's service.** If that is blocked, they
  only warn. No job depends on them.
