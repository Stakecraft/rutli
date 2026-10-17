# Self-hosted CI runner (isolated Colima VM)

Runs this repo's `ci.yml` jobs on your own machine instead of GitHub-hosted runners. Useful when
hosted minutes are unavailable (for example, an organisation billing block), or when you need
more CPU or memory than a hosted runner has.

## Trust model

**A job controls the Docker daemon it is given, and that is root on the daemon's host.** The
runner container mounts the daemon's socket (jobs such as `frost-tls-smoke` run `docker compose`
with bind mounts), so any workflow step can start a privileged container and bind-mount anything
that daemon can see. Treat "can run a job" as "is root on the Docker host".

What that daemon can see decides the blast radius:

- **Docker Desktop (macOS): unsafe, unsupported.** Its daemon shares `/Users`, so a job could read
  your kubeconfig, AWS SSO cache, `gh` and ghcr tokens, SSH keys and any drill or key material in
  your home directory. This was verified. The earlier setup of "mount the host Docker Desktop
  socket into the runner" is therefore not supported; do not run `docker-compose.yml` against
  Docker Desktop or any daemon whose host shares your home.
- **Dedicated Colima VM (`rutli-ci` profile): supported.** The VM is started with a single host
  mount, an empty directory (`~/.rutli-ci-empty`), read-only. That replaces Colima's default
  mount of `$HOME`. The job work dir lives inside the VM (`/var/lib/rutli-ci/work`). A job that
  takes over the VM's daemon gets root in a throwaway VM that holds no host files.

What the VM still exposes:

- **Network egress.** The VM has your machine's network access: the LAN, anything reachable from
  your VPN, and the internet. A malicious job can scan or call whatever your Mac can reach.
- **The runner's registration and the job's `GITHUB_TOKEN`.** Jobs can read the runner config in
  the VM and use the job's `GITHUB_TOKEN` with whatever permissions `ci.yml` grants it. Repo
  secrets that a job is given are visible to that job as on any runner.
- **Whatever you put in the VM.** Do not copy credentials into it or add mounts.

Consequences: use the runner **only for this private repo and trusted branches**. Never attach it
to a public repository, and never to one that runs fork pull requests, because that would run
arbitrary code with the access above.

`scripts/ci-runner-up.sh` enforces the isolation rather than assuming it. It refuses to continue
if the VM mounts anything other than the empty directory read-only, if the `colima-rutli-ci`
docker context does not point at the profile's own socket, or if a probe container can see files
under `$HOME`. It never falls back to the default Docker context.

## Start

Needs `colima`, `docker` with the compose plugin, and `gh` authenticated with admin rights on the
repo (it fetches a one-hour registration token, which is never printed).

```bash
scripts/ci-runner-up.sh
```

This is idempotent. It creates the VM if missing, starts it if stopped, verifies the mounts and
isolation, creates the work dir inside the VM, and runs `docker-compose.yml` against the VM's
daemon. It restores your previous Docker context afterwards (`colima start` switches it), so
Docker Desktop stays your default. Re-running re-registers the runner under the same name.

The VM is created with exactly:

```bash
colima start --profile rutli-ci --cpu 4 --memory 8 --disk 60 --vm-type vz --arch aarch64 \
  --runtime docker --mount ~/.rutli-ci-empty
```

Overrides: `RUNNER_REPO`, `RUNNER_NAME` (default `rutli-ci-isolated`), `RUNNER_WORKDIR` (a path
inside the VM under `/var/lib/rutli-ci/`), `RUTLI_CI_PROFILE`, `RUTLI_CI_CPU`,
`RUTLI_CI_MEMORY` (GiB), `RUTLI_CI_DISK` (GiB). The runner label stays `rutli-ci`.

Check the isolation by hand at any time:

```bash
colima ssh -p rutli-ci -- mount | grep virtiofs        # one line: the empty dir, ro
docker --context colima-rutli-ci run --rm -v $HOME/.kube:/x:ro alpine:3.20 ls /x   # lists nothing
```

Follow the runner: `docker --context colima-rutli-ci compose -f deploy/ci-runner/docker-compose.yml -p rutli-ci-isolated logs -f`.

## Route CI to it, and back

Each job in `ci.yml` runs on `${{ vars.CI_RUNNER || 'ubuntu-latest' }}`.

```bash
gh variable set CI_RUNNER --body rutli-ci --repo Stakecraft/rutli      # use the self-hosted runner
gh variable delete CI_RUNNER --repo Stakecraft/rutli                   # back to GitHub-hosted
```

Switch back before stopping the runner, or queued jobs will wait for a runner that is gone.

## Stop and delete

```bash
scripts/ci-runner-down.sh              # remove the runner container; the VM keeps running
colima stop -p rutli-ci                # stop the VM (start it again with scripts/ci-runner-up.sh)
scripts/ci-runner-down.sh --delete-vm  # also delete the VM, its images and caches
```

Neither script touches GitHub. Unregister the runner, or remove it under Settings, Actions,
Runners:

```bash
id=$(gh api repos/Stakecraft/rutli/actions/runners -q '.runners[] | select(.name=="rutli-ci-isolated") | .id')
gh api -X DELETE repos/Stakecraft/rutli/actions/runners/$id
```

## Resources and limits

- **4 CPU, 8 GiB, 60 GiB disk** for the VM. The image limits cargo to 4 parallel jobs with
  line-table debug info, so that the linker is not OOM-killed. Raise the numbers with the
  `RUTLI_CI_*` variables when creating the VM (an existing VM keeps its size; change it with
  `colima stop` and `colima start -p rutli-ci --cpu N --memory N`, or delete and recreate it).
- **One job at a time.** CI is slower than on GitHub's parallel runners.
- **The architecture is arm64** (Apple silicon, `--arch aarch64`). All jobs work there, except
  the `conformance` job's `dpm` download, which is amd64 only. That job runs on schedule or
  manual dispatch, not on pull requests. amd64 image builds run under emulation and are slow.
  For full parity, use a Linux amd64 host.
- **`actions/cache` and artifact upload still use GitHub's service.** If that is blocked, they
  only warn. No job depends on them.
