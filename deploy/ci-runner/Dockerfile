# Self-hosted GitHub Actions runner for Stakecraft/rutli CI (label `rutli-ci`).
# Adds what ci.yml expects from the GitHub ubuntu image: a C toolchain for cargo, jq, yq v4,
# kubectl, openssl, python3, and the docker CLI + compose plugin (jobs drive the HOST daemon
# through the mounted socket — see docker-compose.yml for the matching work-dir mount).
FROM docker:27.3.1-cli AS dockercli

# GitHub refuses to register runners below a minimum version (and the runner self-updates once
# registered), so bump this when registration reports "out of date".
FROM ghcr.io/actions/actions-runner:2.338.0
USER root
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      build-essential pkg-config curl ca-certificates git jq unzip openssl python3 \
 && rm -rf /var/lib/apt/lists/*
ARG YQ_VERSION=v4.44.6
ARG KUBECTL_VERSION=v1.31.4
RUN arch="$(dpkg --print-architecture)" \
 && curl -fsSL -o /usr/local/bin/yq "https://github.com/mikefarah/yq/releases/download/${YQ_VERSION}/yq_linux_${arch}" \
 && curl -fsSL -o /usr/local/bin/kubectl "https://dl.k8s.io/release/${KUBECTL_VERSION}/bin/linux/${arch}/kubectl" \
 && chmod 0755 /usr/local/bin/yq /usr/local/bin/kubectl
COPY --from=dockercli /usr/local/bin/docker /usr/local/bin/docker
COPY --from=dockercli /usr/local/libexec/docker/cli-plugins/ /usr/local/libexec/docker/cli-plugins/
# UTF-8 locale: without it the JVM cannot name class files like `$tilde$qmark$greater$λ.class`
# (sbt assembly fails with InvalidPathException), as GitHub's image would have it.
ENV LANG=C.UTF-8 LC_ALL=C.UTF-8
# A desktop Docker VM has a few GiB of RAM: cargo's default parallelism (one job per core) gets
# rustc/ld OOM-killed linking the cosigner test binaries. Bound it, and keep line tables only so
# debug links stay small. Runner-only: GitHub-hosted runs are unaffected.
ENV CARGO_BUILD_JOBS=4 CARGO_PROFILE_DEV_DEBUG=line-tables-only CARGO_PROFILE_TEST_DEBUG=line-tables-only
COPY entrypoint.sh /entrypoint.sh
RUN chmod 0755 /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
