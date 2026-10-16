# Self-hosted GitHub Actions runner for Stakecraft/rutli CI (label `rutli-ci`).
# Adds what ci.yml expects from the GitHub ubuntu image: a C toolchain for cargo, jq, yq v4,
# kubectl, openssl, python3, and the docker CLI + compose plugin (jobs drive the HOST daemon
# through the mounted socket — see docker-compose.yml for the matching work-dir mount).
FROM docker:27.3.1-cli AS dockercli

FROM ghcr.io/actions/actions-runner:2.321.0
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
COPY entrypoint.sh /entrypoint.sh
RUN chmod 0755 /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
