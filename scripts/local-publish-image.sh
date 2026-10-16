#!/usr/bin/env bash
# Build and push the multi-arch cosigner image from a workstation, the way
# .github/workflows/publish-image.yml does (context frost/, frost/Dockerfile, linux/amd64 +
# linux/arm64, tag = the semver of the git tag without the leading v). For when GitHub Actions is
# unavailable. Prints the multi-arch index digest to pin (as in the release digest-pin commit).
#
# Usage (from repo root, on a clean checkout of the tag):
#   scripts/local-publish-image.sh v0.4.0-rc.3            # build + push
#   DRY_RUN=1 scripts/local-publish-image.sh v0.4.0-rc.3  # build both platforms, push nothing
#
# Needs: Docker with buildx and QEMU (Docker Desktop has both), and `docker login ghcr.io` with a
# token that has write:packages (e.g. `gh auth token | docker login ghcr.io -u <user> --password-stdin`).
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."
REF="${1:?usage: $0 <git tag, e.g. v0.4.0-rc.3>}"
IMAGE="${IMAGE:-ghcr.io/stakecraft/rutli-cosigner}"
BUILDER="${BUILDER:-rutli-builder}"
PLATFORMS="linux/amd64,linux/arm64"

[[ "$REF" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$ ]] || { echo "not a release tag: $REF" >&2; exit 2; }
VERSION="${REF#v}"

# Build exactly the tagged tree: refuse a dirty checkout or a HEAD that is not the tag.
[ -z "$(git status --porcelain --untracked-files=no)" ] || { echo "working tree has changes; check out $REF cleanly" >&2; exit 1; }
[ "$(git rev-parse HEAD)" = "$(git rev-parse "$REF^{commit}")" ] || { echo "HEAD is not $REF" >&2; exit 1; }

docker buildx inspect "$BUILDER" >/dev/null 2>&1 || docker buildx create --name "$BUILDER" --driver docker-container >/dev/null
docker buildx inspect "$BUILDER" --bootstrap | grep -q 'linux/arm64' || { echo "builder $BUILDER lacks linux/arm64" >&2; exit 1; }

REVISION="$(git rev-parse HEAD)"
CREATED="$(git log -1 --format=%cI "$REF")"
LABELS=(
  --label "org.opencontainers.image.source=https://github.com/Stakecraft/rutli"
  --label "org.opencontainers.image.version=$VERSION"
  --label "org.opencontainers.image.revision=$REVISION"
  --label "org.opencontainers.image.created=$CREATED"
)

if [ "${DRY_RUN:-}" = 1 ]; then
  echo "==> building $IMAGE:$VERSION for $PLATFORMS (dry run, not pushed)"
  docker buildx build --builder "$BUILDER" --platform "$PLATFORMS" -f frost/Dockerfile "${LABELS[@]}" frost
  exit 0
fi

echo "==> building and pushing $IMAGE:$VERSION for $PLATFORMS (revision $REVISION)"
docker buildx build --builder "$BUILDER" --platform "$PLATFORMS" -f frost/Dockerfile \
  "${LABELS[@]}" -t "$IMAGE:$VERSION" --push frost

DIGEST="$(docker buildx imagetools inspect "$IMAGE:$VERSION" --format '{{json .Manifest}}' | jq -r .digest)"
echo "==> pushed $IMAGE:$VERSION"
echo "    index digest: $DIGEST"
echo "    pin as: tag: \"$VERSION@$DIGEST\""
