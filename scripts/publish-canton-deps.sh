#!/usr/bin/env bash
# Resolve the Canton KMS Driver API artifacts locally.
#
# The community artifacts `kms-driver-api` and `kms-driver-testing` are NOT on Maven Central. The
# reliable, credential-free way to build against them is to check out Canton at the pinned tag and
# `publishLocal`, after which sbt resolves them from your local ivy repo (see build.sbt resolvers).
#
# Usage:  scripts/publish-canton-deps.sh [CANTON_TAG]   (default: v3.5.6)
set -euo pipefail

TAG="${1:-v3.5.6}"
WORK="${CANTON_CHECKOUT_DIR:-$HOME/.cache/canton-src}"

echo "Publishing Canton KMS driver API artifacts locally (tag=$TAG)"

if [[ ! -d "$WORK/.git" ]]; then
  echo "Cloning digital-asset/canton into $WORK ..."
  git clone --depth 1 --branch "$TAG" https://github.com/digital-asset/canton.git "$WORK"
else
  echo "Reusing checkout at $WORK; fetching tag $TAG ..."
  git -C "$WORK" fetch --depth 1 origin "refs/tags/$TAG:refs/tags/$TAG"
  git -C "$WORK" checkout "$TAG"
fi

# Publish just the two modules we depend on (and their transitive community deps) to the ivy local.
( cd "$WORK" && sbt "kms-driver-api/publishLocal" "kms-driver-testing/publishLocal" )

echo "Done. build.sbt (Resolver.defaultLocal / mavenLocal) will now resolve:"
echo "  com.digitalasset.canton %% kms-driver-api     % <version>"
echo "  com.digitalasset.canton %% kms-driver-testing % <version>"
echo "Ensure cantonVersion in build.sbt matches the published version (tag $TAG -> e.g. 3.5.6)."
