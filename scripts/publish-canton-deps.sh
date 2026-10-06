#!/usr/bin/env bash
# Resolve the Canton KMS Driver API artifacts locally.
#
# The community artifacts `kms-driver-api` and `kms-driver-testing` are NOT on Maven Central. The
# reliable, credential-free way to build against them is to check out Canton at the pinned tag and
# `publishLocal`, after which sbt resolves them from the local ivy repo (see build.sbt resolvers).
#
# Modes:
#   default   publish kms-driver-api only — no inter-module deps, fast (~2 min). Enough for
#             `sbt driver/test` (unit suite) and `sbt driver/assembly`.
#   --full    additionally publish kms-driver-testing and its full transitive module closure
#             (community-base, daml-lf, ...). Required for `CONFORMANCE=1 sbt driver/test`.
#             The daml-lf modules need the `dpm` binary on PATH:
#             https://github.com/digital-asset/dpm/releases (single static binary).
#
# Usage:  scripts/publish-canton-deps.sh [--full] [CANTON_TAG]     (default tag: v3.5.6)
set -euo pipefail

FULL=false
TAG="v3.5.6"
for arg in "$@"; do
  case "$arg" in
    --full) FULL=true ;;
    *) TAG="$arg" ;;
  esac
done

WORK="${CANTON_CHECKOUT_DIR:-$HOME/.cache/canton-src}"

echo "Publishing Canton KMS driver API artifacts locally (tag=$TAG, full=$FULL)"

if $FULL && ! command -v dpm >/dev/null; then
  echo "ERROR: --full requires the 'dpm' binary on PATH (needed by Canton's daml-lf modules)."
  echo "Install: download your platform's tarball from https://github.com/digital-asset/dpm/releases"
  exit 1
fi

if [[ ! -d "$WORK/.git" ]]; then
  echo "Cloning digital-asset/canton into $WORK ..."
  git clone --depth 1 --branch "$TAG" https://github.com/digital-asset/canton.git "$WORK"
else
  echo "Reusing checkout at $WORK; fetching tag $TAG ..."
  git -C "$WORK" fetch --depth 1 origin "refs/tags/$TAG:refs/tags/$TAG" || true
  git -C "$WORK" reset --hard  # drop a previous run's daml-components override before switching
  git -C "$WORK" checkout "$TAG"
fi

cd "$WORK"

# Digital Asset prunes old snapshots from the public-unstable dpm registry, so the daml components
# version pinned inside a Canton tag (project/project/DamlVersions.scala) eventually stops
# existing and `damlInstall` dies with "not found" — the Canton tag itself never changes, the
# registry rots underneath it. Override the pin with a version that is still published. Bump the
# default below when the weekly conformance job reports the current one pruned; set
# DAML_COMPONENTS_VERSION=upstream to keep Canton's own pin.
DAML_COMPONENTS_VERSION="${DAML_COMPONENTS_VERSION:-3.6.0-snapshot.20260915.14804.0.v53478765}"
if $FULL && [[ "$DAML_COMPONENTS_VERSION" != "upstream" ]]; then
  DV="project/project/DamlVersions.scala"
  upstream_pin=$(grep -oE 'val version: String = "[^"]+"' "$DV" | sed -E 's/.*"([^"]+)".*/\1/')
  if [[ "$upstream_pin" != "$DAML_COMPONENTS_VERSION" ]]; then
    echo "Overriding Canton's daml components pin: $upstream_pin -> $DAML_COMPONENTS_VERSION"
    sed -E -i.bak 's/(val version: String = ")[^"]+(")/\1'"$DAML_COMPONENTS_VERSION"'\2/' "$DV"
    rm -f "$DV.bak"
  fi
fi

# NOTE: the in-repo fallback version is used for local publishing (e.g. 3.6.0-SNAPSHOT at tag
# v3.5.6); Digital Asset injects real release versions only in CI. Keep build.sbt's cantonVersion
# aligned with what lands in ~/.ivy2/local/com.daml/.
sbt -batch "kms-driver-api/publishLocal"

if ! $FULL; then
  echo "Done (api only). For the conformance suite run again with --full."
  exit 0
fi

sbt -batch "kms-driver-testing/publishLocal"

# kms-driver-testing's POM references sibling Canton modules that publishLocal does NOT publish
# automatically. Walk the local ivy dependency graph and publish missing com.daml modules until the
# closure is complete. Artifact names match sbt project ids in the Canton build.
for i in 1 2 3 4 5 6 7 8; do
  # `|| true`: an ivy.xml with no com.daml deps at all (e.g. wartremover-annotations) makes grep
  # exit 1, which under set -e/pipefail would silently kill the whole script mid-walk.
  missing=$(for f in ~/.ivy2/local/com.daml/*/*/ivys/ivy.xml; do
    grep -oE 'org="com\.daml" name="[a-zA-Z0-9._-]+"' "$f" |
      sed -E 's/.*name="([a-zA-Z0-9._-]+)"/\1/' || true
  done | sort -u | while read -r m; do
    [ -d ~/.ivy2/local/com.daml/"$m" ] || echo "${m%_2.13}"
  done | sort -u)

  # scalatest-utils has publish/skip upstream and only ever appears test-scoped in the POMs;
  # coursier does not resolve test-scoped transitive deps, so it is safe to ignore.
  missing=$(echo "$missing" | grep -v '^scalatest-utils$' || true)

  if [[ -z "$missing" ]]; then
    echo "Module closure complete."
    break
  fi
  echo "== closure iteration $i: publishing: $(echo "$missing" | tr '\n' ' ')"
  # shellcheck disable=SC2046
  sbt -batch $(for m in $missing; do printf '%s/publishLocal ' "$m"; done)
done

echo "Done. sbt will resolve com.daml %% kms-driver-api / kms-driver-testing from the local ivy repo."