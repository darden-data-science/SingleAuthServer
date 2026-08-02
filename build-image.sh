#!/usr/bin/env bash
# Build (and optionally push) a versioned SingleAuthServer image.
#
# Why this exists: the deployed image was previously only ever tagged :latest,
# so there was no way to say "roll back to what was running last Tuesday" — the
# bytes behind that tag are unrecoverable once overwritten. Every build here is
# addressable three ways:
#
#   :<version>      0.2.0.dev0   — human-readable milestone, from _version.py
#   :sha-<short>    sha-4a881f0  — exact commit, always unique, never reused
#   :latest         convenience only; NEVER reference this from a helm chart
#
# The chart should pin :sha-<short> or :<version>. Never :latest.
#
# Usage:
#   ./build-image.sh                 build only
#   ./build-image.sh --push          build and push all three tags
#   ./build-image.sh --repo my/repo  override the target repository
set -euo pipefail
cd "$(dirname "$0")"

REPO="albertmichaelj/saml_single_auth_server"
PUSH=0

while [ $# -gt 0 ]; do
  case "$1" in
    --push) PUSH=1 ;;
    --repo) shift; REPO="$1" ;;
    --repo=*) REPO="${1#*=}" ;;
    -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
  shift
done

# Version comes from the one place that defines it.
VERSION=$(python3 -c "import re,pathlib; \
  t=pathlib.Path('SingleAuthServer/_version.py').read_text(); \
  ns={}; exec(t,ns); print(ns['__version__'])")

GIT_SHA=$(git rev-parse --short HEAD)
GIT_SHA_FULL=$(git rev-parse HEAD)
BUILD_DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ)
BRANCH=$(git rev-parse --abbrev-ref HEAD)

# A dirty tree produces an image that matches no commit. Tag it so it can never
# be mistaken for a reproducible build.
if ! git diff-index --quiet HEAD -- 2>/dev/null; then
  GIT_SHA="${GIT_SHA}-dirty"
  echo "WARNING: working tree is dirty. Tagging as ${GIT_SHA}." >&2
  echo "         Commit before building anything you intend to deploy." >&2
fi

echo "repo:    $REPO"
echo "version: $VERSION"
echo "commit:  $GIT_SHA_FULL ($BRANCH)"
echo "tags:    $VERSION, sha-$GIT_SHA, latest"
echo

docker build \
  --platform=linux/amd64 \
  --build-arg "VERSION=$VERSION" \
  --build-arg "GIT_SHA=$GIT_SHA_FULL" \
  --build-arg "BUILD_DATE=$BUILD_DATE" \
  -t "$REPO:$VERSION" \
  -t "$REPO:sha-$GIT_SHA" \
  -t "$REPO:latest" \
  .

echo
echo "built. verify with:"
echo "  docker inspect --format '{{json .Config.Labels}}' $REPO:sha-$GIT_SHA"

if [ "$PUSH" -eq 1 ]; then
  case "$GIT_SHA" in
    *-dirty)
      echo "REFUSING to push a dirty build. Commit first." >&2
      exit 1 ;;
  esac
  echo
  for tag in "$VERSION" "sha-$GIT_SHA" latest; do
    echo "pushing $REPO:$tag"
    docker push "$REPO:$tag"
  done
  echo
  echo "Pin the chart to:  $REPO:sha-$GIT_SHA"
fi
