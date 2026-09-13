#!/usr/bin/env bash
# Deploy the mathlib package to an environment through the release service.
# Usage: scripts/deploy.sh <staging|production>
set -euo pipefail
ENV="${1:?usage: scripts/deploy.sh <staging|production>}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=/dev/null
[ -f "$ROOT/.deployrc" ] && . "$ROOT/.deployrc"
: "${RELEASE_SERVICE_URL:?RELEASE_SERVICE_URL not set; see .deployrc}"
: "${PROJECT_ID:?PROJECT_ID not set; see .deployrc}"
VERSION="$(git -C "$ROOT" rev-parse --short HEAD 2>/dev/null || echo unknown)"
STAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
mkdir -p "$ROOT/deploy/$ENV"
TARBALL="$ROOT/deploy/mathlib-$VERSION.tar.gz"
echo "Packaging mathlib@$VERSION for $ENV..."
tar -czf "$TARBALL" -C "$ROOT" mathlib
echo "Uploading to release service ($RELEASE_SERVICE_URL)..."
curl -fsS -X POST "$RELEASE_SERVICE_URL/projects/$PROJECT_ID/deploy/$ENV" -H "X-Mathlib-Version: $VERSION" \
  --data-binary @"$TARBALL" -o /dev/null
echo "$STAMP $VERSION" > "$ROOT/deploy/$ENV/LAST_DEPLOY"
rm -f "$TARBALL"
echo "=== mathlib@$VERSION deployed to $ENV ($STAMP) ==="
