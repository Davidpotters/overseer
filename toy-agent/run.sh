#!/usr/bin/env bash
# Runs the toy agent under a hardened container profile: non-root, all
# capabilities dropped, read-only root filesystem, no network, and hard
# CPU, memory, and process-count limits. Every flag here was adversarially
# tested against this image before this project's Monitor component was
# ever built.
set -euo pipefail

docker build -t overseer/toy-agent:dev "$(dirname "$0")"

docker run \
  --rm \
  --user 10001:10001 \
  --cap-drop=ALL \
  --security-opt=no-new-privileges \
  --read-only \
  --tmpfs /tmp \
  --tmpfs /scratch:uid=10001,gid=10001,mode=0700 \
  --network none \
  --memory=256m --cpus=0.5 --pids-limit=64 \
  "$@" \
  overseer/toy-agent:dev
