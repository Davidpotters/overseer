#!/usr/bin/env bash
# Runs Halt with access to the Docker Engine API socket. The socket is
# root:docker-owned (srw-rw----) on a real Docker host -- rather than
# running this container as root or loosening the socket's own
# permissions, it joins the docker group by GID, the same pattern real
# CI systems use to grant unprivileged containers socket access. The GID
# is resolved from the actual socket at run time, not hardcoded, since
# it varies by host.
set -euo pipefail

# Resolved through the daemon itself, not the local shell: a -v bind
# mount's source path is resolved by whatever host the Docker daemon
# actually runs on (colima's Linux VM here, not this Mac), and so must
# this stat be -- a local `stat /var/run/docker.sock` fails outright on
# macOS since that path only exists inside the VM. This one throwaway
# container also makes the lookup portable to any Docker host, colima
# or not.
DOCKER_GID="$(docker run --rm -v /var/run/docker.sock:/var/run/docker.sock alpine:3.20 stat -c '%g' /var/run/docker.sock)"

docker build -t overseer/halt:dev "$(dirname "$0")/../.." -f "$(dirname "$0")/Dockerfile"

docker run \
  --rm \
  -v /var/run/docker.sock:/var/run/docker.sock \
  --group-add "$DOCKER_GID" \
  overseer/halt:dev \
  "$@"
