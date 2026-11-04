#!/bin/sh
# sandbox-box-import <image> — load the box image into the inner daemon.
# Used by the entrypoint at boot and by the spike in a fresh container, so the
# spike's boxes are byte-for-byte the runner's.
#
# The pre-built rootfs shipped in the image is ALWAYS imported when present,
# even over an existing tag: Compose carries the dind's /var/lib/docker volume
# over to a re-created container, so an image already in the daemon may be an
# older release's box. Without the tarball (a dev build), an existing image is
# kept, else the box is built from /opt/box (needs network) and flattened.
#
# `docker import` keeps only the --change settings: no ENV from the base image
# reaches a box. The default user is nobody; the runner always passes --user.
set -eu

IMAGE="${1:?usage: sandbox-box-import <image>}"
TARBALL=/opt/box-rootfs.tar.gz

import_box() {
  docker import \
    --change 'USER 65534:65534' \
    --change 'WORKDIR /tmp' \
    --change 'CMD ["python3"]' \
    "$1" "$IMAGE" >/dev/null
}

if [ -r "$TARBALL" ]; then
  echo "[box-import] importing the pre-built box image as $IMAGE"
  import_box "$TARBALL"
elif docker image inspect "$IMAGE" >/dev/null 2>&1; then
  echo "[box-import] no pre-built box; keeping the loaded $IMAGE"
else
  echo "[box-import] no pre-built box — building it from /opt/box (needs network)"
  docker build -q -t "$IMAGE-build" /opt/box >/tmp/box-build.log 2>&1 || { tail -30 /tmp/box-build.log >&2; exit 1; }
  cid=$(docker create "$IMAGE-build")
  docker export "$cid" | import_box -
  docker rm "$cid" >/dev/null
  docker rmi "$IMAGE-build" >/dev/null || true
fi
# The image the tag pointed at before (an older box), if no box still uses it.
docker image prune --force >/dev/null 2>&1 || true
