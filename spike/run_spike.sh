#!/bin/sh
# Plan 11 phase 6: the escape-test gate, run inside the sandbox_runner image.
# Two modes, picked automatically:
#
#   fresh     a new container (CI, local). Starts its own inner dockerd and
#             loads the box image exactly as the entrypoint does:
#               docker run --rm --privileged -v "$PWD/results:/results" <image> /opt/spike/run_spike.sh
#   attached  inside the RUNNING runner (Dennis), whose dockerd is already up:
#               sudo docker exec sandbox_runner /opt/spike/run_spike.sh
#             Starts nothing, reuses the runner's loaded box image, and touches
#             only its own boxes (removed by name) and its own dirs under
#             $SPIKE_WORK — never the runner's boxes or call dirs.
#
# The checks themselves are spike/gate.py: every box is started by the runner's
# own code (utils.exec_service.execute), as uid 1000 like uvicorn, so flags,
# mounts, limits and cleanup are production's. It also times the file-making
# workload under runc and runsc. Writes $SPIKE_RESULTS/summary.md (default
# /results), prints it, and exits non-zero if any check fails.
set -u
# The docker:dind base image points the CLI at tcp://docker:2375 (its sidecar
# setup); the inner daemon listens on the socket.
export DOCKER_HOST=unix:///var/run/docker.sock

RESULTS="${SPIKE_RESULTS:-/results}"
WORK="${SPIKE_WORK:-/var/lib/sandbox-runner/spike}"
IMAGE="${SANDBOX_IMAGE:-sandbox-box:local}"
PY=/opt/venv/bin/python
mkdir -p "$RESULTS"
SUMMARY="$RESULTS/summary.md"

say() { echo "$*" >> "$SUMMARY"; }
fail() { say ""; say "**Result: the gate could not run — $*.**"; cat "$SUMMARY"; exit 1; }

: > "$SUMMARY"
say "# Sandbox spike — $(uname -m)"
say ""
say "| Host fact | Value |"
say "| --- | --- |"
say "| Architecture | $(uname -m) |"
say "| Kernel | $(uname -r) |"
if [ -e /dev/kvm ]; then say "| /dev/kvm | present |"; else say "| /dev/kvm | **absent** (as on Dennis) |"; fi
say "| CPUs | $(nproc) |"
say "| runsc | $(runsc --version 2>/dev/null | head -1) |"
say "| Image | ${APP_VERSION:-dev} |"

# ---- the inner daemon ------------------------------------------------------
if docker info >/dev/null 2>&1; then
  MODE=attached
  docker image inspect "$IMAGE" >/dev/null 2>&1 || fail "the running daemon has no $IMAGE"
else
  MODE=fresh
  # As the entrypoint: through docker:dind's `dind` wrapper (nested cgroup v2),
  # socket group `runner` so the gate can drive it as uid 1000.
  rm -f /var/run/docker.pid /var/run/docker.sock
  dind dockerd --host=unix:///var/run/docker.sock --group=runner >/var/log/spike-dockerd.log 2>&1 &
  i=0
  until docker info >/dev/null 2>&1; do
    i=$((i + 1))
    if [ "$i" -gt 60 ]; then tail -30 /var/log/spike-dockerd.log >> "$SUMMARY"; fail "the inner dockerd did not start"; fi
    sleep 1
  done
  sandbox-box-import "$IMAGE" >/dev/null 2>/var/log/spike-box-import.log || fail "the box image could not be loaded"
fi
say "| Mode | $MODE |"
say "| Inner runtimes | $(docker info --format '{{range $k, $v := .Runtimes}}{{$k}} {{end}}') |"
say ""

# ---- the gate --------------------------------------------------------------
# Its own work dir (calls root, canary), 0700 and owned by uid 1000 like the
# runner's calls root; wiped before and after.
case "$WORK" in
  /*/*/*) ;;
  *) fail "SPIKE_WORK=$WORK is too shallow to be wiped" ;;
esac
rm -rf "$WORK"
mkdir -p "$WORK"
chown 1000:1000 "$WORK"
chmod 0700 "$WORK"

SPIKE_WORK="$WORK" su-exec runner:runner "$PY" /opt/spike/gate.py >"$WORK.md" 2>"$WORK.log"
status=$?
cat "$WORK.md" >> "$SUMMARY"
if [ "$status" -ne 0 ] && ! grep -q '^\*\*Gate:' "$WORK.md"; then
  say ""; say "gate.py exited $status without a verdict:"; say '```'; tail -30 "$WORK.log" >> "$SUMMARY"; say '```'
fi
cp "$WORK.log" "$RESULTS/gate.log" 2>/dev/null || true
rm -rf "$WORK" "$WORK.md" "$WORK.log"

say ""
if [ "$status" -eq 0 ]; then say "**Result: every check passed.**"; else say "**Result: at least one check FAILED.**"; fi
cat "$SUMMARY"
exit "$status"
