"""Plan 11 phase 6 — the escape-test gate, run against the image that ships.

Started by ``run_spike.sh`` as uid 1000 (the runner's own uid) inside the
runner image, beside a running inner daemon. Every box here is started by the
runner's OWN code (``utils.exec_service.execute`` / ``utils.runner``), so the
flags, mounts, limits, watchdogs, output collection and call-dir cleanup under
test are exactly production's — nothing is re-typed. Only three things differ
from a live runner, all outside the code under test:

* a random in-process internal-caller secret (there is no HTTP hop: mTLS and
  the secret check are uvicorn's / the router's and are unit-tested);
* its own calls root (``$SPIKE_WORK/calls``), so a run beside a live runner
  never touches the runner's call dirs;
* two observation hooks: the container names and call dirs each call used, and
  its audit record (for ``bytes_written``) — so the gate can prove a box and a
  dir are gone at return. Nothing is swept by label: a live runner's own boxes
  are never touched.

Prints the gate as Markdown on stdout (logs go to stderr); exits 1 if any check
FAILs. A check is PASS, FAIL, or ACCEPTED (a documented, accepted exception).
"""
import os
import secrets
import sys

SPIKE_WORK = os.environ.get("SPIKE_WORK", "/var/lib/sandbox-runner/spike")
APP_DIR = os.environ.get("SPIKE_APP_DIR", "/app")
# Before the runner's settings are imported: they are read at import time.
os.environ["TRUSTED_PROXY_SECRET"] = secrets.token_hex(32)
os.environ.pop("TRUSTED_PROXY_SECRET_FILE", None)
os.environ["SANDBOX_CALLS_ROOT"] = os.path.join(SPIKE_WORK, "calls")
sys.path.insert(0, APP_DIR)

import asyncio  # noqa: E402
import base64  # noqa: E402
import json  # noqa: E402
import shutil  # noqa: E402
import socket  # noqa: E402
import time  # noqa: E402
from dataclasses import dataclass  # noqa: E402
from pathlib import Path  # noqa: E402

from pydantic import ValidationError  # noqa: E402

import utils.exec_service as exec_service  # noqa: E402
import utils.runner as runner  # noqa: E402
from core.settings import settings  # noqa: E402
from schema import ExecRequest, ExecResponse, FileIn  # noqa: E402
from utils.docker_args import CONTAINER_LABEL  # noqa: E402
from utils.health import run_self_check  # noqa: E402
from utils.workspace import prepare_workspace, remove_workspace  # noqa: E402

CFG = settings.sandbox
CALLS_ROOT = CFG.calls_root
CANARY_DIR = Path(SPIKE_WORK) / "canary"
MIB = 1024 * 1024

# What each gate item must show (plan 11 §8, phase 6).
GATE = {
    1: ("Network", "every outbound attempt fails; no interface but loopback"),
    2: ("Host filesystem", "all refused; nothing outside the mounts and tmpfs is reachable"),
    3: ("/proc and kernel surface", "all refused; gVisor's /proc exposes no host detail"),
    4: ("Fork bomb", "dies at the pids cap; runner and host stay responsive; the call returns a clean failure"),
    5: ("Disk fill", "/tmp bounded by its tmpfs; output/ by the per-call budget; the call fails cleanly"),
    6: ("Symlink / hardlink out", "no read or write resolves outside the mounts; links are skipped and deleted as links"),
    7: ("Cross-tenant", "every attempt refused; identity never becomes a path"),
    8: ("Privilege", "non-root throughout; nosuid/no-new-privileges hold; noexec holds on /tmp"),
    9: ("Persistence", "the container is gone at return; nothing survives but the returned files"),
    10: ("Runtime confirmation", "the box's kernel is gVisor, and the check can tell gVisor from runc"),
}
# Every probe box/probes.py must report; a missing one is a FAIL.
EXPECTED_PROBES = {
    1: ["net-loopback-only", "net-tcp-internet", "net-tcp-internal", "net-udp", "net-dns", "net-icmp"],
    2: ["fs-shadow-unreadable", "fs-proc1-environ-clean", "fs-env-allowlist", "fs-docker-socket-absent",
        "fs-host-paths-absent", "fs-mount-refused", "fs-mounts-expected", "fs-writable-only-expected",
        "fs-rootfs-read-only", "fs-input-read-only"],
    3: ["proc-sys-write-refused", "proc-sysrq-trigger-refused", "proc-kcore-unreadable", "sys-cgroup-write-refused",
        "kernel-unshare-refused", "kernel-mount-in-userns-refused", "kernel-ptrace-outside-refused",
        "kernel-module-load-refused", "proc-no-host-detail"],
    5: ["disk-tmp-bounded", "disk-shm-bounded"],
    8: ["priv-non-root", "priv-no-capabilities", "priv-no-new-privs", "priv-sudo-absent", "priv-su-refused",
        "priv-setuid-not-honored", "priv-tmp-noexec", "priv-shm-noexec", "priv-output-noexec"],
    9: ["persist-no-scheduler"],
    10: ["gvisor-kernel"],
}
# Names a box might try for the estate's services.
ESTATE_NAMES = ["vectordb", "chat_postgres", "redis", "dialogue_bridge", "agents", "sandbox_runner",
                "host.docker.internal"]


@dataclass
class Check:
    item: int
    name: str
    verdict: str  # PASS / FAIL / ACCEPTED
    detail: str


CHECKS: list[Check] = []


def record(item: int, name: str, verdict, detail: str) -> None:
    if verdict is True:
        verdict = "PASS"
    elif verdict is False:
        verdict = "FAIL"
    CHECKS.append(Check(item, name, verdict, " ".join(str(detail).split())))


# ---- observation hooks (names, call dirs, audit records) -----------------------
BOXES: list[str] = []
WORKSPACES: list[Path] = []
AUDITS: list[dict] = []
_new_container_name = runner.new_container_name
_prepare_workspace = exec_service.prepare_workspace
_audit_exec = exec_service.audit_exec


def _tracked_name() -> str:
    name = _new_container_name()
    BOXES.append(name)
    return name


def _tracked_workspace(*args, **kwargs):
    ws = _prepare_workspace(*args, **kwargs)
    WORKSPACES.append(ws.call_dir)
    return ws


def _tracked_audit(*args, **kwargs) -> None:
    AUDITS.append(dict(kwargs))
    _audit_exec(*args, **kwargs)


runner.new_container_name = _tracked_name
exec_service.prepare_workspace = _tracked_workspace
exec_service.audit_exec = _tracked_audit


# ---- helpers --------------------------------------------------------------------
def b64(data: str | bytes) -> str:
    return base64.b64encode(data.encode() if isinstance(data, str) else data).decode()


def request(command: str, *, files: dict[str, str] | None = None, timeout: int = 60,
            user: str = "spike-user", conversation: str = "spike-conv") -> ExecRequest:
    return ExecRequest(
        user_id=user, agent_slug="spike", conversation_id=conversation, command=command,
        timeout_seconds=timeout,
        files=[FileIn(path=p, content_b64=b64(c)) for p, c in (files or {}).items()],
    )


async def run(req: ExecRequest) -> tuple[ExecResponse | None, str, Path | None, dict, str]:
    """One call through the runner's code: (response or None, box name, call dir, audit, error)."""
    n_boxes, n_ws, n_audits = len(BOXES), len(WORKSPACES), len(AUDITS)
    started = time.monotonic()
    try:
        resp, error = await exec_service.execute(req), ""
    except Exception as exc:  # noqa: BLE001 — recorded as the check's failure
        resp, error = None, f"{type(exc).__name__}: {exc}"
    box = BOXES[n_boxes] if len(BOXES) > n_boxes else ""
    ws = WORKSPACES[n_ws] if len(WORKSPACES) > n_ws else None
    audit = AUDITS[n_audits] if len(AUDITS) > n_audits else {}
    audit["_wall"] = round(time.monotonic() - started, 1)
    return resp, box, ws, audit, error


async def docker(*args: str, timeout: float = 30) -> tuple[int, str]:
    code, out, err = await runner.docker_cli(CFG, *args, timeout=timeout)
    return code, (out or err).decode(errors="replace").strip()


async def box_gone(name: str) -> bool:
    """No container and no mount volume of this box is left in the daemon."""
    if not name:
        return False
    _, ps = await docker("ps", "--all", "--quiet", f"--filter=name=^/{name}$")
    _, vols = await docker("volume", "ls", "--quiet", f"--filter=name={name}")
    return not ps and not vols


def summary(resp: ExecResponse | None, error: str = "") -> str:
    if resp is None:
        return f"no response ({error})"
    tail = (resp.stdout + resp.stderr).strip().replace("\n", " / ")[-160:]
    return f"exit={resp.exit_code} killed={resp.killed_reason} {resp.duration_ms} ms; output: {tail!r}"


def dir_snapshot(path: Path) -> dict[str, str]:
    return {str(p.relative_to(path)): p.read_text() for p in sorted(path.rglob("*")) if p.is_file()}


async def own_addresses() -> list[str]:
    addrs = set()
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            addrs.add(info[4][0])
    except OSError:
        pass
    code, out = await docker("network", "inspect", "bridge", "--format",
                             "{{range .IPAM.Config}}{{.Gateway}} {{end}}")
    if code == 0:
        addrs.update(a for a in out.split() if a)
    return sorted(a for a in addrs if not a.startswith("127."))


# ---- 10. runtime confirmation ----------------------------------------------------
async def gate_runtime() -> None:
    code, out = await docker("info", "--format", "{{json .Runtimes}}")
    try:
        runtimes = json.loads(out) if code == 0 else {}
    except ValueError:
        runtimes = {}
    rt = runtimes.get(CFG.runtime) or {}
    args = rt.get("runtimeArgs") or []
    record(10, "daemon-runtime", CFG.runtime == "runsc" and "runsc" in str(rt.get("path", "")) and
           "--oci-seccomp" in args,
           f"runner runtime={CFG.runtime}; daemon: path={rt.get('path')} args={args}")

    verdict = await run_self_check(CFG)
    record(10, "runner-self-check", verdict.ok, f"the runner's /health check (runsc box): {verdict.reason}")

    # Negative control: the same check, same flags, under runc must say NOT gVisor.
    control = await run_self_check(CFG.model_copy(update={"runtime": "runc"}))
    record(10, "negative-control-runc", (not control.ok) and control.reason == "not_gvisor",
           f"same check under runc: {control.reason} (it can tell the two apart)")


# ---- the in-box probes (items 1, 2, 3, 5, 8, 9, 10) -------------------------------
async def gate_probes() -> None:
    addrs = await own_addresses()
    targets = [f"{a}:{p}" for a in addrs for p in (8090, 2375, 2376)]
    cmd = f"python3 /opt/probes.py --targets {','.join(targets)} --names {','.join(ESTATE_NAMES)}"
    resp, box, _, _, error = await run(request(cmd, files={"input/data.txt": "input data"}, timeout=180))
    out = resp.stdout if resp else ""
    seen: dict[str, tuple[str, int, str]] = {}
    for line in out.splitlines():
        parts = line.split(" ", 3)
        if len(parts) == 4 and parts[0] in ("PASS", "FAIL", "ACCEPTED") and parts[1].isdigit():
            seen[parts[2]] = (parts[0], int(parts[1]), parts[3].removeprefix("— "))
    if "PROBES DONE" not in out:
        record(10, "probe-box-ran", False, summary(resp, error))
    for item, names in EXPECTED_PROBES.items():
        for name in names:
            verdict, _, detail = seen.get(name, ("FAIL", item, "no verdict printed"))
            record(item, name, verdict, detail)
    record(9, "probe-box-removed", await box_gone(box), f"{box or '?'} and its volumes gone at return")


# ---- 4. fork bomb, thread bomb, memory ---------------------------------------------
FORK_BOMB = """python3 -c '
import os, time
print("STARTED", flush=True)
n = 0
while True:
    try:
        if os.fork() == 0:
            time.sleep(60)
            os._exit(0)
        n += 1
    except OSError:
        print("CAPPED", n, flush=True)
        time.sleep(2)
        os._exit(0)
'"""
THREAD_BOMB = """python3 -c '
import threading, time
print("STARTED", flush=True)
n = 0
while True:
    try:
        threading.Thread(target=time.sleep, args=(60,), daemon=True).start()
        n += 1
    except (RuntimeError, OSError, MemoryError):
        print("CAPPED", n, flush=True)
        break
'"""
SHELL_BOMB = "echo STARTED; bomb() { bomb | bomb & }; bomb; sleep 20; echo SURVIVED"
MEMORY_HOG = """python3 -c '
print("STARTED", flush=True)
b = bytearray(2 * 1024 ** 3)
b[::4096] = b"x" * len(b[::4096])
print("ALLOCATED", flush=True)
'"""


async def responsive() -> tuple[bool, str]:
    resp, box, _, _, error = await run(request("echo alive", timeout=30))
    health = await run_self_check(CFG)
    code, _ = await docker("info", "--format", "{{.ServerVersion}}")
    ok = resp is not None and resp.exit_code == 0 and resp.stdout.strip() == "alive" and health.ok and code == 0
    return ok and await box_gone(box), f"next call: {summary(resp, error)}; self-check {health.reason}; daemon {'up' if code == 0 else 'DOWN'}"


async def gate_bombs() -> None:
    timeout = 60
    for name, cmd in (("fork-bomb", FORK_BOMB), ("thread-bomb", THREAD_BOMB), ("shell-fork-bomb", SHELL_BOMB)):
        resp, box, _, _, error = await run(request(cmd, timeout=timeout))
        gone = await box_gone(box)
        ok = (resp is not None and "STARTED" in resp.stdout and resp.killed_reason != "timeout" and gone
              and ("CAPPED" in resp.stdout or "SURVIVED" in resp.stdout or resp.exit_code != 0 or resp.killed_reason))
        how = "capped" if resp and "CAPPED" in resp.stdout else (
            "contained" if resp and "SURVIVED" in resp.stdout else "sandbox killed")
        record(4, name, ok, f"{how}: {summary(resp, error)}; box gone={gone}")
        alive, detail = await responsive()
        record(4, f"{name}-runner-responsive", alive, detail)

    resp, box, _, _, error = await run(request(MEMORY_HOG, timeout=timeout))
    ok = resp is not None and "STARTED" in resp.stdout and "ALLOCATED" not in resp.stdout and await box_gone(box)
    record(4, "memory-hog", ok, f"2 GiB under --memory={CFG.memory}: {summary(resp, error)}")


# ---- 5. disk fill through output/ ---------------------------------------------------
OUTPUT_FILL = """python3 -c '
import os
print("STARTED", flush=True)
chunk = b"\\0" * (4 * 1024 * 1024)
n = 0
try:
    while True:
        with open(f"/conversation/output/fill-{n}", "wb") as fh:
            for _ in range(16):
                fh.write(chunk)
        n += 1
except OSError as exc:
    print("STOPPED", exc.errno, n, flush=True)
'"""
FILE_SIZE = """python3 -c '
import errno
written = 0
try:
    with open("/conversation/output/big", "wb", buffering=0) as fh:
        for _ in range(150):
            written += fh.write(b"\\0" * (1024 * 1024))
    print("WROTE", written)
except OSError as exc:
    print("STOPPED", errno.errorcode.get(exc.errno), written)
'"""


async def gate_disk() -> None:
    free_before = shutil.disk_usage(CALLS_ROOT).free
    resp, box, ws, audit, error = await run(request(OUTPUT_FILL, timeout=120))
    written = audit.get("bytes_written")
    ok = (resp is not None and resp.killed_reason == "disk_limit" and ws is not None and not ws.exists()
          and await box_gone(box))
    over = f"{(written - CFG.disk_budget_bytes) / MIB:.0f} MiB past the budget" if isinstance(written, int) else "?"
    record(5, "disk-output-budget", ok,
           f"budget {CFG.disk_budget_bytes // MIB} MiB (polled every {CFG.disk_poll_seconds:g}s): "
           f"{summary(resp, error)}; out/ peaked at {written} bytes ({over}); call dir removed={ws is not None and not ws.exists()}")

    resp, box, ws, _, error = await run(request(FILE_SIZE, timeout=60))
    out = resp.stdout.strip() if resp else ""
    last = out.split()[-1] if out else ""
    ok = resp is not None and "STOPPED EFBIG" in out and last.isdigit() and int(last) <= CFG.fsize_bytes
    record(5, "disk-file-size-cap", ok, f"one 150 MiB file under RLIMIT_FSIZE={CFG.fsize_bytes // MIB} MiB: {out.strip()}")

    free_after = shutil.disk_usage(CALLS_ROOT).free
    leftovers = sorted(p.name for p in CALLS_ROOT.iterdir())
    drift = (free_before - free_after) / MIB
    record(5, "disk-host-volume", not leftovers and drift < 64,
           f"calls root empty={not leftovers}; free space before/after: {free_before // MIB} / {free_after // MIB} MiB")


# ---- 6. symlinks and hardlinks out of output/ ----------------------------------------
async def gate_links() -> None:
    token = "CANARY-" + secrets.token_hex(12)
    shutil.rmtree(CANARY_DIR, ignore_errors=True)
    CANARY_DIR.mkdir(parents=True)
    canary = CANARY_DIR / "secret.txt"
    canary.write_text(token)
    before = dir_snapshot(CANARY_DIR)
    calls = CALLS_ROOT
    cmd = f"""cd /conversation/output
ln -s / root; ln -s ../../../../../.. up; ln -s /etc/shadow shadow; ln -s /conversation/input in
ln -s {canary} canary; ln -s {CANARY_DIR} canarydir; ln -s {calls} calls
mkdir sub; ln -s ../../../../../../.. sub/up; ln -s {CANARY_DIR} sub/canarydir
ln /conversation/input/data.txt hard-in 2>/dev/null && echo HARD_IN_CREATED || echo HARD_IN_REFUSED
ln /etc/passwd hard-etc 2>/dev/null && echo HARD_ETC_CREATED || echo HARD_ETC_REFUSED
ln keep.txt hard-keep 2>/dev/null && echo HARD_KEEP_CREATED
cat canary canarydir/secret.txt sub/canarydir/secret.txt up{canary} root{canary} ../../..{canary} {canary} 2>/dev/null
ls calls/ canarydir/ 2>/dev/null
echo pwned > canary 2>/dev/null && echo WROTE_LINK || echo WRITE_LINK_REFUSED
echo pwned > canarydir/secret.txt 2>/dev/null && echo WROTE_DIR_LINK || echo WRITE_DIR_LINK_REFUSED
echo pwned > {canary} 2>/dev/null && echo WROTE_ABSOLUTE || echo WRITE_ABSOLUTE_REFUSED
echo pwned > ../../..{canary} 2>/dev/null && echo WROTE_DOTDOT || echo WRITE_DOTDOT_REFUSED
echo regular > regular.txt
true"""
    resp, box, ws, _, error = await run(request(
        cmd, files={"input/data.txt": "input data", "output/keep.txt": "keep"}, timeout=60))
    out = (resp.stdout + resp.stderr) if resp else ""
    returned = sorted(f.path for f in resp.files) if resp else []
    contents = b"".join(base64.b64decode(f.content_b64) for f in resp.files) if resp else b""

    record(6, "links-read-no-escape", resp is not None and token not in out and token.encode() not in contents,
           f"read through links to /, ../.., an absolute host path and the calls root: canary never seen; {summary(resp, error)}")
    writes_refused = all(w in out for w in ("WRITE_LINK_REFUSED", "WRITE_DIR_LINK_REFUSED",
                                            "WRITE_ABSOLUTE_REFUSED", "WRITE_DOTDOT_REFUSED"))
    record(6, "links-write-no-escape", resp is not None and writes_refused and dir_snapshot(CANARY_DIR) == before,
           f"writes through links / absolute / .. refused in the box={writes_refused}; host canary unchanged={dir_snapshot(CANARY_DIR) == before}")
    # hard-keep is a hardlink to keep.txt inside output/: a regular file, fine to return.
    allowed = {"output/regular.txt", "output/hard-keep"}
    links = {"root", "up", "shadow", "in", "canary", "canarydir", "calls", "sub/up", "sub/canarydir"}
    record(6, "collection-skips-links",
           resp is not None and "output/regular.txt" in returned and set(returned) <= allowed,
           f"returned={returned} (the {len(links)} links skipped, unchanged keep.txt not returned)")
    hard = [w for w in ("HARD_IN_REFUSED", "HARD_ETC_REFUSED") if w in out]
    record(6, "hardlinks-stay-inside", len(hard) == 2,
           f"hardlink output/→input/: {'refused' if 'HARD_IN_REFUSED' in out else 'CREATED'}; "
           f"output/→rootfs: {'refused' if 'HARD_ETC_REFUSED' in out else 'CREATED'} (cross-mount); within output/: a regular file")
    record(6, "cleanup-deletes-links-not-targets",
           ws is not None and not ws.exists() and canary.read_text() == token and await box_gone(box),
           f"call dir removed={ws is not None and not ws.exists()}; canary file + dir intact={canary.read_text() == token}")

    bad_paths = ["output/../../etc/passwd", "../output/x", "/etc/passwd", "input/../output/x", "output//x",
                 "output/./x", "output/a\\..\\b", "conversation/output/x", "output/" + "a/" * 5 + "x"]
    refused = []
    for path in bad_paths:
        try:
            FileIn(path=path, content_b64=b64("x"))
        except ValidationError:
            refused.append(path)
    record(6, "request-path-traversal-refused", refused == bad_paths,
           f"{len(refused)}/{len(bad_paths)} traversal / absolute / over-deep file paths refused by the request schema")


# ---- 7. cross-tenant ---------------------------------------------------------------
async def wait_running(n_boxes: int, timeout: float = 30) -> str:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if len(BOXES) > n_boxes:
            name = BOXES[n_boxes]
            code, out = await docker("inspect", "--format", "{{.State.Running}}", name)
            if code == 0 and out == "true":
                return name
        await asyncio.sleep(0.2)
    return ""


async def gate_tenants() -> None:
    ta, ta_in = "TENANT-A-" + secrets.token_hex(12), "TENANT-A-IN-" + secrets.token_hex(12)
    a_cmd = f"ls -A /conversation/output; echo {ta} > /conversation/output/a-secret.txt; sleep 6; echo A_DONE"
    a_req = request(a_cmd, files={"input/a.txt": ta_in}, user="tenant-a", conversation="conv-a", timeout=60)

    n_boxes, n_ws = len(BOXES), len(WORKSPACES)
    a_task = asyncio.ensure_future(run(a_req))
    a_box = await wait_running(n_boxes)
    a_dir = WORKSPACES[n_ws] if len(WORKSPACES) > n_ws else None

    # The deployed box config, read from the daemon while A runs (item 10).
    code, cfg_json = await docker("inspect", "--format", "{{json .HostConfig}}", a_box) if a_box else (1, "")
    try:
        hc = json.loads(cfg_json) if code == 0 else {}
    except ValueError:
        hc = {}
    flags_ok = (hc.get("Runtime") == "runsc" and hc.get("NetworkMode") == "none" and hc.get("ReadonlyRootfs") is True
                and "ALL" in (hc.get("CapDrop") or []) and "no-new-privileges" in (hc.get("SecurityOpt") or [])
                and (hc.get("PidsLimit") or 0) > 0 and (hc.get("Memory") or 0) > 0)
    record(10, "box-config-as-deployed", flags_ok,
           f"runtime={hc.get('Runtime')} network={hc.get('NetworkMode')} read-only={hc.get('ReadonlyRootfs')} "
           f"cap-drop={hc.get('CapDrop')} security-opt={hc.get('SecurityOpt')} pids={hc.get('PidsLimit')} "
           f"memory={hc.get('Memory')} tmpfs={hc.get('Tmpfs')}")

    a_path = str(a_dir) if a_dir else "/var/lib/sandbox-runner/calls/unknown"
    b_cmd = f"""ls -A /conversation/output; echo ---
for p in {a_path}/out/a-secret.txt {a_path}/in/a.txt {a_path} {CALLS_ROOT}; do
  cat "$p" 2>/dev/null && echo "READ $p"; ls "$p" >/dev/null 2>&1 && echo "LISTED $p"
done
ln -s {a_path}/out /conversation/output/leak 2>/dev/null; cat /conversation/output/leak/a-secret.txt 2>/dev/null
find / \\( -path /proc -o -path /sys \\) -prune -o \\( -name 'a-secret*' -o -name a.txt \\) -print 2>/dev/null
echo B_DONE"""
    b_resp, b_box, b_dir, _, b_error = await run(
        request(b_cmd, user="tenant-b", conversation="conv-b", timeout=60))
    a_resp, _, _, _, a_error = await a_task

    b_out = (b_resp.stdout + b_resp.stderr) if b_resp else ""
    b_files = b"".join(base64.b64decode(f.content_b64) for f in b_resp.files) if b_resp else b""
    a_files = {f.path: base64.b64decode(f.content_b64).decode(errors="replace") for f in a_resp.files} if a_resp else {}
    # Positive control: A's secret existed (and came back to A) while B looked for it.
    a_ok = a_resp is not None and ta in a_files.get("output/a-secret.txt", "")
    b_saw = [w for w in (ta, ta_in, "READ /", "a-secret") if w in b_out or w.encode() in b_files]
    b_listed = [line for line in b_out.splitlines() if line.startswith("LISTED ")]
    record(7, "concurrent-call-isolated",
           a_ok and b_resp is not None and "B_DONE" in b_out and not b_saw and not b_listed,
           f"B ran while A held a secret (A got it back={a_ok}); B saw nothing of A: leaked={b_saw} "
           f"listed={[x[7:] for x in b_listed]}; {summary(b_resp, b_error)}")
    record(7, "call-dirs-wiped",
           a_dir is not None and not a_dir.exists() and b_dir is not None and not b_dir.exists()
           and not any(CALLS_ROOT.iterdir()),
           f"A's and B's call dirs removed at return; calls root empty={not any(CALLS_ROOT.iterdir())}")

    # The same identity again, and A's captured request replayed verbatim: each
    # gets a new, empty workspace — nothing of A's run carries over.
    c_resp, _, c_dir, _, c_error = await run(request(
        "ls -A /conversation/output /tmp; find / \\( -path /proc -o -path /sys \\) -prune -o -name 'a-secret*' -print 2>/dev/null; echo C_DONE",
        user="tenant-a", conversation="conv-a", timeout=60))
    r_resp, _, r_dir, _, r_error = await run(a_req)
    c_clean = c_resp is not None and "C_DONE" in c_resp.stdout and "a-secret" not in c_resp.stdout + c_resp.stderr
    # A's command starts with `ls -A output/`: in a fresh workspace it prints nothing.
    r_fresh = r_resp is not None and r_resp.stdout.strip() == "A_DONE"
    r_clean = r_fresh and r_dir not in (None, a_dir)
    record(7, "same-identity-no-carryover", c_clean, f"a new call as tenant-a/conv-a sees an empty output/ and /tmp: {summary(c_resp, c_error)}")
    record(7, "replayed-request-fresh", r_clean,
           f"A's request replayed: new call dir={r_dir not in (None, a_dir)}, output/ empty at start={r_fresh}; {summary(r_resp, r_error)}")

    forged = [("user_id", "../tenant-b"), ("user_id", "/etc"), ("conversation_id", "conv-a/../conv-b"),
              ("conversation_id", "."), ("agent_slug", "../../x"), ("user_id", "tenant a"), ("conversation_id", "")]
    refused = []
    for field, value in forged:
        body = {"user_id": "u", "agent_slug": "a", "conversation_id": "c", "command": "true", field: value}
        try:
            ExecRequest(**body)
        except ValidationError:
            refused.append(f"{field}={value!r}")
    dirs = [p.name for p in WORKSPACES]
    path_free = all(len(n) == 32 and all(c in "0123456789abcdef" for c in n) for n in dirs)
    record(7, "forged-identity-refused", len(refused) == len(forged) and path_free,
           f"{len(refused)}/{len(forged)} forged ids refused by the schema; every call dir is a random uuid "
           f"({len(dirs)} calls), never derived from user/conversation ids")


# ---- 9. persistence ------------------------------------------------------------------
PERSIST = ("sleep 300 & nohup sh -c 'while :; do date >> /conversation/output/beat; sleep 1; done' "
           ">/dev/null 2>&1 & echo marker > /tmp/persist; echo marker > /dev/shm/persist; echo STARTED")


async def gate_persistence() -> None:
    resp, box, ws, _, error = await run(request(PERSIST, timeout=60))
    fast = resp is not None and resp.killed_reason is None and resp.duration_ms < 20000
    gone = await box_gone(box)
    record(9, "background-process-killed", fast and gone and ws is not None and not ws.exists(),
           f"backgrounded sleep + writer loop: call returned in {resp.duration_ms if resp else '?'} ms "
           f"(not held to the timeout); box + volumes gone={gone}; call dir removed={ws is not None and not ws.exists()}")
    await asyncio.sleep(3)
    resp2, _, _, _, error2 = await run(request(
        "ls -A /tmp /dev/shm; cat /tmp/persist /dev/shm/persist 2>/dev/null; ls /proc | grep -c '^[0-9]'",
        timeout=60))
    out = resp2.stdout if resp2 else ""
    procs = out.strip().splitlines()[-1] if out.strip() else "?"
    record(9, "nothing-survives", resp2 is not None and "marker" not in out and "persist" not in out
           and procs.isdigit() and int(procs) <= 4,
           f"next call: no /tmp or /dev/shm marker, {procs} processes (its own); {summary(resp2, error2)}")


async def gate_all_boxes_removed() -> None:
    left = [b for b in BOXES if not await box_gone(b)]
    code, labelled = await docker("ps", "--all", "--quiet", f"--filter=label={CONTAINER_LABEL}")
    record(9, "every-box-removed", not left,
           f"{len(BOXES)} boxes started by the gate, {len(left)} left {left}; "
           f"labelled boxes now in the daemon: {len(labelled.split()) if code == 0 else '?'} (a live runner's own may be among them)")


# ---- workload: runsc vs runc ------------------------------------------------------------
async def workload() -> list[str]:
    lines = []
    for rt in ("runc", "runsc"):
        cfg = CFG.model_copy(update={"runtime": rt})
        ws = prepare_workspace(CALLS_ROOT, [])
        try:
            start = time.monotonic()
            outcome = await runner.run_command(cfg, workspace=ws, workdir="output",
                                               command="python3 /opt/workload.py /conversation/output",
                                               timeout_seconds=180)
            wall = time.monotonic() - start
        finally:
            remove_workspace(ws)
        r = outcome.response
        if r.exit_code == 0 and r.killed_reason is None:
            lines.append(f"- **{rt}**: {wall:.1f}s wall clock, in-script `{r.stdout.strip()}`")
        else:
            lines.append(f"- **{rt}**: FAILED ({summary(r)})")
            record(10, f"workload-{rt}", False, summary(r))
    return lines


def render(workload_lines: list[str]) -> str:
    out = ["## Phase-6 escape-test gate (plan 11 §8)", "",
           f"Runner code path: `utils.exec_service.execute` · runtime `{CFG.runtime}` · image `{CFG.image}` · "
           f"user `{CFG.user}` · memory `{CFG.memory}` · pids `{CFG.pids_limit}` · /tmp `{CFG.tmp_size}` · "
           f"disk budget {CFG.disk_budget_bytes // MIB} MiB · RLIMIT_FSIZE {CFG.fsize_bytes // MIB} MiB", ""]
    icon = {"PASS": "✅ pass", "FAIL": "❌ FAIL", "ACCEPTED": "⚠️ ACCEPTED-EXCEPTION"}
    for item, (title, criterion) in GATE.items():
        rows = [c for c in CHECKS if c.item == item]
        state = "FAIL" if any(c.verdict == "FAIL" for c in rows) or not rows else "PASS"
        out += [f"### {item}. {title} — {'✅' if state == 'PASS' else '❌'}", "", f"*Pass criterion:* {criterion}", "",
                "| Check | Result | Detail |", "| --- | --- | --- |"]
        out += [f"| {c.name} | {icon.get(c.verdict, c.verdict)} | {c.detail.replace('|', '/')} |" for c in rows]
        out.append("")
    counts = {v: sum(c.verdict == v for c in CHECKS) for v in ("PASS", "FAIL", "ACCEPTED")}
    out += ["## Workload: 100k-row CSV → pandas → xlsx, chart, docx, pptx, pdf (runner flags)", "", *workload_lines, ""]
    out.append(f"**Gate: {counts['PASS']} passed, {counts['FAIL']} failed, {counts['ACCEPTED']} accepted exception(s).**")
    return "\n".join(out)


async def main() -> int:
    CALLS_ROOT.mkdir(mode=0o700, parents=True, exist_ok=True)
    steps = ((10, gate_runtime), (10, gate_probes), (4, gate_bombs), (5, gate_disk), (6, gate_links),
             (7, gate_tenants), (9, gate_persistence))
    for item, step in steps:
        try:
            await step()
        except Exception as exc:  # noqa: BLE001 — a crashed step is a failed gate, never a silent pass
            record(item, f"{step.__name__}-crashed", False, f"{type(exc).__name__}: {exc}")
    try:
        lines = await workload()
    except Exception as exc:  # noqa: BLE001
        lines = [f"- workload crashed: {type(exc).__name__}: {exc}"]
        record(10, "workload-crashed", False, f"{type(exc).__name__}: {exc}")
    await gate_all_boxes_removed()
    print(render(lines))
    return 1 if any(c.verdict == "FAIL" for c in CHECKS) else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
