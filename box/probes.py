"""Containment probes, run INSIDE a box by the phase-6 spike (spike/gate.py)
through the runner's own code path, so the box has exactly the production flags
and mounts (/conversation/input read-only, /conversation/output read-write).

Prints one line per check, ``<VERDICT> <gate item> <name> — <detail>``, where
VERDICT is PASS, FAIL or ACCEPTED (a documented, accepted exception), then
``PROBES DONE``. The gate counts a check as passed only when its PASS line is
printed, so a box that never started (or crashed) fails every check instead of
passing them.

    python3 probes.py [--targets host:port,...] [--names name,...]

``--targets`` are extra TCP endpoints that must be unreachable (the runner's
own API, the inner daemon); ``--names`` are hostnames that must not resolve.
"""
import argparse
import ctypes
import errno
import os
import platform
import shutil
import socket
import stat
import subprocess
import time

OUTPUT = "/conversation/output"
INPUT = "/conversation/input"
# The only writable places a box has: its scratch tmpfs, the runtime's
# /dev/shm tmpfs and its own output dir.
ALLOWED_WRITABLE = {"/tmp", "/dev/shm", OUTPUT}
# The runner's allowlist, HOSTNAME (Docker's, fixed to "sandbox") and what the
# box's own `sh -c` sets (PWD, SHLVL, _).
ALLOWED_ENV = {"PATH", "HOME", "LANG", "HOSTNAME", "PWD", "SHLVL", "_"}
ALLOWED_MOUNT_PREFIXES = ("/sys/fs/cgroup/",)
ALLOWED_MOUNTS = {
    "/", "/dev", "/dev/shm", "/dev/pts", "/dev/mqueue", "/tmp", "/sys", "/sys/fs/cgroup", "/proc",
    "/etc/hosts", "/etc/hostname", "/etc/resolv.conf", INPUT, OUTPUT,
}
# Paths of the runner container and the hosts around it; none may exist here.
HOST_PATHS = (
    "/app", "/app/tls/tls.key", "/app/secrets", "/opt/magenticx", "/opt/sandbox", "/var/lib/sandbox-runner",
    "/var/lib/docker", "/etc/docker", "/opt/box-rootfs.tar.gz", "/opt/venv", "/usr/local/bin/runsc",
)
DOCKER_SOCKETS = (
    "/var/run/docker.sock", "/run/docker.sock", "/run/containerd/containerd.sock",
    "/run/docker/containerd/containerd.sock",
)
INTERNET = (("1.1.1.1", 443), ("1.1.1.1", 53), ("8.8.8.8", 53), ("8.8.8.8", 443), ("140.82.112.3", 443))

CLONE_NEWNS = 0x00020000
CLONE_NEWUTS = 0x04000000
CLONE_NEWIPC = 0x08000000
CLONE_NEWUSER = 0x10000000
CLONE_NEWPID = 0x20000000
CLONE_NEWNET = 0x40000000
PTRACE_ATTACH = 16
# (init_module, finit_module) per architecture.
MODULE_SYSCALLS = {"x86_64": (175, 313), "aarch64": (105, 273)}

libc = ctypes.CDLL(None, use_errno=True)
results: list[tuple[str, int, str, str]] = []


def check(item, name):
    def wrap(fn):
        try:
            verdict, detail = fn()
            if verdict is True:
                verdict = "PASS"
            elif verdict is False:
                verdict = "FAIL"
        except Exception as exc:  # a probe that crashes is a failure, never a pass
            verdict, detail = "FAIL", f"probe error: {exc!r}"
        results.append((verdict, item, name, " ".join(str(detail).split())[:300]))
        return fn
    return wrap


def errname(code):
    return errno.errorcode.get(code, str(code))


def in_child(fn):
    """Run ``fn`` in a forked child (so a namespace change cannot leak into the
    other probes); returns the child's exit status (0 = fn returned True)."""
    pid = os.fork()
    if pid == 0:
        try:
            os._exit(0 if fn() else 1)
        except BaseException:
            os._exit(2)
    _, status = os.waitpid(pid, 0)
    return os.waitstatus_to_exitcode(status)


def try_write(path):
    try:
        with open(path, "w") as fh:
            fh.write("1")
        return "written"
    except OSError as exc:
        return errname(exc.errno)


def run_binary_from(directory):
    """Copy /bin/true into ``directory``, chmod +x, run it. (ran, how)."""
    target = os.path.join(directory, f"true-{os.getpid()}")
    with open("/bin/true", "rb") as src, open(target, "wb") as dst:
        dst.write(src.read())
    os.chmod(target, 0o755)
    try:
        subprocess.run([target], check=True, timeout=10)
        return True, "ran"
    except (PermissionError, OSError, subprocess.CalledProcessError) as exc:
        return False, type(exc).__name__
    finally:
        os.unlink(target)


def fill(directory, limit):
    """Write 1 MiB chunks into ``directory`` until a write fails or ``limit``; (bytes, error)."""
    path = os.path.join(directory, f"fill-{os.getpid()}")
    chunk = b"\0" * (1024 * 1024)
    written, error = 0, "none"
    try:
        with open(path, "wb", buffering=0) as fh:
            while written < limit:
                try:
                    n = fh.write(chunk)
                except OSError as exc:
                    error = errname(exc.errno)
                    break
                written += n or 0
                if not n:
                    break
    except OSError as exc:
        error = errname(exc.errno)
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass
    return written, error


def mount_size(target):
    """The size= option of the tmpfs mounted at ``target`` (bytes), or None."""
    for line in open("/proc/self/mountinfo"):
        if line.split()[4] == target and "tmpfs" in line:
            for opt in line.split(" - ", 1)[1].split()[-1].split(","):
                if opt.startswith("size="):
                    v = opt[5:].lower()
                    mult = {"k": 1024, "m": 1024 ** 2, "g": 1024 ** 3}.get(v[-1], 1)
                    return int(v.rstrip("kmg")) * mult
    return None


def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("--targets", default="")
    p.add_argument("--names", default="")
    return p.parse_args()


ARGS = parse_args()
TARGETS = [(t.rsplit(":", 1)[0], int(t.rsplit(":", 1)[1])) for t in ARGS.targets.split(",") if t]
NAMES = [n for n in ARGS.names.split(",") if n]


# ---- 1. network ---------------------------------------------------------------
@check(1, "net-loopback-only")
def _interfaces():
    names = sorted(os.listdir("/sys/class/net")) if os.path.isdir("/sys/class/net") else []
    idx = sorted(n for _, n in socket.if_nameindex())
    return names in ([], ["lo"]) and idx in ([], ["lo"]), f"/sys/class/net={names} if_nameindex={idx}"


@check(1, "net-tcp-internet")
def _tcp_internet():
    for host, port in INTERNET:
        try:
            socket.create_connection((host, port), timeout=3).close()
            return False, f"connected to {host}:{port}"
        except OSError:
            pass
    return True, f"{len(INTERNET)} internet endpoints unreachable"


@check(1, "net-tcp-internal")
def _tcp_internal():
    # The runner's own API and the inner daemon (from the gate), plus the box's
    # own loopback on the runner's port and the dockerd TCP ports.
    targets = TARGETS + [("127.0.0.1", 8090), ("127.0.0.1", 2375), ("127.0.0.1", 2376)]
    for host, port in targets:
        try:
            socket.create_connection((host, port), timeout=3).close()
            return False, f"connected to {host}:{port}"
        except OSError:
            pass
    return True, "unreachable: " + ", ".join(f"{h}:{p}" for h, p in targets)


@check(1, "net-udp")
def _udp():
    query = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01"
    last = None
    for host in ("1.1.1.1", "8.8.8.8"):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(2)
        try:
            s.sendto(query, (host, 53))
            s.recvfrom(512)
            return False, f"UDP answer from {host}:53"
        except OSError as exc:
            last = exc
        finally:
            s.close()
    return True, f"no UDP path ({last!r})"


@check(1, "net-dns")
def _dns():
    names = ["example.com", "github.com", *NAMES]
    for name in names:
        try:
            addrs = socket.getaddrinfo(name, 443)
            return False, f"resolved {name} -> {addrs[0][4]}"
        except OSError:
            pass
    return True, f"no name resolves ({', '.join(names)})"


@check(1, "net-icmp")
def _icmp():
    echo = b"\x08\x00\xf7\xff\x00\x00\x00\x00"
    notes = []
    for kind in (socket.SOCK_DGRAM, socket.SOCK_RAW):
        try:
            s = socket.socket(socket.AF_INET, kind, socket.IPPROTO_ICMP)
        except OSError as exc:
            notes.append(f"{kind.name}: socket {errname(exc.errno)}")
            continue
        s.settimeout(2)
        try:
            s.sendto(echo, ("1.1.1.1", 0))
            s.recvfrom(512)
            return False, f"ICMP echo answered ({kind.name})"
        except OSError as exc:
            notes.append(f"{kind.name}: {errname(exc.errno) if exc.errno else 'timeout'}")
        finally:
            s.close()
    return True, "; ".join(notes)


# ---- 2. host filesystem -------------------------------------------------------
@check(2, "fs-shadow-unreadable")
def _shadow():
    try:
        open("/etc/shadow").read()
        return False, "read /etc/shadow"
    except OSError as exc:
        return True, errname(exc.errno)


@check(2, "fs-proc1-environ-clean")
def _environ():
    try:
        raw = open("/proc/1/environ", "rb").read()
    except OSError as exc:
        return True, f"unreadable ({errname(exc.errno)})"
    keys = {kv.split(b"=", 1)[0].decode(errors="replace") for kv in raw.split(b"\0") if kv}
    return keys <= ALLOWED_ENV, f"pid 1 is the box's own sh; env keys={sorted(keys)}"


@check(2, "fs-env-allowlist")
def _env():
    keys = set(os.environ)
    return keys <= ALLOWED_ENV, f"env keys={sorted(keys)}"


@check(2, "fs-docker-socket-absent")
def _sockets():
    present = [p for p in DOCKER_SOCKETS if os.path.lexists(p)]
    return not present, f"present={present}" if present else "no docker/containerd socket"


@check(2, "fs-host-paths-absent")
def _host_paths():
    present = [p for p in HOST_PATHS if os.path.lexists(p)]
    return not present, f"present={present}" if present else f"{len(HOST_PATHS)} runner/host paths absent"


@check(2, "fs-mount-refused")
def _mount():
    os.makedirs("/tmp/mnt-probe", exist_ok=True)
    if libc.mount(b"none", b"/tmp/mnt-probe", b"tmpfs", 0, None) == 0:
        return False, "mounted a tmpfs"
    return True, errname(ctypes.get_errno())


@check(2, "fs-mounts-expected")
def _mounts():
    points, bad = [], []
    for line in open("/proc/self/mountinfo"):
        point, source = line.split()[4], line.split(" - ", 1)[1].split()[1]
        points.append(point)
        if point not in ALLOWED_MOUNTS and not point.startswith(ALLOWED_MOUNT_PREFIXES):
            bad.append(point)
        if source.startswith("/") or "/var/lib" in line:
            bad.append(f"{point} from {source}")
    return not bad, f"unexpected={bad}" if bad else f"{len(points)} mounts, none from a host path"


@check(2, "fs-writable-only-expected")
def _writable():
    candidates = sorted(ALLOWED_WRITABLE | {
        "/", "/etc", "/usr", "/usr/local/bin", "/var", "/var/tmp", "/root", "/home", "/opt", "/run", "/srv",
        "/mnt", "/media", "/conversation", INPUT, "/proc", "/sys", "/sys/fs/cgroup", "/dev",
    })
    writable = []
    for d in candidates:
        if not os.path.isdir(d):
            continue
        path = os.path.join(d, f".w-{os.getpid()}")
        try:
            open(path, "w").close()
            os.unlink(path)
            writable.append(d)
        except OSError:
            pass
    extra = sorted(set(writable) - ALLOWED_WRITABLE)
    return not extra, f"writable={writable}"


@check(2, "fs-rootfs-read-only")
def _rootfs():
    result = try_write("/etc/escape")
    return result != "written", f"/etc/escape: {result}"


@check(2, "fs-input-read-only")
def _input():
    result = try_write(os.path.join(INPUT, "escape"))
    return result != "written", f"input/escape: {result}"


# ---- 3. /proc and the kernel surface ------------------------------------------
@check(3, "proc-sys-write-refused")
def _proc_sys():
    paths = ("/proc/sys/kernel/hostname", "/proc/sys/vm/drop_caches", "/proc/sys/kernel/core_pattern",
             "/proc/sys/net/ipv4/ip_forward")
    got = {p: try_write(p) for p in paths}
    return "written" not in got.values(), str(got)


@check(3, "proc-sysrq-trigger-refused")
def _sysrq():
    result = try_write("/proc/sysrq-trigger")
    return result != "written", f"/proc/sysrq-trigger: {result}"


@check(3, "proc-kcore-unreadable")
def _kcore():
    got = {}
    for p in ("/proc/kcore", "/dev/mem", "/dev/kmem", "/dev/kmsg"):
        try:
            open(p, "rb").read(64)
            got[p] = "read"
        except OSError as exc:
            got[p] = errname(exc.errno)
    return "read" not in got.values(), str(got)


@check(3, "sys-cgroup-write-refused")
def _cgroup():
    got = {}
    for p in ("/sys/fs/cgroup/cgroup.procs", "/sys/fs/cgroup/memory/memory.limit_in_bytes",
              "/sys/fs/cgroup/pids/pids.max", "/sys/fs/cgroup/memory.max"):
        if os.path.exists(p):
            got[p] = try_write(p)
    try:
        os.mkdir("/sys/fs/cgroup/escape")
        got["mkdir"] = "written"
    except OSError as exc:
        got["mkdir"] = errname(exc.errno)
    return "written" not in got.values(), str(got)


@check(3, "kernel-unshare-refused")
def _unshare():
    got = {}
    for label, flag in (("user", CLONE_NEWUSER), ("mnt", CLONE_NEWNS), ("net", CLONE_NEWNET),
                        ("pid", CLONE_NEWPID), ("uts", CLONE_NEWUTS), ("ipc", CLONE_NEWIPC)):
        got[label] = "ALLOWED" if in_child(lambda f=flag: libc.unshare(f) == 0) == 0 else "refused"
    return "ALLOWED" not in got.values(), str(got)


@check(3, "kernel-mount-in-userns-refused")
def _userns_mount():
    # The classic route around a refused mount: a new user namespace (full caps
    # inside it), then a mount namespace, then a fresh tmpfs without noexec.
    def attempt():
        os.makedirs("/tmp/userns-mnt", exist_ok=True)
        return (libc.unshare(CLONE_NEWUSER) == 0 and libc.unshare(CLONE_NEWNS) == 0
                and libc.mount(b"none", b"/tmp/userns-mnt", b"tmpfs", 0, None) == 0)
    if in_child(attempt) == 0:
        return False, "user ns -> mount ns -> tmpfs: MOUNTED"
    return True, "user ns -> mount ns -> tmpfs: refused"


@check(3, "kernel-ptrace-outside-refused")
def _ptrace():
    pids = sorted(int(p) for p in os.listdir("/proc") if p.isdigit())
    owners = set()
    for p in pids:
        try:
            owners.add(os.stat(f"/proc/{p}").st_uid)
        except OSError:
            pass
    # pid 1 is the box's `sh`, not this process's child: attaching needs CAP_SYS_PTRACE.
    r1 = libc.ptrace(PTRACE_ATTACH, 1, None, None)
    e1 = errname(ctypes.get_errno())
    # Nothing outside the box is addressable at all.
    far = [p for p in (2, 100, 1000, 4242, 31337) if p not in pids]
    reach = [p for p in far if libc.ptrace(PTRACE_ATTACH, p, None, None) == 0 or ctypes.get_errno() != errno.ESRCH]
    ok = r1 != 0 and not reach and owners <= {os.getuid()} and len(pids) < 16
    return ok, (f"visible pids={pids} owners={sorted(owners)}; attach pid 1: {e1}; "
                f"pids outside the box: {'unaddressable (ESRCH)' if not reach else reach}")


@check(3, "kernel-module-load-refused")
def _modules():
    nums = MODULE_SYSCALLS.get(platform.machine())
    if nums is None:
        return False, f"unknown arch {platform.machine()}"
    got = {}
    for label, num, args in (("init_module", nums[0], (None, 0, b"")), ("finit_module", nums[1], (-1, b"", 0))):
        got[label] = "LOADED" if libc.syscall(num, *args) == 0 else errname(ctypes.get_errno())
    return "LOADED" not in got.values(), str(got)


@check(3, "proc-no-host-detail")
def _proc_detail():
    version = open("/proc/version").read().strip()
    mountinfo = open("/proc/self/mountinfo").read()
    leaks = [w for w in ("/var/lib/docker", "/var/lib/sandbox-runner", "overlay2", "/opt/") if w in mountinfo]
    host = socket.gethostname()
    ok = "gvisor" in version.lower() and not leaks and host == "sandbox"
    return ok, f"/proc/version={version[:40]}; hostname={host}; host paths in mountinfo={leaks}"


# ---- 5. disk fill (inside the box; output/ is exercised by the gate) --------------
@check(5, "disk-tmp-bounded")
def _tmp_fill():
    size = mount_size("/tmp")
    written, error = fill("/tmp", 512 * 1024 * 1024)
    ok = size is not None and written <= size and error in ("ENOSPC", "EFBIG")
    return ok, f"/tmp tmpfs size={size}; wrote {written} bytes, then {error}"


@check(5, "disk-shm-bounded")
def _shm_fill():
    size = mount_size("/dev/shm")
    written, error = fill("/dev/shm", 512 * 1024 * 1024)
    ok = size is not None and written <= size and error in ("ENOSPC", "EFBIG")
    return ok, f"/dev/shm tmpfs size={size}; wrote {written} bytes, then {error}"


# ---- 8. privilege -------------------------------------------------------------
@check(8, "priv-non-root")
def _user():
    ids = (os.getuid(), os.geteuid(), os.getgid(), os.getegid())
    return 0 not in ids and 0 not in os.getgroups(), f"uid/euid/gid/egid={ids} groups={os.getgroups()}"


@check(8, "priv-no-capabilities")
def _caps():
    status = dict(line.split(":\t", 1) for line in open("/proc/self/status").read().splitlines() if ":\t" in line)
    caps = {k: status.get(k, "?").strip() for k in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb")}
    return all(set(v) == {"0"} for v in caps.values()), str(caps)


@check(8, "priv-no-new-privs")
def _nnp():
    status = open("/proc/self/status").read()
    lines = [line.replace("\t", " ") for line in status.splitlines() if line.startswith(("NoNewPrivs", "Seccomp:"))]
    return "NoNewPrivs:\t1" in status, "; ".join(lines)


@check(8, "priv-sudo-absent")
def _sudo():
    found = {b: shutil.which(b) for b in ("sudo", "doas", "pkexec", "run0") if shutil.which(b)}
    return not found, f"present={found}" if found else "no sudo/doas/pkexec/run0"


@check(8, "priv-su-refused")
def _su():
    su = shutil.which("su")
    if su is None:
        return True, "su absent"
    r = subprocess.run([su, "-c", "id -u", "root"], input="\n", capture_output=True, text=True, timeout=20)
    return r.returncode != 0 and r.stdout.strip() != "0", f"su exit {r.returncode}: {r.stderr.strip()[:80]}"


def _setuid_root_binaries():
    found = set()
    for d in ("/usr/bin", "/bin", "/usr/sbin", "/sbin"):
        if not os.path.isdir(d):
            continue
        for name in os.listdir(d):
            p = os.path.realpath(os.path.join(d, name))
            try:
                st = os.stat(p)
            except OSError:
                continue
            if stat.S_ISREG(st.st_mode) and st.st_mode & stat.S_ISUID and st.st_uid == 0:
                found.add(p)
    return sorted(found)


@check(8, "priv-setuid-not-honored")
def _setuid():
    # A setuid-root binary, caught while it waits for a password: under
    # no-new-privileges its effective uid stays the box's.
    binaries = _setuid_root_binaries()
    su = next((b for b in binaries if os.path.basename(b) == "su"), None)
    if su is None:
        return True, f"no setuid-root su to try; setuid-root binaries: {binaries}"
    proc = subprocess.Popen([su, "-c", "true", "root"], stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL)
    uid_line = None
    try:
        for _ in range(60):
            try:
                if open(f"/proc/{proc.pid}/comm").read().strip() == "su":
                    for line in open(f"/proc/{proc.pid}/status"):
                        if line.startswith("Uid:"):
                            uid_line = line.split()[1:]
                    break
            except OSError:
                pass
            time.sleep(0.05)
    finally:
        proc.kill()
        proc.wait()
    if not uid_line:
        return False, "could not read the setuid process's status"
    return "0" not in uid_line, (f"{su} (setuid root) ran as real/effective/saved/fs uid={uid_line}; "
                                 f"{len(binaries)} setuid-root binaries on the rootfs")


@check(8, "priv-tmp-noexec")
def _tmp_noexec():
    ran, how = run_binary_from("/tmp")
    return not ran, f"binary copied into /tmp: {how}"


@check(8, "priv-shm-noexec")
def _shm_noexec():
    ran, how = run_binary_from("/dev/shm")
    return not ran, f"binary copied into /dev/shm: {how}"


@check(8, "priv-output-noexec")
def _output_noexec():
    ran, how = run_binary_from(OUTPUT)
    if not ran:
        return "PASS", f"binary copied into output/: {how}"
    # Documented, accepted exception (magenticx docs/flows/sandboxed-execution.md).
    return "ACCEPTED", ("gVisor ignores noexec on the bind mounts, so a binary in output/ runs. Accepted: sh and "
                        "python already run anything in the box; the boundary is gVisor, no network and the "
                        "limits, not exec bits (noexec holds on /tmp and /dev/shm)")


# ---- 9. persistence -----------------------------------------------------------
@check(9, "persist-no-scheduler")
def _cron():
    found = {b: shutil.which(b) for b in ("crontab", "cron", "crond", "at", "atd", "systemctl", "systemd-run")
             if shutil.which(b)}
    return not found, f"present={found}" if found else "no cron/at/systemd"


# ---- 10. runtime confirmation ---------------------------------------------------
@check(10, "gvisor-kernel")
def _gvisor():
    release = os.uname().release
    version = open("/proc/version").read().strip()
    buf = ctypes.create_string_buffer(16384)
    n = libc.klogctl(3, buf, len(buf))
    klog = "gvisor" in buf.raw[: max(n, 0)].decode(errors="replace").lower()
    return "gvisor" in release.lower() and "gvisor" in version.lower(), (
        f"uname -r={release}; /proc/version={version[:40]}; kernel log: {'gVisor' if klog else 'refused'}")


for verdict, item, name, detail in results:
    print(f"{verdict} {item} {name} — {detail}")
print("PROBES DONE")
