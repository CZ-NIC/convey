# This file should not do anything that is not vitally needed to stay fast. (Import config would take us 10 ms, do not do it.)
import os
import struct

# The daemon socket must live in a directory only the current user can read/write. A fixed path in
# the world-writable /tmp (the former `/tmp/convey_socket`) let any local user squat the path to
# capture every convey invocation's argv or feed back spoofed output, and — under a permissive
# umask — connect to a running daemon and run arbitrary convey commands as us. We prefer the
# per-user XDG_RUNTIME_DIR (already mode 0700); otherwise a 0700 fallback directory we own under /tmp.
# `os` is imported by the interpreter at startup, so this stays cheap. (Win has no getuid(); the
# daemon was POSIX-only before as well.)
_uid = getattr(os, "getuid", lambda: None)()


def _runtime_dir():
    runtime = os.environ.get("XDG_RUNTIME_DIR")
    if runtime and os.path.isdir(runtime):
        return runtime, False  # managed by the system, already per-user 0700
    name = f"convey-{_uid}" if _uid is not None else "convey"
    return (
        os.path.join("/tmp", name),
        True,
    )  # our private fallback we must create & guard


socket_dir, _own_dir = _runtime_dir()
socket_file = os.path.join(socket_dir, "convey.sock")


def ensure_socket_dir():
    """Make sure the socket directory exists and is private to the current user.
    Returns False if it exists but is not safely owned (refuse to use the daemon then).
    """
    if _own_dir and not os.path.isdir(socket_dir):
        try:
            os.makedirs(socket_dir, mode=0o700, exist_ok=True)
        except OSError:
            return False  # e.g. a foreign file already squats the path
    if _uid is None:
        return True  # platforms without uid semantics (Windows)
    try:
        st = os.stat(socket_dir)
    except OSError:
        return False
    if st.st_uid != _uid:
        return False  # someone else owns this directory - do not trust it
    if _own_dir and (st.st_mode & 0o077):
        os.chmod(socket_dir, st.st_mode & ~0o077)
    return True


def socket_is_ours(path=socket_file):
    """Guard against socket squatting: only trust a socket file owned by the current user."""
    if _uid is None:
        return True
    try:
        return os.stat(path).st_uid == _uid
    except OSError:
        return False


def daemon_pid():
    import subprocess

    return subprocess.run(
        ["lsof", "-t", socket_file], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL
    ).stdout.strip()


def send(pipe, msg):
    d = msg.encode("utf-8")
    msg = struct.pack(">I", len(d)) + d
    try:
        pipe.sendall(msg)
    except BrokenPipeError:
        return False
    return True


def recv(pipe):
    def recv(n):
        # Helper function to recv n bytes or return None if EOF is hit
        data = b""
        while len(data) < n:
            packet = pipe.recv(n - len(data))
            if not packet:
                return None
            data += packet
        return data

    raw_msglen = recv(4)
    if not raw_msglen:
        pipe.close()
        return False
    return recv(struct.unpack(">I", raw_msglen)[0]).decode("utf-8")
