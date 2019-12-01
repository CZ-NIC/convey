# This file should not anything that is not vitally needed. (Import config would take us 10 ms, do not do it.)
import struct

# XX I suppose this will not work on Win. What other paths should I use instead?
# Importing default package tempdir would cost another 7 ms which is a lot.
socket_file = "/tmp/convey_socket"


def daemon_pid():
    import subprocess
    return subprocess.run(["lsof", "-t", socket_file], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL).stdout.strip()


def send(pipe, msg):
    d = msg.encode("utf-8")
    msg = struct.pack('>I', len(d)) + d
    try:
        pipe.sendall(msg)
    except BrokenPipeError:
        return False
    return True


def recv(pipe):
    def recv(n):
        # Helper function to recv n bytes or return None if EOF is hit
        data = b''
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
    return recv(struct.unpack('>I', raw_msglen)[0]).decode("utf-8")
