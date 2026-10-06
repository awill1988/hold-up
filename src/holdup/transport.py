"""Authenticated, bounded loopback messages shared by all native clients."""

import hashlib
import hmac
import json
import os
import secrets
import socket
import struct
import subprocess
import time
from collections.abc import Mapping

from .data import freeze, immutable_result, json_value
from .locations import runtime_directory

VERSION = 1
MAX_FRAME = 16384  # 16 KiB
DEADLINE = 0.075
INSPECTION_DEADLINE = 2.0


def signature(value, secret):
    content = json.dumps(
        value, sort_keys=True, separators=(",", ":"), allow_nan=False, default=json_value
    ).encode()
    return hmac.new(secret.encode(), content, hashlib.sha256).hexdigest()


def authenticate(value, secret):
    supplied = value.get("signature", "")
    unsigned = {key: item for key, item in value.items() if key != "signature"}
    return isinstance(supplied, str) and hmac.compare_digest(supplied, signature(unsigned, secret))


def lock_owner(root):
    root = runtime_directory(root)
    private_directory(root)
    stream = (root / "owner.lock").open("a+b")
    try:
        if os.name == "nt":
            import msvcrt

            if stream.seek(0, 2) == 0:
                stream.write(b"0")
                stream.flush()
            stream.seek(0)
            msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl

            fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return stream
    except OSError:
        stream.close()
        raise ValueError("socket_owner_already_running") from None


def private_directory(root):
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    if root.is_symlink():
        raise ValueError("invalid state directory")
    if os.name == "nt":
        identity = subprocess.run(
            ["whoami", "/user", "/fo", "csv", "/nh"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout
        import csv

        sid = next(csv.reader([identity.strip()]))[1]
        subprocess.run(
            ["icacls", str(root), "/inheritance:r", "/grant:r", f"*{sid}:(OI)(CI)F"],
            check=True,
            capture_output=True,
        )
    else:
        os.chmod(root, 0o700)


@immutable_result
def publish_endpoint(root, port):
    root = runtime_directory(root)
    private_directory(root)
    endpoint = {"version": VERSION, "port": port, "secret": secrets.token_hex(32)}
    temporary = root / ("endpoint-" + secrets.token_hex(8))
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        json.dump(endpoint, stream)
    temporary.replace(root / "endpoint.json")
    return endpoint


@immutable_result
def receive(sock, deadline):
    def exact(size):
        result = bytearray()
        while len(result) < size:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("socket_deadline")
            sock.settimeout(remaining)
            block = sock.recv(size - len(result))
            if not block:
                raise ValueError("socket_disconnected")
            result.extend(block)
        return bytes(result)

    size = struct.unpack("!I", exact(4))[0]
    if not 0 < size <= MAX_FRAME:
        raise ValueError("socket_frame_invalid")
    value = json.loads(exact(size))
    if not isinstance(value, Mapping):
        raise ValueError("socket_frame_invalid")
    return value


def send(sock, value, deadline):
    content = json.dumps(value, separators=(",", ":"), allow_nan=False, default=json_value).encode()
    if len(content) > MAX_FRAME:
        raise ValueError("socket_frame_oversized")
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("socket_deadline")
    sock.settimeout(remaining)
    sock.sendall(struct.pack("!I", len(content)) + content)


@immutable_result
def request(root, message):
    budget = INSPECTION_DEADLINE if message.get("event") in ("stats", "status") else DEADLINE
    deadline = time.monotonic() + budget
    path = runtime_directory(root) / "endpoint.json"
    if path.is_symlink() or path.stat().st_size > 1024:
        raise ValueError("socket_endpoint_invalid")
    endpoint = freeze(json.loads(path.read_text(encoding="utf-8")))
    if endpoint.get("version") != VERSION or type(endpoint.get("port")) is not int:
        raise ValueError("socket_endpoint_invalid")
    with socket.create_connection(("127.0.0.1", endpoint["port"]), timeout=DEADLINE) as sock:
        nonce = secrets.token_hex(16)
        value = {**message, "version": VERSION, "nonce": nonce}
        send(sock, {**value, "signature": signature(value, endpoint["secret"])}, deadline)
        reply = receive(sock, deadline)
    if (
        not authenticate(reply, endpoint["secret"])
        or reply.get("nonce") != nonce
        or reply.get("version") != VERSION
        or "error" in reply
    ):
        raise ValueError("socket_response_invalid")
    return {key: item for key, item in reply.items() if key not in ("nonce", "signature")}
