#!/usr/bin/env python3
"""Bounded server regression tests; run with ~/venv/bin/python.

CF_SERVER selects a compiled server. CF_TEST_TMP selects the artifact directory.
No real clients, external network, or production sockets are used.
"""
import ctypes
import os
from pathlib import Path
import select
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import time
import unittest


class Header(ctypes.Structure):
    _fields_ = [("type", ctypes.c_int8), ("id", ctypes.c_uint32), ("length", ctypes.c_int16)]


def frame(kind, operation=0, payload=b"", v2=False):
    header = struct.pack("!4sBBHII", b"CTF2", 2, kind, 0, operation, len(payload)) if v2 else bytes(Header(kind, operation, len(payload)))
    return header + payload


class Server:
    def __init__(self, v2=False, directory=None, cn="review", extra=()):
        self.temp = tempfile.TemporaryDirectory(prefix="cf-test-", dir=os.environ.get("CF_TEST_TMP")) if directory is None else None
        self.directory = Path(self.temp.name if self.temp else directory)
        self.path = self.directory / cn
        self.v2 = v2
        args = [os.environ["CF_SERVER"], "-p", str(self.directory), "--protocol", "v2" if v2 else "legacy", *extra]
        self.process = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                        env=dict(os.environ, SSL_CLIENT_DN="/CN=" + cn, ASAN_OPTIONS="detect_leaks=1:abort_on_error=1"))
        deadline = time.monotonic() + 3
        while not self.path.exists() and self.process.poll() is None and time.monotonic() < deadline:
            time.sleep(0.005)

    def connect(self):
        sock = socket.socket(socket.AF_UNIX)
        sock.settimeout(2)
        sock.connect(str(self.path))
        return sock

    def command(self, text):
        with self.connect() as sock:
            sock.sendall(text.encode() + b"\n")
            return self.response(sock)

    @staticmethod
    def response(sock):
        data = bytearray()
        while chunk := sock.recv(4096):
            data.extend(chunk)
        return data.decode()

    def send(self, data):
        self.process.stdin.write(data)
        self.process.stdin.flush()

    def read_exact(self, size):
        data = bytearray()
        while len(data) < size:
            if not select.select([self.process.stdout], [], [], 3)[0]:
                raise TimeoutError("server produced no frame")
            chunk = os.read(self.process.stdout.fileno(), size - len(data))
            if not chunk:
                raise EOFError("server exited")
            data.extend(chunk)
        return bytes(data)

    def receive(self):
        if self.v2:
            magic, version, kind, flags, operation, size = struct.unpack("!4sBBHII", self.read_exact(16))
            assert (magic, version, flags) == (b"CTF2", 2, 0)
        else:
            header = Header.from_buffer_copy(self.read_exact(ctypes.sizeof(Header)))
            kind, operation, size = header.type, header.id, header.length
        return kind, operation, self.read_exact(size)

    def close(self):
        if self.process.poll() is None:
            self.process.terminate()
        try:
            _, errors = self.process.communicate(timeout=3)
        except subprocess.TimeoutExpired:
            self.process.kill()
            _, errors = self.process.communicate()
            raise AssertionError("server did not shut down")
        finally:
            if self.temp:
                self.temp.cleanup()
        if self.process.returncode not in (0, 2) or b"runtime error:" in errors or b"AddressSanitizer" in errors:
            raise AssertionError(errors.decode(errors="replace"))


class RegressionTests(unittest.TestCase):
    def server(self, **kwargs):
        server = Server(**kwargs)
        self.addCleanup(server.close)
        return server

    def test_control_bounds_and_missing_arguments(self):
        s = self.server()
        for command in ["CONNECT 0", "CONNECT", "EXEC 0", "FILE 0", "CONNECT 0 host 99999", "EXEC -1 x", "EXEC 65536 x", "EXECUTE 0 x", "X" * 1036]:
            self.assertIn("ERROR", s.command(command))
            self.assertIn("LAST_PING", s.command("STATUS"))

    def test_idle_and_fragmented_controllers(self):
        s = self.server()
        with s.connect() as idle, s.connect() as fragmented:
            fragmented.sendall(b"STA")
            self.assertIn("LAST_PING", s.command("STATUS"))
            fragmented.sendall(b"TUS\n")
            self.assertIn("LAST_PING", s.response(fragmented))
            idle.sendall(b"STATUS ")
            self.assertIn("LAST_PING", s.response(idle))

    def test_legacy_trailing_space_and_admin_commands(self):
        s = self.server()
        with s.connect() as sock:
            sock.sendall(b"EXEC 0 cmd /c echo hello ")
            self.assertIn("SUCCESS", s.response(sock))
        self.assertEqual(s.receive()[0], 5)
        self.assertIn("LOCAL_PORT=", s.command("LIST"))
        self.assertIn("LOG SENT", s.command("LOG 1"))
        self.assertEqual(s.receive(), (9, 0, b"1\0"))
        self.assertIn("CLOSING", s.command("CLOSE"))
        s.process.wait(timeout=2)

    def test_malformed_frames_terminate_without_memory_errors(self):
        for data in [bytes(Header(4, 1, 2048)), bytes(Header(4, 1, -1)), bytes(Header(99, 1, 0)), frame(1, payload=b"x")]:
            with self.subTest(data=data):
                s = self.server()
                s.send(data)
                s.process.wait(timeout=2)

    def test_bytewise_and_coalesced_frames(self):
        s = self.server(v2=True)
        for byte in frame(1, v2=True):
            s.send(bytes([byte]))
        s.send(frame(1, v2=True) * 20)
        self.assertIn("PROTOCOL=v2", s.command("STATUS"))

    def test_v2_rejects_legacy_and_unknown_flags(self):
        for data in [frame(1) + b"\0" * 4, struct.pack("!4sBBHII", b"CTF2", 2, 1, 1, 0, 0)]:
            s = self.server(v2=True)
            s.send(data)
            s.process.wait(timeout=2)

    def test_fast_legacy_download_is_retained(self):
        s = self.server()
        response = s.command("FILE 0 C:\\test.txt").split()
        kind, operation, _ = s.receive()
        self.assertEqual(kind, 7)
        s.send(frame(4, operation, b"hello") + frame(3, operation))
        time.sleep(0.05)
        with socket.create_connection(("127.0.0.1", int(response[-1])), timeout=2) as data:
            self.assertEqual(data.recv(10), b"hello")
            self.assertEqual(data.recv(10), b"")

    def test_owner_only_v2_socket_result_and_credit(self):
        s = self.server(v2=True)
        self.assertEqual(stat.S_IMODE(s.path.stat().st_mode), 0o600)
        response = s.command("GET 0 C:\\test.txt").split()
        operation, path = int(response[2]), response[3]
        self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)
        self.assertEqual(s.receive()[0], 10)
        s.send(frame(4, operation, b"hello", True) + frame(13, operation, b"OK\0", True) + frame(3, operation, v2=True))
        with socket.socket(socket.AF_UNIX) as data:
            data.settimeout(2)
            data.connect(path)
            self.assertEqual(data.recv(10), b"hello")
            self.assertEqual(data.recv(10), b"")
        self.assertEqual(s.receive(), (14, operation, struct.pack("!I", 5)))
        self.assertEqual(s.command(f"RESULT {operation}"), "OK\n")

    def test_credit_violation_and_bad_compression(self):
        for violation in ["credit", "compression"]:
            s = self.server(v2=True)
            operation = int(s.command("GET 0 C:\\test.txt").split()[2])
            s.receive()
            data = frame(6, operation, b"not zlib", True) if violation == "compression" else frame(14, operation, struct.pack("!I", 1), True)
            s.send(data)
            s.process.wait(timeout=2)

    def test_duplicate_cn_does_not_replace_owner(self):
        first = self.server()
        inode = first.path.stat().st_ino
        second = self.server(directory=first.directory)
        self.assertEqual(second.process.wait(timeout=2), 2)
        self.assertEqual(first.path.stat().st_ino, inode)
        self.assertIn("LAST_PING", first.command("STATUS"))

    def test_operation_limit_leaves_control_responsive(self):
        s = self.server(v2=True)
        for _ in range(64):
            self.assertIn("SUCCESS", s.command("CONNECT 0 localhost 1"))
        self.assertIn("OPERATION LIMIT", s.command("CONNECT 0 localhost 1"))
        self.assertEqual(len(s.command("LIST").splitlines()), 64)
        self.assertIn("LAST_PING", s.command("STATUS"))

    def test_permission_and_long_identity_rejection(self):
        with tempfile.TemporaryDirectory(prefix="cf-test-", dir=os.environ.get("CF_TEST_TMP")) as directory:
            os.chmod(directory, 0o755)
            s = self.server(directory=directory)
            self.assertEqual(s.process.wait(timeout=2), 2)
        s = self.server(cn="x" * 100)
        self.assertEqual(s.process.wait(timeout=2), 2)

    def test_unwritable_log_does_not_crash(self):
        s = self.server(extra=("-l", "/nonexistent-cuttlefish-log"))
        self.assertIn("CLOSING", s.command("CLOSE"))
        self.assertEqual(s.process.wait(timeout=2), 0)

    def test_legacy_unflagged_payload(self):
        s = self.server(extra=("-z",))
        self.assertIn("SUCCESS", s.command("EXEC 0 cmd /c echo hello"))
        self.assertEqual(s.receive()[2], b"cmd /c echo hello\0")

    def helper(self, *args):
        process = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        def cleanup():
            if process.poll() is None:
                process.kill()
            process.communicate()
        self.addCleanup(cleanup)
        return process

    def test_python_helper_empty_put_and_get(self):
        s = self.server(v2=True)
        local = s.directory / "empty.txt"
        local.write_bytes(b"")
        script = str(Path(__file__).resolve().parent / "bin" / "cfctl")
        process = self.helper(sys.executable, script, str(s.path), "put", str(local), "C:\\empty.txt")
        kind, operation, payload = s.receive()
        self.assertEqual(kind, 11)
        self.assertTrue(payload.startswith(b"\0" + b"0 e3b0c442"))
        self.assertEqual(s.receive(), (12, operation, b""))
        s.send(frame(13, operation, b"OK\0", True) + frame(3, operation, v2=True))
        output, errors = process.communicate(timeout=3)
        self.assertEqual(process.returncode, 0, errors)
        self.assertEqual(output, b"")
        process = self.helper(sys.executable, script, str(s.path), "get", "C:\\empty.txt")
        kind, operation, _ = s.receive()
        self.assertEqual(kind, 10)
        self.assertEqual(s.receive(), (12, operation, b""))
        s.send(frame(4, operation, b"content", True) + frame(13, operation, b"OK\0", True) + frame(3, operation, v2=True))
        output, errors = process.communicate(timeout=3)
        self.assertEqual(process.returncode, 0, errors)
        self.assertEqual(output, b"content")

    def test_perl_empty_upload_uses_put(self):
        with tempfile.TemporaryDirectory(prefix="cf-perl-", dir=os.environ.get("CF_TEST_TMP")) as base:
            directory = Path(base) / "pipes"
            directory.mkdir(mode=0o700)
            s = Server(v2=True, directory=directory)
            try:
                module_dir = str(Path(__file__).resolve().parent / "perl" / "lib")
                process = self.helper("perl", "-I" + module_dir, "-Mcf", "-e",
                    '$cmf::CF_BASE=shift; print cf::cmd_file("review", "C:\\\\empty.txt", "");', base)
                kind, operation, payload = s.receive()
                self.assertEqual(kind, 11)
                self.assertTrue(payload.startswith(b"\0" + b"0 e3b0c442"))
                self.assertEqual(s.receive(), (12, operation, b""))
                s.send(frame(13, operation, b"OK\0", True) + frame(3, operation, v2=True))
                output, errors = process.communicate(timeout=3)
                self.assertEqual(process.returncode, 0, errors)
                self.assertEqual(output, b"1")
            finally:
                s.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
