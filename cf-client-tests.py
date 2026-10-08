#!/usr/bin/env python3
"""Native Windows (or explicitly enabled Wine) TLS/worker regressions.

CF_CLIENT and CF_APRO select executables; CF_FIXTURE selects cf-test-child.exe.
CF_WINE optionally selects Wine. Use an isolated WINEPREFIX for Wine runs.
CF_TEST_TMP selects the directory for disposable certificates and test data.
"""
import contextlib
import hashlib
import os
from pathlib import Path
import socket
import ssl
import struct
import subprocess
import tempfile
import time
import unittest


def winpath(path):
    path = str(Path(path).resolve())
    return path.replace("/", "\\") if os.name == "nt" else "Z:" + path.replace("/", "\\")


def wire(kind, operation=0, data=b""):
    return struct.pack("!4sBBHII", b"CTF2", 2, kind, 0, operation, len(data)) + data


class Peer:
    def __init__(self, case, apro=False, certificate="server", connect=True):
        self.case = case
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(1)
        self.listener.settimeout(10)
        exe = os.environ["CF_APRO" if apro else "CF_CLIENT"]
        args = ([os.environ["CF_WINE"]] if "CF_WINE" in os.environ else []) + [exe, "-u", "127.0.0.1", "-p", str(self.listener.getsockname()[1]),
            "-w", winpath(case.directory), "-s", "server.crt", "-c", "client.pem", "--protocol", "v2", "--root", winpath(case.allowed)]
        self.process = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                                        env=dict(os.environ, WINEDEBUG="-all"))
        self.socket = None
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.minimum_version = ssl.TLSVersion.TLSv1_2
        self.context.load_cert_chain(str(case.directory / (certificate + ".crt")), str(case.directory / (certificate + ".key")))
        self.context.load_verify_locations(str(case.directory / "client.crt"))
        self.context.verify_mode = ssl.CERT_REQUIRED
        try:
            raw, _ = self.listener.accept()
            raw.settimeout(5)
            try:
                self.socket = self.context.wrap_socket(raw, server_side=True)
            except BaseException:
                raw.close()
                raise
        except BaseException:
            if connect:
                self.close()
                raise
        self.listener.close()

    def send(self, kind, operation=0, data=b""):
        self.socket.sendall(wire(kind, operation, data))

    def request(self, kind, operation, text):
        self.send(kind, operation, b"\0" + text.encode() + b"\0")

    def exact(self, length):
        data = bytearray()
        while len(data) < length:
            chunk = self.socket.recv(length - len(data))
            if not chunk:
                raise EOFError("client closed TLS")
            data.extend(chunk)
        return bytes(data)

    def receive(self):
        magic, version, kind, flags, operation, length = struct.unpack("!4sBBHII", self.exact(16))
        assert (magic, version, flags) == (b"CTF2", 2, 0)
        assert length <= 1024
        return kind, operation, self.exact(length)

    def collect(self, operation, credit=True):
        data = bytearray()
        result = None
        while True:
            kind, stream, payload = self.receive()
            if kind == 1:
                self.send(1)
                continue
            if stream != operation:
                raise AssertionError(f"unexpected stream {stream}")
            if kind in (4, 6):
                if kind == 6:
                    import zlib
                    payload = zlib.decompress(payload)
                data.extend(payload)
                if credit:
                    self.send(14, operation, struct.pack("!I", len(payload)))
            elif kind == 13:
                result = payload.rstrip(b"\0").decode()
            elif kind == 3:
                return bytes(data), result
            elif kind != 14:
                raise AssertionError(f"unexpected packet {kind}")

    def put(self, operation, path, data):
        self.request(11, operation, f"{len(data)} {hashlib.sha256(data).hexdigest()} {winpath(path)}")
        credit = 65536
        for offset in range(0, len(data), 1024):
            chunk = data[offset:offset + 1024]
            while credit < len(chunk):
                kind, stream, payload = self.receive()
                if kind != 14 or stream != operation:
                    raise AssertionError((kind, stream, payload))
                credit += struct.unpack("!I", payload)[0]
            self.send(4, operation, chunk)
            credit -= len(chunk)
        self.send(12, operation)
        return self.collect(operation)

    def close(self):
        if self.socket:
            self.socket.close()
        self.listener.close()
        try:
            _, errors = self.process.communicate(timeout=8)
        except subprocess.TimeoutExpired:
            self.process.kill()
            _, errors = self.process.communicate()
            raise AssertionError("client did not shut down: " + errors.decode(errors="replace"))


class ClientTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="cf-client-test-", dir=os.environ.get("CF_TEST_TMP"))
        cls.directory = Path(cls.temp.name)
        cls.allowed = cls.directory / "allowed"
        cls.allowed.mkdir()

        def openssl(*args):
            subprocess.run([os.environ.get("OPENSSL", "openssl"), *args], cwd=cls.directory,
                           check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)

        for name in ("server", "client", "unrelated"):
            openssl("req", "-new", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2", "-subj", "/CN=" + name,
                    "-keyout", name + ".key", "-out", name + ".crt")
        (cls.directory / "client.pem").write_bytes((cls.directory / "client.crt").read_bytes() + (cls.directory / "client.key").read_bytes())
        openssl("req", "-new", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=other", "-keyout", "other.key", "-out", "other.csr")
        openssl("x509", "-req", "-in", "other.csr", "-CA", "server.crt", "-CAkey", "server.key", "-set_serial", "2", "-days", "2", "-out", "other.crt")
        # A trusted-chain leaf with a different certificate must fail exact pinning.
        (cls.directory / "index").write_text("")
        (cls.directory / "serial").write_text("03\n")
        (cls.directory / "ca.conf").write_text("""[ca]
default_ca=local
[local]
database=index
serial=serial
new_certs_dir=.
certificate=server.crt
private_key=server.key
default_md=sha256
policy=names
[names]
commonName=supplied
""")
        openssl("ca", "-batch", "-config", "ca.conf", "-in", "other.csr", "-out", "expired.crt",
                "-startdate", "20100101000000Z", "-enddate", "20110101000000Z")
        (cls.directory / "expired.key").write_bytes((cls.directory / "other.key").read_bytes())

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    @contextlib.contextmanager
    def peer(self, **kwargs):
        peer = Peer(self, **kwargs)
        try:
            yield peer
        finally:
            peer.close()

    def test_untrusted_wrong_pin_and_expired_certificates(self):
        for certificate in ("unrelated", "other", "expired"):
            with self.subTest(certificate=certificate), self.peer(certificate=certificate, connect=False) as peer:
                if peer.socket:
                    with self.assertRaises((EOFError, OSError)):
                        peer.receive()
                self.assertEqual(peer.process.wait(timeout=5), 2)

    def test_transactional_put_get_and_empty_file(self):
        with self.peer() as peer:
            for operation, data in [(1, b""), (3, b"0123456789abcdef" * 10000)]:
                path = self.allowed / f"transfer-{operation}.txt"
                _, result = peer.put(operation, path, data)
                self.assertEqual(result, "OK")
                self.assertEqual(path.read_bytes(), data)
                peer.request(10, operation + 1, winpath(path))
                self.assertEqual(peer.collect(operation + 1), (data, "OK"))

    def test_interrupted_upload_is_removed_and_retry_stays_put(self):
        with self.peer() as peer:
            operation = 10
            for offset in (0, 1, 1024, 8192):
                path = self.allowed / f"retry-{offset}.txt"
                data = b"x" * 9000
                peer.request(11, operation, f"9000 {hashlib.sha256(data).hexdigest()} {winpath(path)}")
                for start in range(0, offset, 1024):
                    peer.send(4, operation, data[start:min(start + 1024, offset)])
                peer.send(15, operation)
                self.assertTrue(peer.collect(operation)[1].startswith("ERROR"))
                self.assertFalse(path.exists())
                self.assertFalse(list(self.allowed.glob(path.name + ".cf-*.tmp")))
                self.assertEqual(peer.put(operation + 1, path, data)[1], "OK")
                operation += 2

    def test_digest_mismatch_and_destination_race(self):
        with self.peer() as peer:
            bad = self.allowed / "bad-digest.txt"
            peer.request(11, 30, f"1 {'0' * 64} {winpath(bad)}")
            peer.send(4, 30, b"x")
            peer.send(12, 30)
            self.assertIn("MISMATCH", peer.collect(30)[1])
            self.assertFalse(bad.exists())
            path = self.allowed / "race.txt"
            peer.request(11, 31, f"1 {hashlib.sha256(b'x').hexdigest()} {winpath(path)}")
            deadline = time.monotonic() + 3
            while not list(self.allowed.glob("race.txt.cf-*.tmp")) and time.monotonic() < deadline:
                time.sleep(0.01)
            path.write_bytes(b"keep")
            peer.send(4, 31, b"x")
            peer.send(12, 31)
            self.assertTrue(peer.collect(31)[1].startswith("ERROR"))
            self.assertEqual(path.read_bytes(), b"keep")

    def test_apro_allowlist_and_path_containment(self):
        with self.peer(apro=True) as peer:
            for operation, command in enumerate(["not-allowed.exe", "cmd /c echo hi & whoami", "cmd /c echo %COMSPEC%", "cmd /c dir C:\\"], 40):
                peer.request(5, operation, command)
                self.assertEqual(peer.collect(operation)[1], "ERROR COMMAND DENIED")
            peer.request(5, 45, "whoami")
            self.assertTrue(peer.collect(45)[1].startswith("OK"))
            peer.request(5, 46, "cmd /c echo approved")
            output, result = peer.collect(46)
            self.assertIn(b"approved", output)
            self.assertTrue(result.startswith("OK"))
            outside = self.directory / "outside.txt"
            outside.write_bytes(b"secret")
            peer.request(10, 47, winpath(self.allowed) + "\\..\\outside.txt")
            self.assertEqual(peer.collect(47), (b"", "ERROR PATH DENIED"))
            self.assertEqual(peer.put(48, self.allowed / "approved.txt", b"ok")[1], "OK")
            self.assertEqual(peer.put(49, self.allowed / "denied.exe", b"bad")[1], "ERROR EXTENSION DENIED")

    def test_corrupt_compression_aborts_without_publishing(self):
        path = self.allowed / "corrupt.txt"
        with self.peer() as peer:
            peer.request(11, 50, f"3 {hashlib.sha256(b'abc').hexdigest()} {winpath(path)}")
            peer.send(6, 50, b"invalid zlib")
            with self.assertRaises((EOFError, OSError)):
                while True:
                    peer.receive()
        self.assertFalse(path.exists())
        self.assertFalse(list(self.allowed.glob("corrupt.txt.cf-*.tmp")))

    def test_apro_reparse_directory_is_denied(self):
        target = self.directory / "outside-directory"
        target.mkdir()
        (target / "secret.txt").write_bytes(b"secret")
        link = self.allowed / "junction"
        launcher = [os.environ["CF_WINE"]] if "CF_WINE" in os.environ else []
        created = subprocess.run(launcher + ["cmd", "/c", "mklink", "/J", winpath(link), winpath(target)],
                                 capture_output=True, text=True, env=dict(os.environ, WINEDEBUG="-all"))
        self.assertEqual(created.returncode, 0, created.stdout + created.stderr)
        try:
            with self.peer(apro=True) as peer:
                peer.request(10, 51, winpath(self.allowed) + "\\junction\\secret.txt")
                self.assertEqual(peer.collect(51), (b"", "ERROR PATH DENIED"))
        finally:
            subprocess.run(launcher + ["cmd", "/c", "rmdir", winpath(self.allowed) + "\\junction"], check=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, env=dict(os.environ, WINEDEBUG="-all"))

    def test_concurrent_exec_and_stderr_drain(self):
        fixture = winpath(os.environ["CF_FIXTURE"])
        with self.peer() as peer:
            for operation in range(60, 80):
                peer.request(5, operation, f'"{fixture}" flood')
                peer.send(12, operation)
            results, output, done = {}, {}, set()
            while len(done) < 20:
                kind, operation, data = peer.receive()
                if kind == 4:
                    output[operation] = output.get(operation, b"") + data
                    peer.send(14, operation, struct.pack("!I", len(data)))
                elif kind == 13:
                    results[operation] = data
                elif kind == 3:
                    done.add(operation)
                elif kind == 1:
                    peer.send(1)
            self.assertEqual(len(results), 20)
            for operation in done:
                self.assertTrue(results[operation].startswith(b"OK"))
                self.assertEqual(output[operation], b"stdout complete\n")

    def test_slow_stream_does_not_block_other_streams(self):
        path = self.allowed / "slow.txt"
        path.write_bytes(b"s" * 200000)
        with self.peer() as peer:
            peer.request(10, 90, winpath(path))
            peer.request(5, 91, "cmd /c echo responsive")
            done = False
            while not done:
                kind, operation, data = peer.receive()
                if operation == 91 and kind == 13:
                    self.assertTrue(data.startswith(b"OK"))
                if operation == 91 and kind == 3:
                    done = True
                # Withhold all credits for stream 90.
            peer.send(15, 90)
            self.assertTrue(peer.collect(90, credit=False)[1].startswith("ERROR"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
