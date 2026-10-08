# Cuttlefish

A reverse-tunnel remote administration toolkit: a Windows client connects to a
Linux server through mutually authenticated TLS. Operators can execute commands,
transfer files, and forward TCP connections over that connection.

**This update defaults to protocol v2.** For an existing deployment, first upgrade
both endpoints using `--protocol legacy`, then migrate clients to a separate v2
listener. Never point an old client at a v2 listener. There is no automatic downgrade.

## Architecture and source

```
local controller → private Unix control socket → cf-server
                                                  ↕ stdin/stdout
                                               stunnel
                                                  ↕ mutual TLS
                                             Windows client
```

| Source | Purpose |
|---|---|
| `common.h` | Validated legacy/v2 framing and bounded buffers |
| `cf-server.c` | Nonblocking Linux controller, multiplexing, session ownership |
| `cf-client-core.h` | Shared Windows TLS owner, workers, file transactions, APRO policy |
| `cf-client-win.c` | General Windows client |
| `cf-client-win-apro.c` | Restricted APRO Windows client |
| `bin/cfctl` and wrappers | Python 3 controller and shell entry points |
| `perl/lib/cf.pm` | Perl controller API |
| `PROTOCOL.md` | Wire format, flow control, and compatibility rules |
| `cf-hardening-tests.py`, `cf-protocol-test.c` | Linux sanitizer regressions and bounded parser corpus |
| `cf-client-tests.py`, `cf-test-child.c` | Windows TLS, concurrency, APRO, and transactional file tests |
| `.github/workflows/hardening.yml` | Linux sanitizer and native Windows CI |
| `XGetopt.c`, `XGetopt.h` | Historical getopt implementation; no longer required by the clients |

## Build

Both endpoints include the amalgamated `miniz.c` and `miniz.h` directly. Generate
them from a pinned release, for example [miniz 3.1.2](https://github.com/richgel999/miniz/releases):

```sh
curl -fL https://github.com/richgel999/miniz/archive/refs/tags/3.1.2.tar.gz -o /tmp/miniz.tar.gz
tar -xzf /tmp/miniz.tar.gz -C /tmp
cmake -S /tmp/miniz-3.1.2 -B /tmp/miniz-build -DAMALGAMATE_SOURCES=ON
cp /tmp/miniz-build/amalgamation/miniz.c /tmp/miniz-build/amalgamation/miniz.h .
gcc -Wall -Wextra -pedantic -std=gnu99 -Werror -O2 cf-server.c -o cf-server
```

The Windows runtime uses cancellable I/O and restricted handle inheritance.
Use Windows 8/Server 2012 or newer (nested job objects), and a maintained TLS library.
The old XP-oriented build is not supported by this runtime.

Example cross-build, with Windows OpenSSL headers/libraries under `$CF_TLS`:

```sh
i686-w64-mingw32-gcc -Wall -Wextra -pedantic -std=gnu99 -Werror -Os -static -I "$CF_TLS/include" cf-client-win.c -o Cuttlefish.exe -L "$CF_TLS/lib" -lssl -lcrypto -lcrypt32 -lws2_32 -lgdi32
i686-w64-mingw32-gcc -Wall -Wextra -pedantic -std=gnu99 -Werror -Os -static -I "$CF_TLS/include" cf-client-win-apro.c -o CuttlefishApro.exe -L "$CF_TLS/lib" -lssl -lcrypto -lcrypt32 -lws2_32 -lgdi32
```

Match the TLS archive's CRT to the compiler's CRT. Old MSVCRT archives may require
`-lmsvcrt-os` with a UCRT toolchain; prefer rebuilding dependencies consistently.
For modern wolfSSL, build its OpenSSL compatibility layer with
[`--enable-opensslall`](https://www.wolfssl.com/documentation/manuals/wolfssl/chapter02.html),
define `CF_CYASSL` and link `-lwolfssl` instead of `-lssl -lcrypto`.
The historical CyaSSL 2.x library is not supported. CI includes both library variants.

## Certificates and deployment

Create a distinct client certificate for each client, with its stable ID in CN.
Use 1–64 ASCII letters, digits, dots, underscores, or hyphens; `.` and `..` are
not valid IDs. Stunnel supplies the authenticated subject in `SSL_CLIENT_DN`.

The client's `-s` file contains the **exact server certificate**, not a general CA
authorization. The client requires a valid chain, a currently valid certificate,
and an exact match to that certificate. It requires TLS 1.2 or newer. Updating a
server certificate requires updating the client trust files; use a separate
listener while rotating certificates. `-c` points to the combined client
certificate and private-key PEM. Protect private keys with OS permissions.

Use the [stunnel certificate instructions](https://www.stunnel.org/howto.html) to
generate the server identity and configure peer-certificate verification for the
client certificates. A client certificate/key PEM can be generated and combined:

```sh
openssl req -new -x509 -newkey rsa:3072 -nodes -days 365 -subj /CN=client001 -keyout client.key -out client.crt
cat client.crt client.key > client.pem
chmod 0600 client.key client.pem
```

Create the control directory owned by the account running `cf-server`, mode 0700.
The server rejects directories accessible by other users/groups, symlinks as the
final directory component, and duplicate live sessions with the same CN.
Keep `.lock` files in place: an unlocked lock file is reusable, not an orphan
process indicator. PID files are informational; helpers no longer kill a PID
merely because a socket is missing.

Configure stunnel to invoke:

```text
exec = /opt/cuttlefish/cf-server
execargs = /opt/cuttlefish/cf-server -p /opt/cuttlefish/pipes-v2 --protocol v2
```

For the migration listener, use a separate port and directory:

```text
execargs = /opt/cuttlefish/cf-server -p /opt/cuttlefish/pipes-legacy --protocol legacy
```

Add `-z` only for clients predating the compression flag. Modern legacy clients
use `--protocol legacy` without `-z`. Do not combine `-z` with v2.

Client example:

```text
Cuttlefish.exe -u server.example -p 1163 -w C:\Cuttlefish -s server.crt -c client.pem --protocol v2
```

Arguments may appear in any order. Paths to certificates can be absolute or
relative to `-w`. `-l FILE` selects a client log; server `-l DIRECTORY` selects its
log directory. A logging failure does not terminate a session. The general
client accepts LOG toggles for its configured destination; APRO ignores them.
A service manager such as NSSM can restart a client after tunnel failure.

## Operations

All commands end in a newline. All v2 operation commands specify local port `0`;
the response supplies an operation ID and a private Unix data-socket path.
Only the service user can access control and v2 data sockets.

```text
EXEC 0 [--compress] command
CONNECT 0 [--compress] host port
GET 0 [--compress] remote-path
PUT 0 [--compress] byte-count sha256-hex remote-path
STATUS
LIST
RESULT operation-id
CANCEL operation-id
PING
LOG 0|1
CLOSE
```

GET downloads an existing file. PUT never replaces a destination. It writes a
temporary file beside the destination, checks the declared size and SHA-256,
flushes it, and publishes without replacement. Cancellation or failure removes
the temporary file. Abrupt process/OS termination can leave a uniquely named
temporary file, but never publishes it as the destination or changes a retry's
operation direction. A successful PUT retry against an already published file
returns an error rather than overwriting it.

Socket EOF alone is not proof of success: v2 callers must read RESULT. The latest
64 completed results are retained per tunnel; callers should retrieve them promptly.
EXEC exposes stdin/stdout. Stderr is drained and discarded; it is not merged into
stdout. FINISH/Unix write-half-close sends stdin EOF without discarding output.

Examples (Python 3.8+ on the controller host):

```sh
bin/cfcmd /opt/cuttlefish/pipes-v2/client001 'cmd /c dir C:\'
bin/cfcmdshell /opt/cuttlefish/pipes-v2/client001
bin/cfcpup /opt/cuttlefish/pipes-v2/client001 local.txt 'C:\Data\new.txt'
bin/cfcpdown /opt/cuttlefish/pipes-v2/client001 'C:\Data\existing.txt' > local.txt
bin/cfpipe /opt/cuttlefish/pipes-v2/client001 STATUS
```

For CN-only helper arguments, set `CF_BASE`; sockets are then found under
`$CF_BASE/pipes/CN`. The Perl module retains `check`, `cmd`, `cmd_connect`,
`cmd_exec`, and `cmd_file`. Configure `$cmf::CF_BASE`. V2 endpoints returned by
`cmd_connect`/interactive `cmd_exec` are Unix paths, not numeric ports. Failures
raise exceptions. Perl buffers returned data up to 8 MiB; use `cfctl` for larger
downloads. File helpers transfer exact bytes; they no longer delete destinations
or automatically gzip/rename files before uploading.

## Legacy limits

Legacy retains the 12-byte native header used by existing little-endian x86
builds. The old FILE command chooses direction by destination existence. Exclusive
creation prevents overwrites, but an interrupted upload can leave a partial file
and a retry can still become a download. Legacy has no trustworthy completion
acknowledgment or per-stream flow control. Use v2 for transactional transfers.

Legacy operation ports bind only to loopback but still trust other local users.
Run legacy only on a host whose local users are trusted. Legacy buffering limits
close an overflowing operation rather than consuming unbounded memory. Existing
space-terminated Perl requests get a 100 ms compatibility grace period; that
historical format cannot unambiguously distinguish a delayed fragment from a
finished command. Updated helpers always send newlines.

## APRO policy

APRO disables CONNECT and dynamic LOG. Its default roots are `C:\apro`,
`C:\ezagent`, `C:\eappw`, and `C:\aprosql`. Repeated `--root ABSOLUTE_PATH` options
replace these defaults. Paths are expanded, resolved, checked for containment,
and guarded against reparse-point/ancestor substitution. Device paths, UNC file
paths, alternate streams, wildcards, and ambiguous trailing dots/spaces are denied.
Upload extensions are `.txt`, `.pdf`, `.csv`, `.gif`, `.png`, `.jpg`, `.jpeg`,
`.tif`, and `.tiff`.

EXEC permits `whoami`, validated `net use` mapping arguments, `cmd /c echo`,
`cmd /c dir` with one contained path, `md5sum`/`zzip1` with one contained file,
`oddie1`/`zpxdump` with validated path arguments, and contained `formview.exe`
execution. The documented `cmd /c start "" /d"ROOT" /wait /high "ROOT\formview" ...`
form is translated to direct execution with the validated working directory.
System tools use explicit System32 paths; application utilities come from `-w`.
Shell chaining, redirection, expansion, and escape characters are rejected.
Application utilities and their configuration remain trusted; install them and
the allowed roots with permissions appropriate for the service account.

## Verification

Run the bounded Linux suite with ASan/UBSan:

```sh
mkdir -p /tmp/cf-check
gcc -Wall -Wextra -pedantic -std=gnu99 -Werror -g -O1 -fsanitize=address,undefined cf-server.c -o /tmp/cf-check/cf-server
gcc -Wall -Wextra -pedantic -std=gnu99 -Werror -g -O1 -fsanitize=address,undefined cf-protocol-test.c -o /tmp/cf-check/cf-protocol-test
/tmp/cf-check/cf-protocol-test
CF_SERVER=/tmp/cf-check/cf-server ~/venv/bin/python cf-hardening-tests.py
```

Windows tests require `CF_CLIENT`, `CF_APRO`, `CF_FIXTURE`, and an `openssl`
executable for disposable test certificates. Run `cf-client-tests.py` with Python.
On Linux, `CF_WINE=wine` enables Wine explicitly; supply an isolated `WINEPREFIX`.
The suite uses only generated certificates, local connections, and temporary files.
CI runs native Windows tests for both TLS-library variants. Extended fuzzing and
long soak runs are separate from this bounded suite.
