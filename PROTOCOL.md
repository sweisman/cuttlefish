# Cuttlefish protocol

Both endpoints explicitly select `--protocol v2` (default) or `--protocol legacy`.
There is no sniffing, negotiation, or fallback. Stunnel authenticates clients;
the Windows client validates and pins the server certificate before reading frames.

## Framing

V2 has a 16-byte header, followed by exactly the declared number of payload bytes:

| Offset | Width | Field |
|---|---|---|
| 0 | 4 | ASCII `CTF2` |
| 4 | 1 | Version, exactly 2 |
| 5 | 1 | Packet type |
| 6 | 2 | Reserved flags, exactly zero |
| 8 | 4 | Unsigned stream ID, network byte order |
| 12 | 4 | Unsigned payload length, network byte order, at most 1024 |

Legacy preserves `type` at offset 0, ID at offset 4, signed 16-bit length at offset
8, and a total native header size of 12. The existing little-endian ABI is required;
padding is zeroed on output and ignored on input. Negative lengths are invalid.

The parser accepts partial headers/payloads and multiple frames per read. It
validates lengths before copying and fails the tunnel on invalid framing. It does
not scan for a new magic sequence after corruption. Compression is independently
bounded to 1024 decompressed bytes per DATA frame; failed decompression is fatal.

## Packets

| Type | Name | Payload / use |
|---|---|---|
| 1 | PING | ID 0, empty; heartbeat, no immediate echo required |
| 2 | CONNECT | Compression byte, NUL-terminated `host:port` |
| 3 | DISCONNECT | Empty; remote operation output has ended |
| 4 | DATA | 1–1024 raw bytes |
| 5 | EXEC | Compression byte, NUL-terminated command |
| 6 | COMPRESSED | zlib-compressed DATA |
| 7 | FILE | Legacy only: compression byte and NUL-terminated path |
| 8 | MESSAGE | Legacy diagnostic string; NUL-terminated |
| 9 | LOG | ID 0, `0\0` or `1\0`; configured client logging toggle |
| 10 | GET | V2: compression byte, NUL-terminated path |
| 11 | PUT | V2: compression byte, NUL-terminated `size sha256 path` |
| 12 | FINISH | V2: empty; no more input for this operation |
| 13 | RESULT | V2: NUL-terminated `OK...` or `ERROR...` |
| 14 | CREDIT | V2: unsigned 32-bit byte count, network byte order |
| 15 | CANCEL | V2: empty; abort operation |

The compression byte is 0 or 1; it requests compression for outgoing operation
data. Incompressible chunks use DATA. `-z` in legacy mode omits this byte from
CONNECT/EXEC/FILE requests and disables compressed data. Request strings contain
exactly one terminating NUL, with no embedded NUL. Operations have nonzero IDs.
Duplicate active IDs are fatal. Late packets for released operations are ignored.

Requests originate at the server. The client returns RESULT then DISCONNECT after
all queued output; clients do not free a worker's buffers until its thread exits.
GET/PUT require explicit completion, not transport closure. FINISH is an input
half-close; CANCEL discards the operation. In legacy, DISCONNECT also serves as
input EOF/cancellation, so legacy cannot provide these distinctions.

## Limits and flow control

Each v2 operation starts with 65,536 bytes of credit in each direction. DATA and
COMPRESSED consume credit by their **uncompressed** byte count. A receiver returns
CREDIT only after successfully writing those bytes to its sink. Accumulated credit
cannot exceed the initial window. Over-crediting or sending beyond credit is a
protocol violation. CREDIT and completion/cancellation packets consume no credit.

Limits are 64 live operations, 256 KiB queued application data per operation, and
8 MiB of dynamically allocated queue storage per endpoint/session. Queues account
for allocated capacity, not just live bytes. Local controllers are capped at 16;
control commands at 1023 bytes plus their newline. Replies are bounded at 128 KiB.

Unattached data consumers and operations without forward progress expire after
30 seconds. Workers can block only their own operation; the TLS owner and Linux
event loop remain responsive. Heartbeats are sent after 25 seconds without tunnel
output; 35 seconds without a complete incoming frame ends the session.

Legacy has no credits. Exceeding its bounded output queue terminates the affected
operation. No compatibility mode permits unbounded buffering.

## Local controller protocol

One newline-delimited command per control connection; response then EOF.
Administrative commands are STATUS, LIST, PING, LOG, CLOSE, and (v2) RESULT/CANCEL.
Operation commands are `VERB 0 [--compress] arguments`. Legacy allows a specified
TCP port instead of 0. V2 accepts only 0 and creates a private Unix socket.

```
EXEC SUCCESS 123 /private/pipes/.cf-session/123   # v2: ID and Unix socket
EXEC SUCCESS 49152                              # legacy: TCP port
ERROR INVALID COMMAND                          # control rejection
```

Operation acceptance means the listener exists; it does not mean the remote
operation succeeded. V2 consumers attach, transfer bytes, write-half-close when
their input is complete, drain output to EOF, then query `RESULT 123`. A terminal
result begins with OK or ERROR; PENDING means it is still running. Unknown/evicted
IDs return ERROR. Results retain the latest 64 completions, so retrieve promptly.

PUT metadata describes the original uncompressed content. Its SHA-256 is 64 hex
digits; size is an unsigned decimal byte count. Both empty and nonempty files are
supported. Publication uses a same-directory temporary file, explicit flush, and
a rename that refuses replacement. No protocol command overwrites a destination.
