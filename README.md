# qnc

A netcat-like tool over QUIC, built on [quinn](https://github.com/quinn-rs/quinn)
and rustls. Like `nc`, it pipes stdin to the peer and the peer's data to stdout;
on top of that it has an interactive mode for working with several streams, and
logging/tracing options for learning and debugging the QUIC protocol.

## Install

Install the latest version from GitHub into `~/.cargo/bin` (needs a Rust
toolchain):

```sh
cargo install --git https://github.com/uglykitty/qnc
```

Or build from a clone:

```sh
git clone https://github.com/uglykitty/qnc
cd qnc
cargo build --release        # binary at target/release/qnc
cargo install --path .       # or install it into ~/.cargo/bin
```

## Quick start

```sh
# Server with a generated self-signed certificate, saved for the client
qnc -l 0.0.0.0:4433 --save-cert cert.pem

# Client trusting that certificate
qnc --ca cert.pem localhost 4433

# Client that skips certificate verification
qnc -k localhost 4433
```

Each connection carries one bidirectional stream. When stdin ends, qnc sends
FIN and keeps reading until the peer finishes too, like `nc -N`.

## Modes

| Mode | Command | Description |
|---|---|---|
| Stream (default) | `qnc -k HOST PORT` | One bidirectional stream per connection |
| Datagram | `qnc -u -k HOST PORT` | Unreliable QUIC DATAGRAM frames (RFC 9221), like `nc -u`; both sides need `-u`. After stdin EOF, keeps receiving for `-q SECS` (default 1) |
| Interactive | `qnc -i -k HOST PORT` | A console for several streams, see below |
| Echo server | `qnc -l ADDR --echo` | Echoes every stream (or datagram, with `-u`) back, serving many clients concurrently |

A server handles one connection and exits; with `--keep` it accepts one
connection after another.

For a real certificate use `--cert chain.pem --key key.pem` on the server. On the
client, `--sni` sets the TLS server name (default: HOST) and `--alpn` the ALPN
protocol (default `qnc`, must match on both sides).

## Interactive mode (`-i`)

The connection starts with no streams. Lines you type go to the current stream;
lines starting with `/` are commands:

| Command | Effect |
|---|---|
| `/open` | Open a bidirectional stream and make it current |
| `/open-uni` | Open a unidirectional (send-only) stream and make it current |
| `/list`, `/ls` | List streams: who opened them, bidirectional or unidirectional, bytes sent/received, the state of each direction (`*` = current) |
| `/use ID` | Make stream ID current |
| `/close [ID]` | Finish our sending side (FIN) |
| `/reset [ID] [CODE]` | Abort our sending side (RESET_STREAM) |
| `/stop [ID] [CODE]` | Ask the peer to stop sending (STOP_SENDING) |
| `/kill [ID] [CODE]` | Abort both directions now (`/reset` + `/stop`) |
| `/forget [ID]` | Remove an ended stream from `/list` (no ID: all ended ones); sends nothing |
| `/migrate [PORT]` | Client: move the connection to a new local UDP port (random if not given), like switching networks |
| `/quit` | Close the connection now |
| `/help` | Show the command list |

`ID` defaults to the current stream and `CODE` (the application error code) to 0.
To send a line starting with `/`, type `//`. Bidirectional streams opened by the
client are numbered 0, 4, 8, …, those opened by the server 1, 5, 9, …;
unidirectional ones 2, 6, 10, … (client) and 3, 7, 11, … (server).
On a unidirectional stream only the side that opened it sends; the other side
can only `/stop` it.

Received data is printed per line, prefixed with the stream ID (`[4] hello`), and
events such as a FIN or reset from the peer, or a change of the peer's address
(the client migrating), are shown as `* ...` lines. On a
terminal there is line editing and history, Tab completes command names and
stream IDs, Ctrl-C clears the line, and Ctrl-D quits after sending FIN on every
stream.

Both sides can use `-i`. A server with `-i` shows the console right away; while
it waits for a client, Ctrl-D or `/quit` stops it. Against a server in the default stream mode, note that
it serves only the first stream and closes the connection when that stream ends.

## Transport settings

| Setting | Value |
|---|---|
| Keep-alive | The client sends a PING after 10 s without other traffic; the server sends none |
| Idle timeout | 60 s announced by both sides (the connection uses the smaller of the two announced values) |
| MTU discovery | After the handshake, each side probes its sending direction with padded PING packets, binary search from `--initial-mtu` (default 1200) up to `--mtu-upper` (default 1452) |

Options to experiment with:

- `--no-mtud`: no MTU discovery, stay at `--initial-mtu`.
- `--mtu-upper BYTES`: probe up to this size; it is also announced to the peer as
  our `max_udp_payload_size`, so both sides need it to go above 1472.
- `--initial-mtu BYTES`: packet size used before MTU discovery.
- `--zero-cid`: use zero-length connection IDs. The peer's packets are matched by
  address and we issue no NEW_CONNECTION_ID frames, so connection migration and
  stateless reset no longer work. With it on both sides, no connection IDs are
  exchanged at all.

## Inspecting the protocol

- `-v`: connection events and statistics on exit (RTT, MTU, congestion window,
  bytes, lost packets).
- `-vv`: stream events, negotiated ALPN/SNI, path statistics and per-type frame
  counts.
- `-vvv`: quinn and rustls debug logs; `-vvvv`: packet-level trace.
- `--qlog DIR`: one qlog file per connection, to view in
  [qvis](https://qvis.quictools.info). Client and server traces of the same
  connection share a group ID (the original destination connection ID).
- `SSLKEYLOGFILE=keys.txt`: writes the TLS secrets, so Wireshark can decrypt
  captured QUIC packets.

## Exit status

| Status | Meaning |
|---|---|
| 0 | Success |
| 1 | Error |
| 130 / 143 | Stopped by SIGINT / SIGTERM (128 + signal number) |

On the first SIGINT or SIGTERM, qnc closes every connection with a
CONNECTION_CLOSE frame (application error code 1, reason `interrupted`) so
peers learn right away; a second signal exits immediately.
