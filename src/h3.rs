//! --alpn h3: received data is decoded as HTTP/3 (RFC 9114) for display.
//!
//! Each frame becomes a line naming it, with its contents below: header
//! fields (QPACK-decoded) one per line, the payload of DATA frames as is.
//! Unidirectional streams start with a line naming their type (control,
//! push, QPACK encoder/decoder); QPACK instructions are shown as hex.
//!
//! We send no SETTINGS, so the peer must keep the QPACK dynamic table empty
//! (its default capacity is 0) and every field section decodes on its own.

use bytes::Bytes;

/// Frames other than DATA are shown once complete; larger ones are skipped.
const MAX_FRAME: u64 = 1 << 20;

/// Turns the bytes of one received stream into readable text.
pub struct Decoder {
    state: State,
    /// Bytes received but not decoded yet (an incomplete frame header or frame).
    buf: Vec<u8>,
}

enum State {
    /// Unidirectional stream: its type comes first.
    StreamType,
    /// Push stream: its push ID follows the type.
    PushId,
    /// A sequence of frames: request, control and push streams.
    Frames,
    /// Inside a frame payload that is passed through (DATA) or skipped.
    Payload {
        left: u64,
        show: bool,
        /// The last byte shown ended a line.
        newline: bool,
    },
    /// QPACK encoder/decoder or unknown stream: the rest is shown as hex.
    Hex,
}

impl Decoder {
    /// `uni`: a unidirectional stream (from the peer), which starts with its type.
    pub fn new(uni: bool) -> Self {
        Decoder {
            state: if uni { State::StreamType } else { State::Frames },
            buf: Vec::new(),
        }
    }

    /// Decodes what it can of `data`, keeps the rest for the next call.
    pub fn feed(&mut self, data: &[u8]) -> Vec<u8> {
        self.buf.extend_from_slice(data);
        let buf = std::mem::take(&mut self.buf);
        let mut out = Vec::new();
        let mut pos = 0;
        loop {
            let rest = &buf[pos..];
            match &mut self.state {
                State::StreamType => {
                    let Some((ty, n)) = varint(rest) else { break };
                    pos += n;
                    self.state = match ty {
                        0x00 => {
                            line(&mut out, "control stream");
                            State::Frames
                        }
                        0x01 => State::PushId,
                        0x02 => {
                            line(&mut out, "QPACK encoder stream");
                            State::Hex
                        }
                        0x03 => {
                            line(&mut out, "QPACK decoder stream");
                            State::Hex
                        }
                        _ => {
                            line(&mut out, format_args!("stream type {ty:#x}{}", reserved(ty)));
                            State::Hex
                        }
                    };
                }
                State::PushId => {
                    let Some((id, n)) = varint(rest) else { break };
                    pos += n;
                    line(&mut out, format_args!("push stream, push ID {id}"));
                    self.state = State::Frames;
                }
                State::Frames => {
                    let Some((ty, a)) = varint(rest) else { break };
                    let Some((len, b)) = varint(&rest[a..]) else { break };
                    if ty == 0x00 {
                        line(&mut out, format_args!("DATA, {len} bytes"));
                        self.state = State::Payload { left: len, show: true, newline: true };
                        pos += a + b;
                    } else if frame_name(ty).is_none() || len > MAX_FRAME {
                        let what = frame_name(ty).map_or_else(|| describe(ty), |name| format!("{name}, too large to show"));
                        line(&mut out, format_args!("{what}, {len} bytes"));
                        self.state = State::Payload { left: len, show: false, newline: true };
                        pos += a + b;
                    } else {
                        let end = a + b + len as usize;
                        if rest.len() < end {
                            break;
                        }
                        frame(&mut out, ty, &rest[a + b..end]);
                        pos += end;
                    }
                }
                State::Payload { left, show, newline } => {
                    if *left > 0 {
                        if rest.is_empty() {
                            break;
                        }
                        let n = rest.len().min(usize::try_from(*left).unwrap_or(usize::MAX));
                        if *show {
                            out.extend_from_slice(&rest[..n]);
                            *newline = rest[n - 1] == b'\n';
                        }
                        pos += n;
                        *left -= n as u64;
                    }
                    if *left == 0 {
                        // The next frame starts on a line of its own.
                        if !*newline {
                            out.push(b'\n');
                        }
                        self.state = State::Frames;
                    }
                }
                State::Hex => {
                    if rest.is_empty() {
                        break;
                    }
                    line(&mut out, format_args!("  {}  {}", hex(rest), ascii(rest)));
                    pos = buf.len();
                }
            }
        }
        self.buf = buf;
        self.buf.drain(..pos);
        out
    }

    /// The stream ended (FIN): says so if that was in the middle of something.
    pub fn end(&mut self) -> Vec<u8> {
        let mut out = Vec::new();
        match &self.state {
            State::Payload { left, newline, .. } => {
                if !*newline {
                    out.push(b'\n');
                }
                line(&mut out, format_args!("(stream ended {left} bytes before the end of the frame)"));
            }
            _ if !self.buf.is_empty() => {
                line(&mut out, format_args!("(stream ended inside a frame: {})", hex(&self.buf)));
            }
            _ => {}
        }
        self.buf.clear();
        out
    }
}

/// An HTTP Datagram (RFC 9297): the quarter stream ID of the request it
/// belongs to, then the payload.
pub fn datagram(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    match varint(data) {
        Some((quarter, n)) => {
            let payload = &data[n..];
            line(&mut out, format_args!("DATAGRAM, stream {}, {} bytes", quarter * 4, payload.len()));
            out.extend_from_slice(payload);
            if !payload.is_empty() && !payload.ends_with(b"\n") {
                out.push(b'\n');
            }
        }
        None => line(&mut out, format_args!("DATAGRAM without a quarter stream ID: {}", hex(data))),
    }
    out
}

fn line(out: &mut Vec<u8>, text: impl std::fmt::Display) {
    out.extend_from_slice(format!("{text}\n").as_bytes());
}

/// Frame types we show the contents of (other than DATA).
fn frame_name(ty: u64) -> Option<&'static str> {
    Some(match ty {
        0x01 => "HEADERS",
        0x03 => "CANCEL_PUSH",
        0x04 => "SETTINGS",
        0x05 => "PUSH_PROMISE",
        0x07 => "GOAWAY",
        0x0d => "MAX_PUSH_ID",
        // RFC 9218
        0xf0700 => "PRIORITY_UPDATE (request)",
        0xf0701 => "PRIORITY_UPDATE (push)",
        _ => return None,
    })
}

/// A frame type we do not decode, e.g. "frame type 0x21 (reserved)".
fn describe(ty: u64) -> String {
    let note = match ty {
        0x02 | 0x06 | 0x08 | 0x09 => " (HTTP/2 only, not allowed in HTTP/3)",
        _ => reserved(ty),
    };
    format!("frame type {ty:#x}{note}")
}

/// Reserved types and settings (0x1f * N + 0x21) are sent to exercise the
/// requirement that unknown ones are ignored ("greasing").
fn reserved(n: u64) -> &'static str {
    if n >= 0x21 && (n - 0x21).is_multiple_of(0x1f) { " (reserved)" } else { "" }
}

/// A complete frame other than DATA.
fn frame(out: &mut Vec<u8>, ty: u64, payload: &[u8]) {
    let name = frame_name(ty).unwrap_or("?");
    let mut p = payload;
    match ty {
        0x01 => {
            line(out, name);
            field_section(out, p);
        }
        0x04 => {
            line(out, name);
            while !p.is_empty() {
                let Some(((id, value), rest)) = varint_at(p).and_then(|(id, r)| varint_at(r).map(|(v, r)| ((id, v), r)))
                else {
                    return line(out, format_args!("  (malformed: {})", hex(p)));
                };
                line(out, format_args!("  {} = {value}", setting_name(id)));
                p = rest;
            }
        }
        0x05 => match varint_at(p) {
            Some((id, rest)) => {
                line(out, format_args!("{name}, push ID {id}"));
                field_section(out, rest);
            }
            None => line(out, format_args!("{name}, malformed: {}", hex(p))),
        },
        0x03 | 0x07 | 0x0d => match varint_at(p) {
            Some((id, [])) => {
                let what = if ty == 0x07 { "ID" } else { "push ID" };
                line(out, format_args!("{name}, {what} {id}"));
            }
            _ => line(out, format_args!("{name}, malformed: {}", hex(p))),
        },
        0xf0700 | 0xf0701 => match varint_at(p) {
            Some((id, value)) => {
                let what = if ty == 0xf0700 { "stream" } else { "push ID" };
                line(out, format_args!("{name}, {what} {id}: {}", String::from_utf8_lossy(value)));
            }
            None => line(out, format_args!("{name}, malformed: {}", hex(p))),
        },
        _ => unreachable!("frame_name() lists the frames shown"),
    }
}

/// QPACK-encoded header fields, one "  name: value" line each.
fn field_section(out: &mut Vec<u8>, block: &[u8]) {
    let mut buf = Bytes::copy_from_slice(block);
    match qpack::decode_stateless(&mut buf, MAX_FRAME) {
        Ok(decoded) => {
            for field in decoded.fields {
                line(out, format_args!("  {}: {}", String::from_utf8_lossy(&field.name), String::from_utf8_lossy(&field.value)));
            }
        }
        Err(e) => line(out, format_args!("  (QPACK: {e}: {})", hex(block))),
    }
}

fn setting_name(id: u64) -> String {
    match id {
        0x01 => "QPACK_MAX_TABLE_CAPACITY".into(),
        0x06 => "MAX_FIELD_SECTION_SIZE".into(),
        0x07 => "QPACK_BLOCKED_STREAMS".into(),
        0x08 => "ENABLE_CONNECT_PROTOCOL".into(),
        0x33 => "H3_DATAGRAM".into(),
        _ => format!("{id:#x}{}", reserved(id)),
    }
}

/// A QUIC variable-length integer (RFC 9000, 16) and its length in bytes.
fn varint(b: &[u8]) -> Option<(u64, usize)> {
    let first = *b.first()?;
    let len = 1 << (first >> 6);
    let bytes = b.get(1..len)?;
    let v = bytes.iter().fold(u64::from(first & 0x3f), |v, &x| v << 8 | u64::from(x));
    Some((v, len))
}

/// `varint`, returning the bytes after it.
fn varint_at(b: &[u8]) -> Option<(u64, &[u8])> {
    varint(b).map(|(v, n)| (v, &b[n..]))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(" ")
}

/// The bytes as printable ASCII, with "." for the rest, to go next to `hex`.
fn ascii(bytes: &[u8]) -> String {
    bytes.iter().map(|&b| if b == b' ' || b.is_ascii_graphic() { b as char } else { '.' }).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(out: Vec<u8>) -> String {
        String::from_utf8(out).unwrap()
    }

    #[test]
    fn request_stream() {
        // HEADERS: prefix 00 00, ":status: 200" (static 25), "content-type:
        // text/plain" (static 53); DATA "hello" without a newline; a reserved frame.
        let stream = [&[0x01, 0x04, 0x00, 0x00, 0xd9, 0xf5][..], &[0x00, 0x05], b"hello", &[0x21, 0x01, 0xff]].concat();
        let want = "HEADERS\n  :status: 200\n  content-type: text/plain\nDATA, 5 bytes\nhello\nframe type 0x21 (reserved), 1 bytes\n";
        assert_eq!(text(Decoder::new(false).feed(&stream)), want);
        // Byte by byte gives the same, apart from where DATA is split.
        let mut d = Decoder::new(false);
        let out: Vec<u8> = stream.iter().flat_map(|b| d.feed(&[*b])).collect();
        assert_eq!(text(out), want);
        assert_eq!(text(d.end()), "");
    }

    #[test]
    fn literal_huffman_value() {
        // ":authority: www.example.com" as a literal with static name
        // reference 0 and a Huffman-coded value (from RFC 7541, C.4.1).
        let huffman = [0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff];
        let block = [&[0x00, 0x00, 0x50, 0x8c][..], &huffman].concat();
        let stream = [&[0x01, block.len() as u8][..], &block].concat();
        assert_eq!(text(Decoder::new(false).feed(&stream)), "HEADERS\n  :authority: www.example.com\n");
    }

    #[test]
    fn control_stream() {
        // type 0, SETTINGS {QPACK_MAX_TABLE_CAPACITY: 4096 (2-byte varint), 0x21: 0}, GOAWAY 8
        let stream = [0x00, 0x04, 0x05, 0x01, 0x50, 0x00, 0x21, 0x00, 0x07, 0x01, 0x08];
        assert_eq!(
            text(Decoder::new(true).feed(&stream)),
            "control stream\nSETTINGS\n  QPACK_MAX_TABLE_CAPACITY = 4096\n  0x21 (reserved) = 0\nGOAWAY, ID 8\n"
        );
    }

    #[test]
    fn ends_inside_frame() {
        let mut d = Decoder::new(false);
        assert_eq!(text(d.feed(&[0x00, 0x05, b'h', b'i'])), "DATA, 5 bytes\nhi");
        assert_eq!(text(d.end()), "\n(stream ended 3 bytes before the end of the frame)\n");
    }

    #[test]
    fn unknown_stream() {
        // A reserved stream type (0x21) followed by text and a non-printable byte.
        assert_eq!(text(Decoder::new(true).feed(&[0x21, b'h', b'i', 0x00])), "stream type 0x21 (reserved)\n  68 69 00  hi.\n");
    }

    #[test]
    fn http_datagram() {
        assert_eq!(text(datagram(&[0x01, b'h', b'i'])), "DATAGRAM, stream 4, 2 bytes\nhi\n");
    }
}
