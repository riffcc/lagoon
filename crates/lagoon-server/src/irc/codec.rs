/// IRC line codec — frames a TCP byte stream into IRC messages.
///
/// Splits on `\r\n` (per RFC 2812), parses each line into a [`Message`],
/// and serializes outgoing messages with `\r\n` termination.
///
/// Oversized lines (> 8191 bytes) are silently skipped rather than
/// killing the connection — this is scaffolding for the IRC transport
/// layer until TGFP replaces it.
use bytes::{Buf, BufMut, BytesMut};
use tokio_util::codec::{Decoder, Encoder};
use tracing::warn;

use super::message::{Message, ParseError};

/// Maximum line length (including `\r\n`).
/// RFC 2812 says 512 bytes. IRCv3 `message-tags` can push this to 8191.
const MAX_LINE_LENGTH: usize = 8191;

/// Codec error: either a protocol parse failure or an I/O error.
#[derive(Debug, thiserror::Error)]
pub enum CodecError {
    #[error("line exceeds maximum length ({MAX_LINE_LENGTH} bytes)")]
    LineTooLong,
    #[error(transparent)]
    Parse(#[from] ParseError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// A tokio codec that frames IRC messages on `\r\n` boundaries.
///
/// Oversized lines are skipped (logged + discarded) instead of returning
/// a fatal error. This keeps connections alive when MESH protocol messages
/// exceed the IRC line limit.
#[derive(Debug, Default)]
pub struct IrcCodec {
    /// True when we're discarding an oversized line and waiting for `\r\n`.
    skipping: bool,
}

impl Decoder for IrcCodec {
    type Item = Message;
    type Error = CodecError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        // If we're in skip mode (discarding an oversized line that didn't
        // have its \r\n terminator yet), scan for the terminator.
        if self.skipping {
            if let Some(pos) = src.windows(2).position(|w| w == b"\r\n") {
                let discarded = pos + 2;
                warn!(
                    bytes = discarded,
                    "codec: finished skipping oversized line tail"
                );
                src.advance(discarded);
                self.skipping = false;
                // Continue — try to decode the next message.
            } else {
                // Still no terminator. Discard everything and wait.
                src.clear();
                return Ok(None);
            }
        }

        // Look for \r\n in the buffer.
        let crlf_pos = src.windows(2).position(|w| w == b"\r\n");

        match crlf_pos {
            Some(pos) if pos > MAX_LINE_LENGTH => {
                // Complete oversized line — skip it entirely.
                warn!(
                    bytes = pos,
                    "codec: skipped oversized IRC line ({pos} bytes)"
                );
                src.advance(pos + 2); // skip line + \r\n
                // Try to decode the next message in the buffer.
                self.decode(src)
            }
            Some(pos) => {
                // Normal line — extract and parse.
                let line_bytes = src.split_to(pos);
                src.advance(2); // skip \r\n

                let line = std::str::from_utf8(&line_bytes)
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

                Ok(Some(Message::parse(line)?))
            }
            None => {
                // No complete line yet. Check if buffer is getting too large.
                if src.len() > MAX_LINE_LENGTH {
                    let discarded = src.len();
                    warn!(
                        bytes = discarded,
                        "codec: discarding oversized partial line, waiting for terminator"
                    );
                    src.clear();
                    self.skipping = true;
                }
                Ok(None)
            }
        }
    }
}

impl Encoder<Message> for IrcCodec {
    type Error = CodecError;

    fn encode(&mut self, item: Message, dst: &mut BytesMut) -> Result<(), Self::Error> {
        let wire = item.to_wire();
        dst.reserve(wire.len() + 2);
        dst.put_slice(wire.as_bytes());
        dst.put_slice(b"\r\n");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BytesMut;

    // ── Decoder ──────────────────────────────────────────────────

    #[test]
    fn decode_complete_line() {
        let mut codec = IrcCodec::default();
        let mut buf = BytesMut::from("NICK wings\r\n");
        let msg = codec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(msg.command, "NICK");
        assert_eq!(msg.params, vec!["wings"]);
        assert!(buf.is_empty());
    }

    #[test]
    fn decode_partial_line_then_complete() {
        let mut codec = IrcCodec::default();
        let mut buf = BytesMut::from("NICK wi");

        // Not enough data yet.
        assert!(codec.decode(&mut buf).unwrap().is_none());

        // More data arrives.
        buf.extend_from_slice(b"ngs\r\n");
        let msg = codec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(msg.command, "NICK");
        assert_eq!(msg.params, vec!["wings"]);
    }

    #[test]
    fn decode_two_messages_in_one_read() {
        let mut codec = IrcCodec::default();
        let mut buf = BytesMut::from("NICK wings\r\nUSER wings 0 * :Wings\r\n");

        let msg1 = codec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(msg1.command, "NICK");

        let msg2 = codec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(msg2.command, "USER");
        assert_eq!(msg2.params, vec!["wings", "0", "*", "Wings"]);

        assert!(buf.is_empty());
    }

    #[test]
    fn decode_message_with_prefix() {
        let mut codec = IrcCodec::default();
        let mut buf =
            BytesMut::from(":wings!user@host PRIVMSG #lagoon :Hello everyone!\r\n");
        let msg = codec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(msg.prefix.as_deref(), Some("wings!user@host"));
        assert_eq!(msg.command, "PRIVMSG");
        assert_eq!(msg.params, vec!["#lagoon", "Hello everyone!"]);
    }

    #[test]
    fn decode_skips_oversized_line_and_continues() {
        let mut codec = IrcCodec::default();
        // Oversized line followed by a valid line.
        let mut buf = BytesMut::new();
        buf.extend_from_slice(&vec![b'A'; MAX_LINE_LENGTH + 100]);
        buf.extend_from_slice(b"\r\nNICK wings\r\n");

        // First decode should skip the oversized line and return the valid one.
        let msg = codec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(msg.command, "NICK");
        assert_eq!(msg.params, vec!["wings"]);
        assert!(buf.is_empty());
    }

    #[test]
    fn decode_skips_oversized_partial_then_completes() {
        let mut codec = IrcCodec::default();
        // Oversized partial line (no \r\n yet).
        let mut buf = BytesMut::from(vec![b'A'; MAX_LINE_LENGTH + 100].as_slice());

        // Should return None and enter skip mode.
        assert!(codec.decode(&mut buf).unwrap().is_none());
        assert!(codec.skipping);
        assert!(buf.is_empty());

        // More data arrives with the terminator and a valid message.
        buf.extend_from_slice(b"more garbage\r\nNICK wings\r\n");
        let msg = codec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(msg.command, "NICK");
        assert!(!codec.skipping);
    }

    #[test]
    fn decode_empty_buffer() {
        let mut codec = IrcCodec::default();
        let mut buf = BytesMut::new();
        assert!(codec.decode(&mut buf).unwrap().is_none());
    }

    // ── Encoder ──────────────────────────────────────────────────

    #[test]
    fn encode_appends_crlf() {
        let mut codec = IrcCodec::default();
        let mut buf = BytesMut::new();
        let msg = Message {
            prefix: None,
            command: "NICK".into(),
            params: vec!["wings".into()],
        };
        codec.encode(msg, &mut buf).unwrap();
        assert_eq!(&buf[..], b"NICK :wings\r\n");
    }

    #[test]
    fn encode_with_prefix() {
        let mut codec = IrcCodec::default();
        let mut buf = BytesMut::new();
        let msg = Message {
            prefix: Some("server.lagun.co".into()),
            command: "001".into(),
            params: vec!["wings".into(), "Welcome to Lagun".into()],
        };
        codec.encode(msg, &mut buf).unwrap();
        assert_eq!(
            &buf[..],
            b":server.lagun.co 001 wings :Welcome to Lagun\r\n"
        );
    }

    // ── Roundtrip through codec ──────────────────────────────────

    #[test]
    fn roundtrip_through_codec() {
        let mut codec = IrcCodec::default();

        // Encode a message.
        let original = Message {
            prefix: Some("wings!user@host".into()),
            command: "PRIVMSG".into(),
            params: vec!["#lagoon".into(), "Hello everyone!".into()],
        };
        let mut buf = BytesMut::new();
        codec.encode(original.clone(), &mut buf).unwrap();

        // Decode it back.
        let decoded = codec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(decoded, original);
    }
}
