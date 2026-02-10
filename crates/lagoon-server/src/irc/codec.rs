/// IRC line codec — frames a TCP byte stream into IRC messages.
///
/// Splits on `\r\n` (per RFC 2812), parses each line into a [`Message`],
/// and serializes outgoing messages with `\r\n` termination.
use bytes::{Buf, BufMut, BytesMut};
use tokio_util::codec::{Decoder, Encoder};

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
#[derive(Debug, Default)]
pub struct IrcCodec;

impl Decoder for IrcCodec {
    type Item = Message;
    type Error = CodecError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        // Look for \r\n in the buffer.
        let crlf_pos = src.windows(2).position(|w| w == b"\r\n");

        match crlf_pos {
            Some(pos) => {
                // Extract the line (without \r\n), advance the buffer.
                let line_bytes = src.split_to(pos);
                src.advance(2); // skip \r\n

                let line = std::str::from_utf8(&line_bytes)
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

                Ok(Some(Message::parse(line)?))
            }
            None => {
                // No complete line yet. Check if buffer is getting too large.
                if src.len() > MAX_LINE_LENGTH {
                    return Err(CodecError::LineTooLong);
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
        let mut codec = IrcCodec;
        let mut buf = BytesMut::from("NICK wings\r\n");
        let msg = codec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(msg.command, "NICK");
        assert_eq!(msg.params, vec!["wings"]);
        assert!(buf.is_empty());
    }

    #[test]
    fn decode_partial_line_then_complete() {
        let mut codec = IrcCodec;
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
        let mut codec = IrcCodec;
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
        let mut codec = IrcCodec;
        let mut buf =
            BytesMut::from(":wings!user@host PRIVMSG #lagoon :Hello everyone!\r\n");
        let msg = codec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(msg.prefix.as_deref(), Some("wings!user@host"));
        assert_eq!(msg.command, "PRIVMSG");
        assert_eq!(msg.params, vec!["#lagoon", "Hello everyone!"]);
    }

    #[test]
    fn decode_rejects_oversized_line() {
        let mut codec = IrcCodec;
        let mut buf = BytesMut::from(vec![b'A'; MAX_LINE_LENGTH + 1].as_slice());
        let err = codec.decode(&mut buf).unwrap_err();
        assert!(matches!(err, CodecError::LineTooLong));
    }

    #[test]
    fn decode_empty_buffer() {
        let mut codec = IrcCodec;
        let mut buf = BytesMut::new();
        assert!(codec.decode(&mut buf).unwrap().is_none());
    }

    // ── Encoder ──────────────────────────────────────────────────

    #[test]
    fn encode_appends_crlf() {
        let mut codec = IrcCodec;
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
        let mut codec = IrcCodec;
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
        let mut codec = IrcCodec;

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
