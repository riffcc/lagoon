/// IRC message parsing and serialization.
///
/// Implements RFC 2812 message format:
///   [`:`prefix SPACE] command [SPACE params] [SPACE `:` trailing]
///
/// Messages are terminated by CR-LF (`\r\n`) on the wire,
/// but parsing operates on the content without the terminator.
use std::fmt;

/// A parsed IRC message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    /// Optional prefix (server name or `nick!user@host`).
    pub prefix: Option<String>,
    /// The command (e.g. `PRIVMSG`, `001`, `NICK`).
    pub command: String,
    /// Parameters — the last may have been a trailing param (with spaces).
    pub params: Vec<String>,
}

/// Errors that can occur during message parsing.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ParseError {
    #[error("empty message")]
    Empty,
    #[error("prefix present but missing command")]
    MissingCommand,
}

impl Message {
    /// Parse a single IRC message from a line (without the trailing `\r\n`).
    pub fn parse(input: &str) -> Result<Self, ParseError> {
        let input = input.trim_end_matches("\r\n");

        if input.is_empty() {
            return Err(ParseError::Empty);
        }

        let (prefix, rest) = if input.starts_with(':') {
            // Prefix runs until the first space.
            match input[1..].find(' ') {
                Some(idx) => (Some(input[1..=idx].to_owned()), &input[idx + 2..]),
                None => return Err(ParseError::MissingCommand),
            }
        } else {
            (None, input)
        };

        // Split into command and parameter portion.
        let (command, param_str) = match rest.find(' ') {
            Some(idx) => (&rest[..idx], Some(&rest[idx + 1..])),
            None => (rest, None),
        };

        if command.is_empty() {
            return Err(ParseError::MissingCommand);
        }

        let mut params = Vec::new();

        if let Some(mut remaining) = param_str {
            while !remaining.is_empty() {
                if remaining.starts_with(':') {
                    // Trailing parameter: everything after the colon, including spaces.
                    params.push(remaining[1..].to_owned());
                    break;
                }
                match remaining.find(' ') {
                    Some(idx) => {
                        params.push(remaining[..idx].to_owned());
                        remaining = &remaining[idx + 1..];
                    }
                    None => {
                        params.push(remaining.to_owned());
                        break;
                    }
                }
            }
        }

        Ok(Message {
            prefix,
            command: command.to_owned(),
            params,
        })
    }

    /// Serialize to the IRC wire format (without trailing `\r\n`).
    pub fn to_wire(&self) -> String {
        let mut out = String::new();

        if let Some(ref prefix) = self.prefix {
            out.push(':');
            out.push_str(prefix);
            out.push(' ');
        }

        out.push_str(&self.command);

        if !self.params.is_empty() {
            let last_idx = self.params.len() - 1;
            for (i, param) in self.params.iter().enumerate() {
                out.push(' ');
                if i == last_idx {
                    // Always prefix the last parameter with `:`.
                    // This is always valid per RFC 2812 and avoids edge cases
                    // where a trailing param could be misinterpreted.
                    out.push(':');
                }
                out.push_str(param);
            }
        }

        out
    }
}

impl fmt::Display for Message {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_wire())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    // ── Parsing basics ───────────────────────────────────────────

    #[test]
    fn parse_simple_command() {
        let msg = Message::parse("QUIT").unwrap();
        assert_eq!(msg.prefix, None);
        assert_eq!(msg.command, "QUIT");
        assert_eq!(msg.params, Vec::<String>::new());
    }

    #[test]
    fn parse_command_with_one_param() {
        let msg = Message::parse("NICK wings").unwrap();
        assert_eq!(msg.command, "NICK");
        assert_eq!(msg.params, vec!["wings"]);
    }

    #[test]
    fn parse_command_with_trailing() {
        let msg = Message::parse("PRIVMSG #lagoon :Hello everyone!").unwrap();
        assert_eq!(msg.command, "PRIVMSG");
        assert_eq!(msg.params, vec!["#lagoon", "Hello everyone!"]);
    }

    #[test]
    fn parse_with_prefix() {
        let msg = Message::parse(":wings!user@host PRIVMSG #lagoon :hey friends").unwrap();
        assert_eq!(msg.prefix.as_deref(), Some("wings!user@host"));
        assert_eq!(msg.command, "PRIVMSG");
        assert_eq!(msg.params, vec!["#lagoon", "hey friends"]);
    }

    #[test]
    fn parse_numeric_reply() {
        let msg = Message::parse(":server.lagun.co 001 wings :Welcome to Lagun").unwrap();
        assert_eq!(msg.prefix.as_deref(), Some("server.lagun.co"));
        assert_eq!(msg.command, "001");
        assert_eq!(msg.params, vec!["wings", "Welcome to Lagun"]);
    }

    #[test]
    fn parse_user_command() {
        let msg = Message::parse("USER wings 0 * :Wings").unwrap();
        assert_eq!(msg.command, "USER");
        assert_eq!(msg.params, vec!["wings", "0", "*", "Wings"]);
    }

    #[test]
    fn parse_ping() {
        let msg = Message::parse("PING :server.lagun.co").unwrap();
        assert_eq!(msg.command, "PING");
        assert_eq!(msg.params, vec!["server.lagun.co"]);
    }

    #[test]
    fn parse_join() {
        let msg = Message::parse("JOIN #lagoon").unwrap();
        assert_eq!(msg.command, "JOIN");
        assert_eq!(msg.params, vec!["#lagoon"]);
    }

    #[test]
    fn parse_strips_crlf() {
        let msg = Message::parse("PING :server\r\n").unwrap();
        assert_eq!(msg.command, "PING");
        assert_eq!(msg.params, vec!["server"]);
    }

    // ── Parsing edge cases ───────────────────────────────────────

    #[test]
    fn parse_trailing_empty_string() {
        let msg = Message::parse("TOPIC #lagoon :").unwrap();
        assert_eq!(msg.params, vec!["#lagoon", ""]);
    }

    #[test]
    fn parse_trailing_starts_with_colon() {
        let msg = Message::parse("PRIVMSG #lagoon ::)").unwrap();
        assert_eq!(msg.params, vec!["#lagoon", ":)"]);
    }

    #[test]
    fn parse_multiple_middle_params() {
        let msg = Message::parse("MODE #lagoon +o wings").unwrap();
        assert_eq!(msg.command, "MODE");
        assert_eq!(msg.params, vec!["#lagoon", "+o", "wings"]);
    }

    // ── Parse errors ─────────────────────────────────────────────

    #[test]
    fn parse_empty_input() {
        assert_eq!(Message::parse(""), Err(ParseError::Empty));
    }

    #[test]
    fn parse_prefix_only() {
        assert_eq!(
            Message::parse(":prefix_only"),
            Err(ParseError::MissingCommand)
        );
    }

    // ── Serialization ────────────────────────────────────────────

    #[test]
    fn serialize_simple() {
        let msg = Message {
            prefix: None,
            command: "QUIT".into(),
            params: vec![],
        };
        assert_eq!(msg.to_wire(), "QUIT");
    }

    #[test]
    fn serialize_with_trailing() {
        let msg = Message {
            prefix: None,
            command: "PRIVMSG".into(),
            params: vec!["#lagoon".into(), "Hello everyone!".into()],
        };
        assert_eq!(msg.to_wire(), "PRIVMSG #lagoon :Hello everyone!");
    }

    #[test]
    fn serialize_with_prefix() {
        let msg = Message {
            prefix: Some("wings!user@host".into()),
            command: "PRIVMSG".into(),
            params: vec!["#lagoon".into(), "hey".into()],
        };
        assert_eq!(msg.to_wire(), ":wings!user@host PRIVMSG #lagoon :hey");
    }

    #[test]
    fn serialize_empty_trailing() {
        let msg = Message {
            prefix: None,
            command: "TOPIC".into(),
            params: vec!["#lagoon".into(), "".into()],
        };
        assert_eq!(msg.to_wire(), "TOPIC #lagoon :");
    }

    // ── Roundtrip ────────────────────────────────────────────────

    #[test]
    fn roundtrip_simple() {
        // Serializer always uses `:` on last param; both forms are valid IRC.
        let msg = Message::parse("NICK wings").unwrap();
        assert_eq!(msg.to_wire(), "NICK :wings");
        // Verify semantic roundtrip: parse the serialized form back.
        let reparsed = Message::parse(&msg.to_wire()).unwrap();
        assert_eq!(msg, reparsed);
    }

    #[test]
    fn roundtrip_with_prefix_and_trailing() {
        let input = ":wings!user@host PRIVMSG #lagoon :Hello everyone!";
        let msg = Message::parse(input).unwrap();
        assert_eq!(msg.to_wire(), input);
    }

    #[test]
    fn roundtrip_numeric() {
        let input = ":server.lagun.co 001 wings :Welcome to Lagun";
        let msg = Message::parse(input).unwrap();
        assert_eq!(msg.to_wire(), input);
    }

    #[test]
    fn roundtrip_ping() {
        let input = "PING :server.lagun.co";
        let msg = Message::parse(input).unwrap();
        assert_eq!(msg.to_wire(), input);
    }

    #[test]
    fn roundtrip_mode() {
        // Serializer always uses `:` on last param; both forms are valid IRC.
        let msg = Message::parse("MODE #lagoon +o wings").unwrap();
        assert_eq!(msg.to_wire(), "MODE #lagoon +o :wings");
        let reparsed = Message::parse(&msg.to_wire()).unwrap();
        assert_eq!(msg, reparsed);
    }

    #[test]
    fn roundtrip_user() {
        let input = "USER wings 0 * :Wings";
        let msg = Message::parse(input).unwrap();
        assert_eq!(msg.to_wire(), input);
    }
}
