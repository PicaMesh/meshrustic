//! Host-typed command input over the USB debug link (Part C of the H1 controlled-node harness).
//!
//! Lets an operator make this node *originate* a frame -- controlling exactly which node is
//! direct, which passive capture cannot arrange on its own. Two commands only: a broadcast text
//! and a unicast text to a node id, one per ASCII line. Parsing writes into fixed-capacity
//! buffers only; there is no heap here and none is added. The parsed command is handed to
//! `Router::send_local` by the board's radio task, through the same channel-access gate every
//! other originated frame already goes through -- nothing here talks to the radio directly.
//!
//! See `tmp/controlled-node-harness-plan-20260911.md` (MeshRustic repo) for the design this
//! implements, including why this parser lives next to `Router::send_local` rather than in
//! `mesh-protocol` (its sole consumer is that one function) and why the line accumulator resets
//! on every new USB connection.

use crate::pool::MAX_PACKET_PAYLOAD;
use heapless::Vec;

/// Longest message text a command may carry: the same ceiling `Router::send_local`'s own
/// payload has, so a command can never ask for more than the wire format allows.
pub const MAX_COMMAND_TEXT: usize = MAX_PACKET_PAYLOAD;

/// Longest raw line the grammar can ever produce: a keyword, a hex node id, the separating
/// spaces, and the text, rounded up generously. A line longer than this is rejected outright
/// (see `LineAccumulator`), not truncated and guessed at.
pub const MAX_COMMAND_LINE: usize = MAX_COMMAND_TEXT + 32;

/// A fully parsed host command, ready for `Router::send_local`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostCommand {
    /// `BCAST <text>` -- broadcast `text` on the primary channel.
    Broadcast { text: Vec<u8, MAX_COMMAND_TEXT> },
    /// `UNI <node-id> <text>` -- unicast `text` to `to`.
    Unicast {
        to: u32,
        text: Vec<u8, MAX_COMMAND_TEXT>,
    },
}

/// Why a line was rejected. Every rejection is logged with its specific reason, never silently
/// dropped and never guessed at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommandError {
    /// The raw line exceeded `MAX_COMMAND_LINE` before a newline was seen.
    LineTooLong,
    /// The line matched neither `BCAST` nor `UNI`.
    UnknownKeyword,
    /// `UNI` was given with no node id token.
    MissingNodeId,
    /// The node id token was not a valid hex node id.
    MalformedNodeId,
    /// The message text (after the keyword and, for `UNI`, the node id) was empty.
    EmptyMessage,
}

const KEYWORD_BCAST: &[u8] = b"BCAST";
const KEYWORD_UNI: &[u8] = b"UNI";

fn is_ascii_space(b: u8) -> bool {
    b == b' ' || b == b'\t'
}

fn trim(mut bytes: &[u8]) -> &[u8] {
    while let [first, rest @ ..] = bytes {
        if is_ascii_space(*first) {
            bytes = rest;
        } else {
            break;
        }
    }
    while let [rest @ .., last] = bytes {
        if is_ascii_space(*last) {
            bytes = rest;
        } else {
            break;
        }
    }
    bytes
}

/// If `line` starts with `keyword` followed by whitespace or end-of-line, return what follows
/// the keyword (not yet trimmed). Case-sensitive: the grammar is a fixed, upper-case keyword.
fn strip_keyword<'a>(line: &'a [u8], keyword: &[u8]) -> Option<&'a [u8]> {
    let rest = line.strip_prefix(keyword)?;
    match rest.first() {
        None => Some(rest),
        Some(&b) if is_ascii_space(b) => Some(rest),
        _ => None, // e.g. "BCASTX ..." must not match "BCAST"
    }
}

/// Split on the first run of whitespace: `(first word, the rest, trimmed)`.
fn split_first_word(bytes: &[u8]) -> (&[u8], &[u8]) {
    let bytes = trim(bytes);
    match bytes.iter().position(|&b| is_ascii_space(b)) {
        Some(i) => (&bytes[..i], trim(&bytes[i + 1..])),
        None => (bytes, &[]),
    }
}

/// Parse a node id written the same way the rest of the firmware logs one: optional leading
/// `!` or `0x`/`0X`, then 1-8 hex digits.
fn parse_hex_node_id(token: &[u8]) -> Option<u32> {
    let token = token
        .strip_prefix(b"!")
        .or_else(|| token.strip_prefix(b"0x"))
        .or_else(|| token.strip_prefix(b"0X"))
        .unwrap_or(token);
    if token.is_empty() || token.len() > 8 {
        return None;
    }
    let mut value: u32 = 0;
    for &b in token {
        let digit = match b {
            b'0'..=b'9' => b - b'0',
            b'a'..=b'f' => b - b'a' + 10,
            b'A'..=b'F' => b - b'A' + 10,
            _ => return None,
        };
        value = (value << 4) | u32::from(digit);
    }
    Some(value)
}

fn to_fixed_text(bytes: &[u8]) -> Result<Vec<u8, MAX_COMMAND_TEXT>, CommandError> {
    let mut out = Vec::new();
    out.extend_from_slice(bytes).map_err(|()| CommandError::LineTooLong)?;
    Ok(out)
}

/// Parse one complete line (no trailing newline/CR -- `LineAccumulator` strips those) into a
/// command. Rejects, with a specific reason, anything that does not match either grammar.
pub fn parse_line(line: &[u8]) -> Result<HostCommand, CommandError> {
    if line.len() > MAX_COMMAND_LINE {
        return Err(CommandError::LineTooLong);
    }
    let line = trim(line);
    if let Some(rest) = strip_keyword(line, KEYWORD_BCAST) {
        let text = trim(rest);
        if text.is_empty() {
            return Err(CommandError::EmptyMessage);
        }
        return Ok(HostCommand::Broadcast {
            text: to_fixed_text(text)?,
        });
    }
    if let Some(rest) = strip_keyword(line, KEYWORD_UNI) {
        let (id_token, text) = split_first_word(rest);
        if id_token.is_empty() {
            return Err(CommandError::MissingNodeId);
        }
        let to = parse_hex_node_id(id_token).ok_or(CommandError::MalformedNodeId)?;
        if text.is_empty() {
            return Err(CommandError::EmptyMessage);
        }
        return Ok(HostCommand::Unicast {
            to,
            text: to_fixed_text(text)?,
        });
    }
    Err(CommandError::UnknownKeyword)
}

/// Assembles raw USB bytes into complete lines with no heap, across as many reads as it takes
/// to see a newline. Must be reset on every new connection (see the board's USB read loop): a
/// line left partial by a host disconnecting mid-command must never be silently completed by
/// bytes from the next session.
pub struct LineAccumulator<const CAP: usize> {
    buf: Vec<u8, CAP>,
    overflowed: bool,
}

impl<const CAP: usize> LineAccumulator<CAP> {
    pub const fn new() -> Self {
        Self {
            buf: Vec::new(),
            overflowed: false,
        }
    }

    /// Discard whatever partial line is in progress. Call this on every new connection.
    pub fn reset(&mut self) {
        self.buf.clear();
        self.overflowed = false;
    }

    /// Feed one byte. Returns `Some` once `b` completes a line (on `\n`; a preceding `\r` is
    /// dropped): `Ok(bytes)` if the line fit, `Err(LineTooLong)` if it did not -- the buffer is
    /// cleared either way, so accumulation resumes cleanly on the very next byte.
    pub fn push_byte(&mut self, b: u8) -> Option<Result<Vec<u8, CAP>, CommandError>> {
        if b == b'\n' {
            let result = if self.overflowed {
                Err(CommandError::LineTooLong)
            } else {
                Ok(self.buf.clone())
            };
            self.buf.clear();
            self.overflowed = false;
            return Some(result);
        }
        if b != b'\r' && self.buf.push(b).is_err() {
            self.overflowed = true;
        }
        None
    }
}

impl<const CAP: usize> Default for LineAccumulator<CAP> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cmd(line: &str) -> Result<HostCommand, CommandError> {
        parse_line(line.as_bytes())
    }

    #[test]
    fn valid_broadcast() {
        match cmd("BCAST hello mesh").unwrap() {
            HostCommand::Broadcast { text } => assert_eq!(&text[..], b"hello mesh"),
            _ => panic!("expected Broadcast"),
        }
    }

    #[test]
    fn valid_unicast_bang_prefix() {
        match cmd("UNI !046b553a ack-pass probe").unwrap() {
            HostCommand::Unicast { to, text } => {
                assert_eq!(to, 0x046b553a);
                assert_eq!(&text[..], b"ack-pass probe");
            }
            _ => panic!("expected Unicast"),
        }
    }

    #[test]
    fn valid_unicast_bare_hex() {
        match cmd("UNI bdacce55 hi").unwrap() {
            HostCommand::Unicast { to, text } => {
                assert_eq!(to, 0xbdacce55);
                assert_eq!(&text[..], b"hi");
            }
            _ => panic!("expected Unicast"),
        }
    }

    #[test]
    fn over_long_line_is_rejected() {
        let mut line = alloc_free_repeat(b'x', MAX_COMMAND_LINE + 1);
        line[..6].copy_from_slice(b"BCAST ");
        assert_eq!(parse_line(&line), Err(CommandError::LineTooLong));
    }

    fn alloc_free_repeat(byte: u8, n: usize) -> heapless::Vec<u8, { MAX_COMMAND_LINE + 64 }> {
        let mut v = heapless::Vec::new();
        for _ in 0..n {
            v.push(byte).unwrap();
        }
        v
    }

    #[test]
    fn malformed_node_id_is_rejected() {
        assert_eq!(cmd("UNI not-hex hello"), Err(CommandError::MalformedNodeId));
    }

    #[test]
    fn missing_node_id_is_rejected() {
        assert_eq!(cmd("UNI"), Err(CommandError::MissingNodeId));
        assert_eq!(cmd("UNI    "), Err(CommandError::MissingNodeId));
    }

    #[test]
    fn empty_broadcast_message_is_rejected() {
        assert_eq!(cmd("BCAST"), Err(CommandError::EmptyMessage));
        assert_eq!(cmd("BCAST    "), Err(CommandError::EmptyMessage));
    }

    #[test]
    fn empty_unicast_message_is_rejected() {
        assert_eq!(cmd("UNI 046b553a"), Err(CommandError::EmptyMessage));
        assert_eq!(cmd("UNI 046b553a   "), Err(CommandError::EmptyMessage));
    }

    #[test]
    fn unknown_keyword_is_rejected() {
        assert_eq!(cmd("FOO bar"), Err(CommandError::UnknownKeyword));
        assert_eq!(cmd("BCASTX hi"), Err(CommandError::UnknownKeyword));
    }

    #[test]
    fn line_accumulator_assembles_across_feeds() {
        let mut acc: LineAccumulator<64> = LineAccumulator::new();
        assert!(acc.push_byte(b'B').is_none());
        assert!(acc.push_byte(b'C').is_none());
        for &b in b"AST hi" {
            assert!(acc.push_byte(b).is_none());
        }
        let line = acc.push_byte(b'\n').unwrap().unwrap();
        assert_eq!(&line[..], b"BCAST hi");
    }

    #[test]
    fn line_accumulator_strips_trailing_cr() {
        let mut acc: LineAccumulator<64> = LineAccumulator::new();
        for &b in b"BCAST hi\r" {
            assert!(acc.push_byte(b).is_none());
        }
        let line = acc.push_byte(b'\n').unwrap().unwrap();
        assert_eq!(&line[..], b"BCAST hi");
    }

    #[test]
    fn line_accumulator_rejects_over_long_line_and_recovers() {
        let mut acc: LineAccumulator<8> = LineAccumulator::new();
        for &b in b"0123456789" {
            assert!(acc.push_byte(b).is_none());
        }
        assert_eq!(acc.push_byte(b'\n'), Some(Err(CommandError::LineTooLong)));
        // The accumulator must be clean for the very next line.
        for &b in b"BCAST hi" {
            assert!(acc.push_byte(b).is_none());
        }
        let line = acc.push_byte(b'\n').unwrap().unwrap();
        assert_eq!(&line[..], b"BCAST hi");
    }

    #[test]
    fn line_accumulator_reset_drops_partial_line_across_a_reconnect() {
        let mut acc: LineAccumulator<64> = LineAccumulator::new();
        // A line left partial by a disconnect: never terminated with '\n'.
        for &b in b"BCAST partial-comm-and-abandoned" {
            assert!(acc.push_byte(b).is_none());
        }
        // Host disconnects mid-line; the board's read loop resets on the next connection.
        acc.reset();
        // The next session's first command must be exactly its own bytes -- none of the
        // abandoned partial line from before the reset.
        for &b in b"BCAST fresh command" {
            assert!(acc.push_byte(b).is_none());
        }
        let line = acc.push_byte(b'\n').unwrap().unwrap();
        assert_eq!(&line[..], b"BCAST fresh command");
    }
}
