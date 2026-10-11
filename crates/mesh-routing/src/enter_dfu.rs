pub const ENTER_DFU_TEXT: &[u8] = b"ENTER DFU";

pub const DFU_CONFIRM_TEXT: &[u8] = b"Entering DFU";

pub const DFU_ENTER_DELAY_SECS: i32 = 2;

fn is_ascii_ws(b: u8) -> bool {
    b == b' ' || b == b'\t' || b == b'\n' || b == b'\r'
}

pub fn payload_is_enter_dfu(payload: &[u8]) -> bool {
    let start = payload
        .iter()
        .position(|&b| !is_ascii_ws(b))
        .unwrap_or(payload.len());
    let end = payload
        .iter()
        .rposition(|&b| !is_ascii_ws(b))
        .map(|i| i + 1)
        .unwrap_or(0);
    if start >= end {
        return false;
    }
    &payload[start..end] == ENTER_DFU_TEXT
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_match() {
        assert!(payload_is_enter_dfu(b"ENTER DFU"));
    }

    #[test]
    fn trims_whitespace() {
        assert!(payload_is_enter_dfu(b"  ENTER DFU\n"));
        assert!(payload_is_enter_dfu(b"\tENTER DFU\r\n"));
    }

    #[test]
    fn rejects_embedded_and_wrong_case() {
        assert!(!payload_is_enter_dfu(b"please ENTER DFU now"));
        assert!(!payload_is_enter_dfu(b"enter dfu"));
        assert!(!payload_is_enter_dfu(b"ENTERDFU"));
        assert!(!payload_is_enter_dfu(b""));
        assert!(!payload_is_enter_dfu(b"   "));
    }
}
