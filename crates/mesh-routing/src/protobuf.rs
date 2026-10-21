pub(crate) fn read_varint64(data: &[u8], mut idx: usize) -> Option<(u64, usize)> {
    let mut value = 0u64;
    for shift in (0..=63).step_by(7) {
        let byte = *data.get(idx)?;
        idx += 1;
        if shift == 63 && byte > 1 {
            return None;
        }
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Some((value, idx));
        }
    }
    None
}

pub(crate) fn read_varint(data: &[u8], idx: usize) -> Option<(u32, usize)> {
    let (value, end) = read_varint64(data, idx)?;
    Some((u32::try_from(value).ok()?, end))
}

/// Read a signed 32-bit varint.
///
/// Protobuf encodes a negative `int32` as a ten-byte varint that carries the
/// sign-extended 64-bit value, so the value has to be read as a 64-bit varint
/// and truncated afterwards. Reading it as a 32-bit varint rejects the
/// canonical encoding of every negative number.
pub(crate) fn read_varint_i32(data: &[u8], idx: usize) -> Option<(i32, usize)> {
    let (value, end) = read_varint64(data, idx)?;
    Some((value as u32 as i32, end))
}

pub(crate) fn skip_field(data: &[u8], idx: usize, wire: u8) -> Option<usize> {
    let end = match wire {
        0 => read_varint64(data, idx)?.1,
        1 => idx.checked_add(8)?,
        2 => {
            let (len, start) = read_varint(data, idx)?;
            start.checked_add(len as usize)?
        }
        5 => idx.checked_add(4)?,
        _ => return None,
    };
    (end <= data.len()).then_some(end)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn overflowing_and_truncated_fields_are_rejected() {
        assert_eq!(read_varint(&[0xff, 0xff, 0xff, 0xff, 0x1f], 0), None);
        assert_eq!(read_varint64(&[0xff; 10], 0), None);
        assert_eq!(skip_field(&[0; 3], 0, 5), None);
        assert_eq!(skip_field(&[0; 7], 0, 1), None);
        assert_eq!(skip_field(&[0xff, 0xff, 0xff, 0xff, 0x0f], 0, 2), None);
        assert_eq!(
            read_varint(&[0xff, 0xff, 0xff, 0xff, 0x0f], 0),
            Some((u32::MAX, 5))
        );
    }
}
