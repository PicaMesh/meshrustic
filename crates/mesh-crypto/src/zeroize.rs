//! Overwrite a buffer so that the key material in it does not outlive its use.

/// Zero a buffer.
///
/// A plain `fill(0)` is a store the optimiser is free to delete: the buffer is
/// usually dead by the time it is cleared, and with LTO and a size-optimised
/// profile the store is very likely to disappear. A volatile write is not
/// removable, and the fence keeps the writes from being reordered past the
/// end of the buffer's lifetime.
pub fn zeroize(buf: &mut [u8]) {
    for byte in buf.iter_mut() {
        // SAFETY: the pointer comes from a live, uniquely borrowed slice
        // element, and the write is volatile so it happens exactly once.
        unsafe { core::ptr::write_volatile(byte, 0) };
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_buffer_is_cleared() {
        let mut buf = [0xAAu8; 8];
        zeroize(&mut buf);
        assert_eq!(buf, [0; 8]);
    }

    #[test]
    fn an_empty_buffer_is_accepted() {
        let mut buf: [u8; 0] = [];
        zeroize(&mut buf);
    }
}
