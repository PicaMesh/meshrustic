/// Returns true when the packet appears to have been sent directly by `from`
/// (not relayed by a third party).
///
/// Signal-routing direct-neighbor rule: `hop_start == hop_limit` (hop budget not
/// consumed) and `relay_node` is zero or matches the originator low byte.
pub fn is_direct_packet(from: u32, hop_start: u8, hop_limit: u8, relay_node: u8) -> bool {
    if hop_start != hop_limit {
        return false;
    }
    let from_low = (from & 0xFF) as u8;
    if relay_node != 0 && relay_node != from_low {
        return false;
    }
    true
}
