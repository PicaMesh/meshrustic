/// Returns true when the packet appears to have been sent directly by `from`
/// (not relayed by a third party). See SR direct-neighbor rules in the implementation plan.
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
