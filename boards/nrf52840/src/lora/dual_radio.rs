use mesh_radio::{RadioId, MAX_RADIOS};

pub const SECOND_RADIO_ID: RadioId = 1;

pub const fn bridge_target_capacity() -> usize {
    mesh_radio::MAX_BRIDGE_TARGETS
}

const _: () = assert!(MAX_RADIOS >= 2);
const _: () = assert!(SECOND_RADIO_ID < MAX_RADIOS as RadioId);
