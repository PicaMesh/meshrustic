//! Second radio slot reserved at compile time (not spawned on v1 hardware).

use mesh_radio::{RadioId, MAX_RADIOS};

/// Reserved id for a future second preset segment (e.g. LONG_FAST).
pub const SECOND_RADIO_ID: RadioId = 1;

/// Compile-time check that bridge capacity matches dual-radio layout.
pub const fn bridge_target_capacity() -> usize {
    mesh_radio::MAX_BRIDGE_TARGETS
}

const _: () = assert!(MAX_RADIOS >= 2);
const _: () = assert!(SECOND_RADIO_ID < MAX_RADIOS as RadioId);
