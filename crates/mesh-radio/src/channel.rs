//! Primary channel hash from stored name and modem preset.

use mesh_crypto::channel_hash;

use crate::config::modem_preset_channel_name;

/// Primary channel hash: xor(name) ^ xor(PSK), with empty name → preset display name.
pub fn primary_channel_hash(
    stored_name: &str,
    modem_preset: u8,
    use_preset: bool,
    psk: &[u8],
) -> u8 {
    if !stored_name.is_empty() {
        return channel_hash(stored_name, psk);
    }
    let name = if use_preset {
        modem_preset_channel_name(modem_preset)
    } else {
        "Custom"
    };
    channel_hash(name, psk)
}

#[cfg(test)]
mod tests {
    use super::*;
    use mesh_crypto::DEFAULT_PSK;

    use crate::config::{
        MODEM_LONG_FAST, MODEM_MEDIUM_FAST, MODEM_SHORT_FAST, MODEM_SHORT_SLOW,
    };

    #[test]
    fn empty_name_uses_preset_display_name() {
        assert_eq!(
            primary_channel_hash("", MODEM_SHORT_SLOW, true, &DEFAULT_PSK),
            0x77
        );
        assert_eq!(
            primary_channel_hash("", MODEM_LONG_FAST, true, &DEFAULT_PSK),
            0x08
        );
        assert_eq!(
            primary_channel_hash("", MODEM_SHORT_FAST, true, &DEFAULT_PSK),
            0x70
        );
        assert_eq!(
            primary_channel_hash("", MODEM_MEDIUM_FAST, true, &DEFAULT_PSK),
            0x1f
        );
    }

    #[test]
    fn explicit_name_overrides_preset() {
        assert_eq!(
            primary_channel_hash("MyPrivate", MODEM_SHORT_SLOW, true, &DEFAULT_PSK),
            channel_hash("MyPrivate", &DEFAULT_PSK)
        );
    }

    #[test]
    fn custom_modem_without_preset_uses_custom_name() {
        assert_eq!(
            primary_channel_hash("", MODEM_SHORT_SLOW, false, &DEFAULT_PSK),
            channel_hash("Custom", &DEFAULT_PSK)
        );
    }
}
