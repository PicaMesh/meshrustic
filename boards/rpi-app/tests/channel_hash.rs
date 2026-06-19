//! Primary channel hash golden vectors for modem presets.

use mesh_crypto::{channel_hash, DEFAULT_PSK};
use mesh_radio::{
    modem_preset_channel_name, primary_channel_hash, MODEM_LONG_FAST, MODEM_LONG_MODERATE,
    MODEM_LONG_SLOW, MODEM_LONG_TURBO, MODEM_MEDIUM_FAST, MODEM_MEDIUM_SLOW, MODEM_SHORT_FAST,
    MODEM_SHORT_SLOW, MODEM_SHORT_TURBO,
};

#[test]
fn preset_display_names_golden() {
    assert_eq!(modem_preset_channel_name(MODEM_LONG_FAST), "LongFast");
    assert_eq!(modem_preset_channel_name(MODEM_SHORT_SLOW), "ShortSlow");
    assert_eq!(modem_preset_channel_name(MODEM_SHORT_FAST), "ShortFast");
    assert_eq!(modem_preset_channel_name(MODEM_MEDIUM_FAST), "MediumFast");
    assert_eq!(modem_preset_channel_name(MODEM_MEDIUM_SLOW), "MediumSlow");
    assert_eq!(modem_preset_channel_name(MODEM_LONG_SLOW), "LongSlow");
    assert_eq!(modem_preset_channel_name(MODEM_LONG_MODERATE), "LongMod");
    assert_eq!(modem_preset_channel_name(MODEM_SHORT_TURBO), "ShortTurbo");
    assert_eq!(modem_preset_channel_name(MODEM_LONG_TURBO), "LongTurbo");
}

#[test]
fn empty_stored_name_hashes_preset_name_not_empty_string() {
    assert_eq!(
        primary_channel_hash("", MODEM_SHORT_SLOW, true, &DEFAULT_PSK),
        channel_hash("ShortSlow", &DEFAULT_PSK)
    );
    assert_ne!(
        primary_channel_hash("", MODEM_SHORT_SLOW, true, &DEFAULT_PSK),
        channel_hash("", &DEFAULT_PSK)
    );
}

#[test]
fn preset_hashes_golden_vectors() {
    assert_eq!(primary_channel_hash("", MODEM_LONG_FAST, true, &DEFAULT_PSK), 0x08);
    assert_eq!(primary_channel_hash("", MODEM_SHORT_SLOW, true, &DEFAULT_PSK), 0x77);
    assert_eq!(primary_channel_hash("", MODEM_SHORT_FAST, true, &DEFAULT_PSK), 0x70);
    assert_eq!(primary_channel_hash("", MODEM_MEDIUM_FAST, true, &DEFAULT_PSK), 0x1f);
    assert_eq!(primary_channel_hash("", MODEM_MEDIUM_SLOW, true, &DEFAULT_PSK), 0x18);
    assert_eq!(primary_channel_hash("", MODEM_LONG_SLOW, true, &DEFAULT_PSK), 0x0f);
    assert_eq!(primary_channel_hash("", MODEM_LONG_MODERATE, true, &DEFAULT_PSK), 0x6e);
    assert_eq!(primary_channel_hash("", MODEM_SHORT_TURBO, true, &DEFAULT_PSK), 0x0e);
    assert_eq!(primary_channel_hash("", MODEM_LONG_TURBO, true, &DEFAULT_PSK), 0x76);
}

#[test]
fn router_default_matches_short_slow_preset() {
    use mesh_routing::Router;
    use static_cell::StaticCell;

    static ROUTER: StaticCell<Router> = StaticCell::new();
    let router = ROUTER.init(Router::new(0x1234_5678));
    assert_eq!(
        router.channel_hash(),
        primary_channel_hash("", MODEM_SHORT_SLOW, true, &DEFAULT_PSK)
    );
}
