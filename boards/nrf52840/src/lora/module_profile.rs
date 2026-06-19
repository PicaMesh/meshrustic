//! SX1262 module SKU profiles (chip is shared; wiring and TCXO/RF-switch differ).
//!
//! HT-RA62 / SX1262 module profiles (TCXO, RF switch, and power quirks).

use sx126x::op::tcxo::{TcxoDelay, TcxoVoltage};

/// Module-specific SX1262 init parameters.
#[allow(dead_code)] // EbyteE22 / EbyteE22p wired when those modules are tested on a board.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Sx1262ModuleProfile {
    /// Heltec HT-RA62 — TCXO @ 1.8 V, internal DIO2 RF switch.
    HtRa62,
    /// Ebyte E22 (SX1262) — external RF switch; TCXO depends on SKU.
    EbyteE22 { use_tcxo: bool },
    /// Ebyte E22P — external RF switch; `POWER_EN` path (no MCU RXEN).
    EbyteE22p,
}

impl Sx1262ModuleProfile {
    /// Default profile for `nrf52_promicro_diy_tcxo` with Heltec HT-RA62.
    pub const fn default_board() -> Self {
        Self::HtRa62
    }

    pub const fn name(self) -> &'static str {
        match self {
            Self::HtRa62 => "HT-RA62",
            Self::EbyteE22 { .. } => "Ebyte-E22",
            Self::EbyteE22p => "Ebyte-E22P",
        }
    }

    /// Enable Semtech DIO2 as internal TX/RX RF switch (HT-RA62 path).
    pub const fn dio2_rf_switch(self) -> bool {
        match self {
            Self::HtRa62 => true,
            Self::EbyteE22 { .. } | Self::EbyteE22p => false,
        }
    }

    pub const fn tcxo_opts(self) -> Option<(TcxoVoltage, TcxoDelay)> {
        match self {
            Self::HtRa62 => Some((TcxoVoltage::Volt1_8, TcxoDelay::from_ms(5))),
            Self::EbyteE22 { use_tcxo: true } => {
                Some((TcxoVoltage::Volt1_8, TcxoDelay::from_ms(5)))
            }
            Self::EbyteE22 { use_tcxo: false } => None,
            Self::EbyteE22p => Some((TcxoVoltage::Volt1_8, TcxoDelay::from_ms(5))),
        }
    }
}
