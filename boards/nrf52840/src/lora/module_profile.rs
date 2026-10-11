use sx126x::op::tcxo::{TcxoDelay, TcxoVoltage};

#[allow(dead_code)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Sx1262ModuleProfile {
    HtRa62,
    EbyteE22 { use_tcxo: bool },
    EbyteE22p,
}

impl Sx1262ModuleProfile {
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
