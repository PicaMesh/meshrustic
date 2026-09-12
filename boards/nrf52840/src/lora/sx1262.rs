//! SX1262 driver — chip-level backend with per-module profiles.

use embassy_nrf::gpio::{Input, Output};
use embassy_nrf::spim::Spim;
use embedded_hal_bus::spi::ExclusiveDevice;
use mesh_protocol::PacketHeader;
use mesh_radio::{
    packet_time_ms, sync_word_sx126x, RadioConfig, RadioError, RadioId, RadioInterface, RxFrame,
    TxFrame, MAX_LORA_PAYLOAD,
};
use sx126x::conf::Config;
use sx126x::op::calib::CalibParam;
use sx126x::op::irq::{IrqMask, IrqMaskBit, IrqStatus};
use sx126x::op::modulation::{
    LoRaBandWidth, LoRaSpreadFactor, LoraCodingRate, LoraModParams, ModParams,
};
use sx126x::op::packet::{
    LoRaCrcType, LoRaHeaderType, LoRaInvertIq, LoRaPacketParams, PacketParams, PacketType,
};
use sx126x::op::rxtx::{PaConfig, RampTime, RxTxTimeout, TxParams};
use sx126x::op::status::ChipMode;
use sx126x::reg::Register;
use sx126x::{calc_rf_freq, SX126x};

/// SX1262 high-power PA for up to +22 dBm (Semtech datasheet §13.1.14).
const SX1262_PA_DUTY_CYCLE: u8 = 0x04;
const SX1262_PA_HP_MAX: u8 = 0x07;
/// Over-current protection for SX1262 HP TX (140 mA).
const SX1262_OCP_140MA: u8 = 0x38;

use super::module_profile::Sx1262ModuleProfile;
use super::pins::LoRaPins;

type SpiDev = ExclusiveDevice<
    Spim<'static, embassy_nrf::peripherals::SPI3>,
    Output<'static>,
    embassy_time::Delay,
>;

type RadioChip = SX126x<SpiDev, Output<'static>, Input<'static>, Output<'static>, Input<'static>>;

pub struct Sx1262Driver {
    id: RadioId,
    profile: Sx1262ModuleProfile,
    config: RadioConfig,
    chip: RadioChip,
    /// Result of the boot-time BUSY probe (see [`probe_module_ready`]).
    module_ready: bool,
    /// When the current reception (preamble/sync/header seen, no RxDone yet) was first noticed.
    rx_active_since: Option<embassy_time::Instant>,
}

impl Sx1262Driver {
    pub fn new(
        id: RadioId,
        profile: Sx1262ModuleProfile,
        chip: RadioChip,
        module_ready: bool,
    ) -> Self {
        Self {
            id,
            profile,
            config: RadioConfig::eu868_default(),
            chip,
            module_ready,
            rx_active_since: None,
        }
    }

    /// Reception-in-progress flags: the modem has seen a preamble, sync word or header of a
    /// frame that has not finished yet. Mirrors Meshtastic `isActivelyReceiving`.
    fn irq_rx_active(irq: IrqStatus) -> bool {
        irq.preamble_detected() || irq.syncword_valid() || irq.header_valid()
    }

    /// Longest a genuine reception can stay in progress: preamble plus the largest frame.
    fn max_rx_in_progress(&self) -> embassy_time::Duration {
        let ms = packet_time_ms(&self.config, MAX_LORA_PAYLOAD, true) as u64;
        embassy_time::Duration::from_millis(ms.saturating_mul(2))
    }

    /// Set LoRa modem parameters before [`RadioInterface::init`].
    pub fn set_radio_config(&mut self, config: RadioConfig) {
        self.config = config;
    }

    pub fn profile(&self) -> Sx1262ModuleProfile {
        self.profile
    }

    fn lora_bandwidth(bw_khz: f32) -> LoRaBandWidth {
        match bw_khz as u32 {
            125 => LoRaBandWidth::BW125,
            250 => LoRaBandWidth::BW250,
            500 => LoRaBandWidth::BW500,
            _ => LoRaBandWidth::BW250,
        }
    }

    fn lora_coding_rate(cr: u8) -> LoraCodingRate {
        match cr {
            6 => LoraCodingRate::CR4_6,
            7 => LoraCodingRate::CR4_7,
            8 => LoraCodingRate::CR4_8,
            _ => LoraCodingRate::CR4_5,
        }
    }

    fn sx1262_pa_config() -> PaConfig {
        PaConfig::default()
            .set_pa_duty_cycle(SX1262_PA_DUTY_CYCLE)
            .set_hp_max(SX1262_PA_HP_MAX)
    }

    fn configure_ocp(&mut self) -> Result<(), RadioError> {
        self.chip
            .write_register(Register::OcpConfiguration, &[SX1262_OCP_140MA])
            .map_err(|_| RadioError::Hardware)
    }

    fn sx126x_config(profile: Sx1262ModuleProfile, radio: &RadioConfig) -> Config {
        let mod_params: ModParams = LoraModParams::default()
            .set_spread_factor(LoRaSpreadFactor::from(radio.spreading_factor))
            .set_bandwidth(Self::lora_bandwidth(radio.bandwidth_khz))
            .set_coding_rate(Self::lora_coding_rate(radio.coding_rate))
            .into();

        let packet_params: PacketParams = LoRaPacketParams {
            preamble_len: radio.preamble_length,
            header_type: LoRaHeaderType::VarLen,
            payload_len: 255,
            crc_type: LoRaCrcType::CrcOn,
            invert_iq: LoRaInvertIq::Standard,
        }
        .into();

        let irq = IrqMask::none()
            .combine(IrqMaskBit::RxDone)
            .combine(IrqMaskBit::TxDone)
            .combine(IrqMaskBit::PreambleDetected)
            .combine(IrqMaskBit::SyncwordValid)
            .combine(IrqMaskBit::HeaderValid)
            .combine(IrqMaskBit::HeaderError)
            .combine(IrqMaskBit::CrcErr)
            .combine(IrqMaskBit::Timeout);

        Config {
            packet_type: PacketType::LoRa,
            sync_word: sync_word_sx126x(radio.sync_word),
            calib_param: CalibParam::all(),
            mod_params,
            pa_config: Self::sx1262_pa_config(),
            packet_params: Some(packet_params),
            tx_params: TxParams::default()
                .set_power_dbm(radio.tx_power_dbm)
                .set_ramp_time(RampTime::Ramp200u),
            dio1_irq_mask: irq,
            dio2_irq_mask: IrqMask::none(),
            dio3_irq_mask: IrqMask::none(),
            rf_freq: calc_rf_freq(radio.frequency_mhz, 32.0),
            rf_frequency: (radio.frequency_mhz * 1_000_000.0) as u32,
            tcxo_opts: profile.tcxo_opts(),
        }
    }

    fn irq_raw(irq: IrqStatus) -> u16 {
        let mut raw = 0u16;
        if irq.tx_done() {
            raw |= 1 << 0;
        }
        if irq.rx_done() {
            raw |= 1 << 1;
        }
        if irq.preamble_detected() {
            raw |= 1 << 2;
        }
        if irq.syncword_valid() {
            raw |= 1 << 3;
        }
        if irq.header_valid() {
            raw |= 1 << 4;
        }
        if irq.header_error() {
            raw |= 1 << 5;
        }
        if irq.crc_err() {
            raw |= 1 << 6;
        }
        if irq.timeout() {
            raw |= 1 << 9;
        }
        raw
    }

    fn chip_mode_name(mode: Option<ChipMode>) -> &'static str {
        match mode {
            Some(ChipMode::RX) => "RX",
            Some(ChipMode::TX) => "TX",
            Some(ChipMode::FS) => "FS",
            Some(ChipMode::StbyXOSC) => "STBY_XOSC",
            Some(ChipMode::StbyRC) => "STBY_RC",
            None => "UNKNOWN",
        }
    }

    fn clear_irqs(&mut self) -> Result<(), RadioError> {
        self.chip
            .clear_irq_status(IrqMask::all())
            .map_err(|_| RadioError::Hardware)
    }

    fn peek_rx_payload(&mut self) -> Result<(u8, i16, i8, [u8; MAX_LORA_PAYLOAD]), RadioError> {
        let status = self
            .chip
            .get_rx_buffer_status()
            .map_err(|_| RadioError::Hardware)?;
        let len = status.payload_length_rx().min(MAX_LORA_PAYLOAD as u8);
        let mut buf = [0u8; MAX_LORA_PAYLOAD];
        if len > 0 {
            self.chip
                .read_buffer(status.rx_start_buffer_pointer(), &mut buf[..len as usize])
                .map_err(|_| RadioError::Hardware)?;
        }
        let pkt = self
            .chip
            .get_packet_status()
            .map_err(|_| RadioError::Hardware)?;
        Ok((len, pkt.rssi_pkt() as i16, pkt.snr_pkt() as i8, buf))
    }

    fn log_rx_crc_error(&mut self) {
        let Ok((len, rssi, snr, buf)) = self.peek_rx_payload() else {
            crate::usb_log::log::radio::warn("RX crc error");
            return;
        };
        let payload = &buf[..len as usize];
        if let Ok(header) = PacketHeader::decode(payload) {
            let parsed = header.parse();
            defmt::warn!(
                "[Radio0] RX crc error len={} rssi={} snr={} maybe: id=0x{:08x} fr=!{:08x} to=!{:08x}",
                len,
                rssi,
                snr,
                parsed.id,
                parsed.from,
                parsed.to
            );
        } else {
            defmt::warn!(
                "[Radio0] RX crc error len={} rssi={} snr={}",
                len,
                rssi,
                snr
            );
        }
        crate::usb_log::log::radio::rx_crc_error(len, rssi, snr, payload);
    }

    fn reenter_rx(&mut self) -> Result<(), RadioError> {
        self.chip
            .set_rx(RxTxTimeout::continuous_rx())
            .map_err(|_| RadioError::Hardware)?;
        self.chip.wait_on_busy().map_err(|_| RadioError::Hardware)?;
        let status = self.chip.get_status().map_err(|_| RadioError::Hardware)?;
        if status.chip_mode() != Some(ChipMode::RX) {
            self.log_set_rx_failure(status);
            return Err(RadioError::Hardware);
        }
        Ok(())
    }

    /// Explain why SetRx did not land in RX: chip mode + command status from the status
    /// byte, plus the SX126x device-error flags. `mode=none` means the status byte was
    /// not a valid SX126x status at all, which points at MISO/SPI wiring rather than the
    /// radio; `xosc_start` points at a TCXO/crystal mismatch with the module profile.
    fn log_set_rx_failure(&mut self, status: sx126x::op::status::Status) {
        use core::fmt::Write;
        let mode = match status.chip_mode() {
            Some(ChipMode::StbyRC) => "StbyRC",
            Some(ChipMode::StbyXOSC) => "StbyXOSC",
            Some(ChipMode::FS) => "FS",
            Some(ChipMode::RX) => "RX",
            Some(ChipMode::TX) => "TX",
            None => "none",
        };
        let cmd = match status.command_status() {
            Some(sx126x::op::status::CommandStatus::DataAvailable) => "data",
            Some(sx126x::op::status::CommandStatus::CommandTimeout) => "timeout",
            Some(sx126x::op::status::CommandStatus::CommandProcessingError) => "proc_err",
            Some(sx126x::op::status::CommandStatus::FailureToExecute) => "exec_fail",
            Some(sx126x::op::status::CommandStatus::CommandTxDone) => "tx_done",
            None => "none",
        };
        let mut msg: heapless::String<160> = heapless::String::new();
        let _ = write!(msg, "set_rx failed: mode={} cmd={}", mode, cmd);
        let errs = self
            .chip
            .wait_on_busy()
            .ok()
            .and_then(|_| self.chip.get_device_errors().ok());
        match errs {
            Some(e) => {
                let _ = write!(
                    msg,
                    " errs[xosc_start={} pll_lock={} pll_calib={} img_calib={} rc64k={} rc13m={} adc={} pa_ramp={}]",
                    e.xosc_start_err() as u8,
                    e.pll_lock_err() as u8,
                    e.pll_calib_err() as u8,
                    e.img_calib_err() as u8,
                    e.rc64k_calib_err() as u8,
                    e.rc13m_calib_err() as u8,
                    e.adc_calib_err() as u8,
                    e.pa_ramp_err() as u8
                );
            }
            None => {
                let _ = write!(msg, " errs=unreadable");
            }
        }
        defmt::warn!("[Radio0] {}", msg.as_str());
        crate::usb_log::log::radio::warn(msg.as_str());
    }

    /// Semtech packet counters — useful to see if the modem sees any RF activity.
    pub fn chip_stats(&mut self) -> Result<(u16, u16, u16), RadioError> {
        self.chip.wait_on_busy().map_err(|_| RadioError::Hardware)?;
        let stats = self.chip.get_stats().map_err(|_| RadioError::Hardware)?;
        Ok((stats.rx_pkt, stats.crc_error, stats.header_error))
    }

    pub fn log_config(&self) {
        let cfg = &self.config;
        defmt::info!(
            "[Radio0] modem SF{} BW{}kHz CR4/{} sync=0x{:02x} sx126x=0x{:04x} preamble={} tx={}dBm pa={}/{} ocp=140mA hop={}",
            cfg.spreading_factor,
            cfg.bandwidth_khz as u32,
            cfg.coding_rate,
            cfg.sync_word,
            sync_word_sx126x(cfg.sync_word),
            cfg.preamble_length,
            cfg.tx_power_dbm,
            SX1262_PA_DUTY_CYCLE,
            SX1262_PA_HP_MAX,
            cfg.hop_limit
        );
        crate::usb_log::log::radio::config_modem(
            cfg.spreading_factor,
            cfg.bandwidth_khz as u32,
            cfg.coding_rate,
            cfg.sync_word,
            sync_word_sx126x(cfg.sync_word),
            cfg.preamble_length,
            cfg.tx_power_dbm,
            SX1262_PA_DUTY_CYCLE,
            SX1262_PA_HP_MAX,
            cfg.hop_limit,
        );
        defmt::info!(
            "[Radio0] profile {} dio2_rf_switch={}",
            self.profile.name(),
            self.profile.dio2_rf_switch()
        );
        crate::usb_log::log::radio::config_profile(
            self.profile.name(),
            self.profile.dio2_rf_switch(),
        );
    }

    pub fn log_chip_status(&mut self) -> Result<(), RadioError> {
        self.chip.wait_on_busy().map_err(|_| RadioError::Hardware)?;
        let status = self.chip.get_status().map_err(|_| RadioError::Hardware)?;
        let (rx_pkt, crc, hdr) = self.chip_stats()?;
        let mode = Self::chip_mode_name(status.chip_mode());
        defmt::info!(
            "[Radio0] chip mode={} stats rx_pkt={} crc_err={} hdr_err={}",
            mode,
            rx_pkt,
            crc,
            hdr
        );
        crate::usb_log::log::radio::chip_status(mode, rx_pkt, crc, hdr);
        Ok(())
    }
}

impl RadioInterface for Sx1262Driver {
    fn radio_id(&self) -> RadioId {
        self.id
    }

    fn config(&self) -> &RadioConfig {
        &self.config
    }

    fn init(&mut self) -> Result<(), RadioError> {
        // The sx126x crate busy-waits on BUSY with no timeout. On a module that is
        // unpowered, unwired or held in reset, BUSY never drops and `chip.init` would
        // spin forever inside the cooperative executor, starving every other task
        // (USB CDC included, so the node never even enumerates). Refuse up front.
        if !self.module_ready {
            return Err(RadioError::InitFailed);
        }
        self.chip
            .init(Self::sx126x_config(self.profile, &self.config))
            .map_err(|_| RadioError::InitFailed)?;

        if self.profile.dio2_rf_switch() {
            self.chip
                .set_dio2_as_rf_switch_ctrl(true)
                .map_err(|_| RadioError::Hardware)?;
        }

        self.configure_ocp()?;
        self.chip
            .set_ant_enabled(true)
            .map_err(|_| RadioError::Hardware)?;

        self.reenter_rx()
    }

    fn poll_recv(&mut self) -> Result<Option<RxFrame>, RadioError> {
        self.chip.wait_on_busy().map_err(|_| RadioError::Hardware)?;
        let irq = self
            .chip
            .get_irq_status()
            .map_err(|_| RadioError::Hardware)?;

        if Self::irq_raw(irq) == 0 {
            return Ok(None);
        }

        if irq.header_error() || irq.crc_err() {
            defmt::warn!(
                "[Radio0] RX error header={} crc={}",
                irq.header_error(),
                irq.crc_err()
            );
            if irq.crc_err() {
                self.log_rx_crc_error();
            }
            if irq.header_error() {
                crate::usb_log::log::radio::warn("RX header error");
            }
            self.rx_active_since = None;
            self.clear_irqs()?;
            self.reenter_rx()?;
            return Ok(None);
        }

        if irq.timeout() {
            crate::usb_log::log::radio::warn("RX timeout");
            self.rx_active_since = None;
            self.clear_irqs()?;
            self.reenter_rx()?;
            return Ok(None);
        }

        if irq.tx_done() {
            self.clear_irqs()?;
            return Ok(None);
        }

        if !irq.rx_done() {
            if Self::irq_rx_active(irq) {
                // A frame is arriving: keep the flags so `rx_in_progress` can see them, but
                // never forever. A false preamble detect or a frame we lost mid-air would
                // otherwise block our transmitter indefinitely.
                let now = embassy_time::Instant::now();
                match self.rx_active_since {
                    None => {
                        self.rx_active_since = Some(now);
                        return Ok(None);
                    }
                    Some(since) if now - since < self.max_rx_in_progress() => return Ok(None),
                    Some(_) => {
                        defmt::trace!("[Radio0] stale RX-in-progress flags cleared");
                        self.rx_active_since = None;
                    }
                }
            }
            self.clear_irqs()?;
            return Ok(None);
        }

        self.rx_active_since = None;
        self.clear_irqs()?;

        let status = self
            .chip
            .get_rx_buffer_status()
            .map_err(|_| RadioError::Hardware)?;
        let len = status.payload_length_rx().min(MAX_LORA_PAYLOAD as u8);
        let mut buf = [0u8; MAX_LORA_PAYLOAD];
        if len > 0 {
            self.chip
                .read_buffer(status.rx_start_buffer_pointer(), &mut buf[..len as usize])
                .map_err(|_| RadioError::Hardware)?;
        }

        let pkt = self
            .chip
            .get_packet_status()
            .map_err(|_| RadioError::Hardware)?;

        self.reenter_rx()?;

        let mut frame = RxFrame::empty(self.id);
        frame.len = len;
        frame.bytes[..len as usize].copy_from_slice(&buf[..len as usize]);
        frame.rssi = pkt.rssi_pkt() as i16;
        frame.snr = pkt.snr_pkt() as i8;

        Ok(Some(frame))
    }

    fn send(&mut self, frame: &TxFrame) -> Result<(), RadioError> {
        if frame.len as usize > MAX_LORA_PAYLOAD {
            return Err(RadioError::InvalidLength);
        }

        self.chip
            .set_ant_enabled(true)
            .map_err(|_| RadioError::Hardware)?;

        let status = self
            .chip
            .write_bytes(
                frame.payload(),
                RxTxTimeout::from_ms(5_000),
                self.config.preamble_length,
                LoRaCrcType::CrcOn,
            )
            .map_err(|_| RadioError::Hardware)?;

        defmt::trace!(
            "[Radio0] TX complete mode={}",
            Self::chip_mode_name(status.chip_mode())
        );
        Ok(())
    }

    fn start_rx(&mut self) -> Result<(), RadioError> {
        self.rx_active_since = None;
        self.reenter_rx()
    }

    fn rx_in_progress(&mut self) -> Result<bool, RadioError> {
        // `poll_recv` runs first in every service pass and leaves the in-progress flags set
        // (aging them out if they go stale), so a fresh read here is authoritative.
        self.chip.wait_on_busy().map_err(|_| RadioError::Hardware)?;
        let irq = self
            .chip
            .get_irq_status()
            .map_err(|_| RadioError::Hardware)?;
        Ok(!irq.rx_done()
            && !irq.header_error()
            && !irq.crc_err()
            && !irq.timeout()
            && Self::irq_rx_active(irq)
            && self.rx_active_since.is_some())
    }
}

/// Longest we wait for BUSY to drop after releasing NRST. The SX126x datasheet puts the
/// post-reset BUSY window at a few milliseconds; a healthy module clears it well inside this.
const BUSY_PROBE_TIMEOUT: embassy_time::Duration = embassy_time::Duration::from_millis(50);

/// Pulse NRST and wait (bounded) for BUSY to go low.
///
/// Returns `false` when the module never signals ready, which means it is unpowered,
/// not wired (BUSY floats high — the input has no pull), or still held in reset.
fn probe_module_ready(pins: &mut LoRaPins) -> bool {
    pins.reset.set_low();
    // 8.1: hold NRST low for at least 100 us.
    embassy_time::block_for(embassy_time::Duration::from_micros(200));
    pins.reset.set_high();
    let deadline = embassy_time::Instant::now() + BUSY_PROBE_TIMEOUT;
    while pins.busy.is_high() {
        if embassy_time::Instant::now() >= deadline {
            return false;
        }
    }
    true
}

/// Build SPI + SX1262 for the Pro Micro DIY pinout.
pub fn create_radio(
    spim: Spim<'static, embassy_nrf::peripherals::SPI3>,
    cs: Output<'static>,
    mut pins: LoRaPins,
    profile: Sx1262ModuleProfile,
) -> Sx1262Driver {
    let module_ready = probe_module_ready(&mut pins);
    let spi_dev = ExclusiveDevice::new(spim, cs, embassy_time::Delay);
    let chip = SX126x::new(spi_dev, (pins.reset, pins.busy, pins.ant_en, pins.dio1));
    Sx1262Driver::new(0, profile, chip, module_ready)
}
