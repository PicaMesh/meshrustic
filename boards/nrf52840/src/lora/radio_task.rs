//! Embassy task driving radio 0 RX/TX and AirTime ticks.

use embassy_time::{Duration, Instant, Timer};
use mesh_crypto::{CryptoKey, DEFAULT_PSK};
use mesh_protocol::PacketHeader;
use mesh_radio::{packet_time_ms, AirTime, RadioError, RadioSlot, TxFrame, EU_868};
use mesh_routing::{wire_may_relay, ChannelQoS, DeviceMetricsSnapshot, InboundPacket, Router, RxDecodeInfo, SrLogEvent, MAX_SR_LOG};
use static_cell::StaticCell;

use super::sx1262::Sx1262Driver;

static AIR_TIME: StaticCell<AirTime> = StaticCell::new();

pub fn air_time() -> &'static mut AirTime {
    AIR_TIME.init(AirTime::new(EU_868))
}

#[embassy_executor::task]
pub async fn radio_task(
    slot: &'static mut RadioSlot<Sx1262Driver>,
    router: &'static mut Router,
    node_num: u32,
) {
    let air = air_time();
    let profile = slot.driver.profile();

    slot.init().expect("radio init failed");
    router.emit_startup_logs();
    let cfg = slot.config();
    router.set_modem_preset(
        "",
        cfg.modem_preset,
        true,
        CryptoKey::from_bytes(&DEFAULT_PSK),
    );
    let boot_ms = (Instant::now().as_millis() & 0xFFFF_FFFF) as u32;
    router.ensure_boot_broadcasts(boot_ms, packet_time_ms(slot.config(), 64, true).max(1));
    let preset = cfg.preset_log_name();
    defmt::info!(
        "[Radio0] nodeId !{:08x} SX1262 ({}) init OK, EU_868 {} @ {} MHz",
        node_num,
        profile.name(),
        preset,
        cfg.frequency_mhz
    );
    crate::usb_log::log::radio::init_ok(profile.name(), node_num, preset, cfg.frequency_mhz);
    slot.driver.log_config();
    let _ = slot.driver.log_chip_status();

    let mut last_second = Instant::now();
    let mut last_stats = Instant::now();
    let mut last_maintenance = Instant::now();
    let mut last_duty_log = Instant::now();
    let boot_instant = Instant::now();
    let mut sr_log_buf: heapless::Vec<SrLogEvent, MAX_SR_LOG> = heapless::Vec::new();

    const LOOP_ACTIVE_MS: u64 = 5;
    const LOOP_IDLE_MS: u64 = 100;

    loop {
        let now_ms = (Instant::now().as_millis() & 0xFFFF_FFFF) as u32;
        let slot_ms = packet_time_ms(slot.config(), 64, true).max(1);

        if let Some(relay) = router.poll_ready_relay(now_ms) {
            enqueue_tx(relay, slot, router, node_num, b"relay");
        }

        if let Some(topo) = router.poll_topology_tx(now_ms) {
            enqueue_tx(topo, slot, router, node_num, b"topology");
        }

        if let Some(nodeinfo) = router.poll_nodeinfo_tx(now_ms) {
            enqueue_tx(nodeinfo, slot, router, node_num, b"nodeinfo");
        }

        if let Some(telemetry) = router.poll_telemetry_tx(now_ms) {
            enqueue_tx(telemetry, slot, router, node_num, b"telemetry");
        }

        if let Some(tr) = router.poll_traceroute_tx(now_ms) {
            enqueue_tx(tr, slot, router, node_num, b"traceroute");
        }

        if let Some(t1) = router.poll_t1_retransmit(now_ms) {
            enqueue_tx(t1, slot, router, node_num, b"t1");
        }

        let airtime_ms = packet_time_ms(slot.config(), 64, false).max(1);
        if let Some(retx) = router.poll_reliable_retransmit(now_ms, airtime_ms, slot_ms) {
            enqueue_tx(retx, slot, router, node_num, b"retx");
        }

        if let Some(ack) = router.poll_ack_tx(now_ms) {
            enqueue_tx(ack, slot, router, node_num, b"ack");
        }

        router.drain_sr_logs(&mut sr_log_buf);
        for event in sr_log_buf.iter() {
            crate::usb_log::log::sr::emit(*event);
        }

        match slot.service(air) {
            Ok(mut report) => {
                while let Some(frame) = report.rx {
                    handle_rx_frame(frame, slot, router, node_num, air);
                    report.rx = slot.rx_queue.pop().ok();
                }
                if let Some(len) = report.tx_len {
                    defmt::info!(
                        "[Radio0] TX done id=0x{:08x} target=!{:08x} {} bytes",
                        report.tx_id.unwrap_or(0),
                        report.tx_to.unwrap_or(0),
                        len
                    );
                    crate::usb_log::log::radio::tx_done(
                        report.tx_id,
                        report.tx_to,
                        len,
                    );
                }
                if report.duty_cycle_blocked
                    && Instant::now().duration_since(last_duty_log) >= Duration::from_secs(10)
                {
                    let duty = air.utilization_tx_percent();
                    let limit = air.duty_cycle_limit_percent();
                    defmt::warn!(
                        "[AirTime] TX blocked duty={}% limit={}% queued={}",
                        duty as u32,
                        limit as u32,
                        report.tx_queue_len
                    );
                    crate::usb_log::log::airtime::duty_cycle_blocked(
                        duty,
                        limit,
                        report.tx_queue_len,
                    );
                    last_duty_log = Instant::now();
                }
            }
            Err(RadioError::InitFailed) => {
                defmt::warn!("[Radio0] init error");
                crate::usb_log::log::radio::warn("init error");
            }
            Err(RadioError::Busy) => defmt::trace!("[Radio0] busy"),
            Err(RadioError::Timeout) => {
                defmt::warn!("[Radio0] timeout");
                crate::usb_log::log::radio::warn("timeout");
            }
            Err(RadioError::InvalidLength) => {
                defmt::warn!("[Radio0] bad length");
                crate::usb_log::log::radio::warn("bad length");
            }
            Err(RadioError::Hardware) => {
                defmt::warn!("[Radio0] hardware error");
                crate::usb_log::log::radio::warn("hardware error");
            }
        }

        if Instant::now().duration_since(last_second) >= Duration::from_secs(1) {
            air.tick_second();
            defmt::trace!(
                "[Radio0] duty={}% chutil={}%",
                air.utilization_tx_percent() as u32,
                air.channel_utilization_percent() as u32
            );
            last_second = Instant::now();
        }

        if Instant::now().duration_since(last_stats) >= Duration::from_secs(30) {
            if let Ok((rx_pkt, crc, hdr)) = slot.driver.chip_stats() {
                defmt::info!(
                    "[Radio0] stats rx_pkt={} crc_err={} hdr_err={}",
                    rx_pkt,
                    crc,
                    hdr
                );
                crate::usb_log::log::radio::stats(rx_pkt, crc, hdr);
            }
            let _ = slot.driver.log_chip_status();
            last_stats = Instant::now();
        }

        if Instant::now().duration_since(last_maintenance) >= Duration::from_secs(60) {
            let batt = crate::battery::latest();
            if batt.valid {
                router.update_device_metrics(DeviceMetricsSnapshot {
                    battery_level: batt.battery_level,
                    voltage_v: batt.voltage_mv as f32 / 1000.0,
                    channel_utilization: air.channel_utilization_percent() as f32,
                    air_util_tx: air.utilization_tx_percent() as f32,
                    uptime_seconds: boot_instant.elapsed().as_secs() as u32,
                });
            }
            let report = router.run_maintenance(now_ms, slot_ms);
            if report.graph_log_due {
                crate::usb_log::log::sr::emit_topology_dump(router);
            }
            last_maintenance = Instant::now();
        }

        let usb_active = crate::usb_log::is_usb_connected();
        let busy = usb_active
            || router.has_pending_work()
            || slot.tx_queue_len() > 0
            || !slot.rx_queue.is_empty();
        let sleep_ms = if busy { LOOP_ACTIVE_MS } else { LOOP_IDLE_MS };

        Timer::after_millis(sleep_ms).await;
    }
}

fn handle_rx_frame(
    frame: mesh_radio::RxFrame,
    slot: &mut RadioSlot<Sx1262Driver>,
    router: &mut Router,
    node_num: u32,
    air: &mut AirTime,
) {
    let now_ms = (embassy_time::Instant::now().as_millis() & 0xFFFF_FFFF) as u32;
    let inbound = InboundPacket {
        radio_id: frame.radio_id,
        rssi: frame.rssi,
        snr: frame.snr,
        bytes: frame.payload(),
    };

    if let Some(result) = router.process_inbound(&inbound, now_ms) {
        crate::usb_log::log::radio::rx_packet(
            &result.parsed,
            result.rssi,
            result.snr,
            result.decode,
            result.duplicate,
            result.rate_limited,
        );

        if result.rate_limited {
            defmt::warn!("[RateLimit] drop from !{:08x}", result.parsed.from);
            crate::usb_log::log::rate_limit::drop_from(result.parsed.from);
        } else if result.duplicate {
            defmt::trace!(
                "[Router] duplicate !{:08x} id={}",
                result.parsed.from,
                result.parsed.id
            );
        }

        let chutil = air.channel_utilization_percent();
        let slot_ms = packet_time_ms(slot.config(), frame.len as usize, true).max(1);
        router.note_rx_airtime(slot_ms);
        let plan = router.evaluate_tx_plan(&result, chutil, slot_ms, now_ms);

        if !result.duplicate
            && !result.rate_limited
            && plan.relay.is_none()
            && router
                .relay_tx_after(result.parsed.from, result.parsed.id, frame.radio_id)
                .is_none()
            && wire_may_relay(
                &result.parsed,
                result.parsed.from == node_num,
                result.parsed.to == node_num,
            )
            && !ChannelQoS::new().can_relay(result.decoded_portnum, result.parsed.channel, chutil)
        {
            defmt::warn!(
                "[QoS] Drop relay !{:08x} chutil {}%",
                result.parsed.from,
                chutil as u32
            );
            crate::usb_log::log::qos::drop_relay(result.parsed.from, chutil);
        }

        if let Some(relay) = plan.relay {
            enqueue_tx(relay, slot, router, node_num, b"relay");
        }

        if let Some(ack) = router.poll_ack_tx(now_ms) {
            enqueue_tx(ack, slot, router, node_num, b"ack");
        }

        if let Some(tr) = router.poll_traceroute_tx(now_ms) {
            enqueue_tx(tr, slot, router, node_num, b"traceroute");
        }
    } else if let Ok(header) = PacketHeader::decode(frame.payload()) {
        let parsed = header.parse();
        let payload_len = frame.payload().len().saturating_sub(mesh_protocol::PACKET_HEADER_LEN);
        crate::usb_log::log::radio::rx_packet(
            &parsed,
            frame.rssi,
            frame.snr,
            RxDecodeInfo::encrypted(payload_len.min(u16::MAX as usize) as u16),
            false,
            false,
        );
    }
}

fn enqueue_tx(
    relay: mesh_routing::RelayPlan,
    slot: &mut RadioSlot<Sx1262Driver>,
    router: &mut Router,
    node_num: u32,
    kind: &[u8],
) {
    crate::usb_log::log::radio::tx_enqueue(
        kind,
        &relay.bytes[..relay.len as usize],
        relay.len,
        relay.delay_ms,
        node_num,
    );

    if let Ok(header) = PacketHeader::decode(&relay.bytes[..relay.len as usize]) {
        let now_ms = (embassy_time::Instant::now().as_millis() & 0xFFFF_FFFF) as u32;
        router.record_tx_on_air(header.parse().id, now_ms);
    }

    if let Some(tx) = TxFrame::new(slot.id, &relay.bytes[..relay.len as usize]) {
        match slot.enqueue_tx(tx) {
            Ok(()) => defmt::info!(
                "[Router] {} enqueue {} bytes hop={} delay={}ms",
                kind,
                relay.len,
                relay.bytes[12] & 0x07,
                relay.delay_ms
            ),
            Err(_) => {
                defmt::warn!("[Router] TX queue full");
                crate::usb_log::log::radio::warn("TX queue full");
            }
        }
    }
}
