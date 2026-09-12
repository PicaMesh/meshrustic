//! Embassy task driving radio 0 RX/TX and AirTime ticks.

use embassy_futures::select::{select, Either};
use embassy_time::{Duration, Instant, Timer};
use mesh_protocol::{num::TEXT_MESSAGE_APP, PacketHeader, NODENUM_BROADCAST, PACKET_HEADER_LEN};
use mesh_radio::{
    eu868_config_for_preset, packet_time_ms, AirTime, RadioError, RadioSlot, TxFrame, EU_868,
};
use mesh_routing::channel_access::ChannelAccess;
use mesh_routing::{
    wire_may_relay, ChannelQoS, DeviceMetricsSnapshot, HostCommand, InboundPacket, Router,
    RxDecodeInfo, SrLogEvent, MAX_SR_LOG,
};
use mesh_store::{ConfigStore, EMPTY_ADMIN_KEY};
use static_cell::StaticCell;

use super::sx1262::Sx1262Driver;
use crate::store::NvmcConfigStore;
use crate::usb_log::HostCommandChannel;

static AIR_TIME: StaticCell<AirTime> = StaticCell::new();

pub fn air_time() -> &'static mut AirTime {
    AIR_TIME.init(AirTime::new(EU_868))
}

#[embassy_executor::task]
pub async fn radio_task(
    slot: &'static mut RadioSlot<Sx1262Driver>,
    router: &'static mut Router,
    store: &'static mut NvmcConfigStore,
    node_num: u32,
    mut watchdog: Option<embassy_nrf::wdt::WatchdogHandle>,
    host_cmd: &'static HostCommandChannel,
    mut dio1_wake: embassy_nrf::gpio::Input<'static>,
) {
    let air = air_time();
    let profile = slot.driver.profile();

    if let Err(err) = slot.init() {
        // Do not panic: a panic halts the executor and takes USB logging down with it,
        // leaving a node that never enumerates and gives no hint why. Park this task
        // and keep repeating the reason so it is visible on the CDC log.
        let reason = match err {
            RadioError::InitFailed => "init FAILED: SX1262 not responding (BUSY stuck high after reset) - check module power/wiring",
            RadioError::Busy => "init FAILED: radio busy",
            RadioError::Timeout => "init FAILED: timeout",
            RadioError::InvalidLength => "init FAILED: invalid length",
            RadioError::Hardware => "init FAILED: hardware/SPI error",
        };
        loop {
            // Keep the watchdog fed: a parked node that keeps logging its reason is worth more
            // than a 30 s reboot loop that shows three lines per cycle.
            if let Some(wdt) = watchdog.as_mut() {
                wdt.pet();
            }
            defmt::error!("[Radio0] {}", reason);
            crate::usb_log::log::radio::warn(reason);
            Timer::after_secs(10).await;
        }
    }
    router.emit_startup_logs();
    // Modem preset + channel key already applied via Router::load_node_config in main.
    let boot_ms = (Instant::now().as_millis() & 0xFFFF_FFFF) as u32;
    router.ensure_boot_broadcasts(boot_ms, packet_time_ms(slot.config(), 64, true).max(1));
    let cfg = slot.config();
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
    // Edge-triggered: one line per hold, not one per poll.
    let mut tx_held_logged = false;
    let boot_instant = Instant::now();
    let mut sr_log_buf: heapless::Vec<SrLogEvent, MAX_SR_LOG> = heapless::Vec::new();
    let mut reboot_deadline: Option<Instant> = None;
    // LoRa preset: persist + soft-reinit after completion reply TX (never sys_reset).
    let mut radio_reinit_pending = false;
    // The only decision point for keying up: post-reception turnaround, post-TX gap and the
    // contention backoff all live in `ChannelAccess` (mesh-routing::channel_access), and both
    // the router's polls and the radio queue itself are gated by it below.
    let mut access = ChannelAccess::new();
    let mut tx_cancels: heapless::Vec<u32, 8> = heapless::Vec::new();

    const LOOP_ACTIVE_MS: u64 = 5;
    const LOOP_IDLE_MS: u64 = 100;

    loop {
        // Every pass through this loop proves the executor and the router are still making
        // progress; a hang anywhere in the firmware stops the petting and the WDT resets the chip.
        if let Some(wdt) = watchdog.as_mut() {
            wdt.pet();
        }
        let now_ms = (Instant::now().as_millis() & 0xFFFF_FFFF) as u32;
        let slot_ms = packet_time_ms(slot.config(), 64, true).max(1);

        // Due frames keep the delay they were given. RadioSlot::service decides whether the
        // head of the queue may key up, with that frame in hand, so a hold names the frame
        // and the reason instead of applying one boolean to the whole pass.
        let may_tx = access.may_transmit(now_ms);
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

        router.set_channel_utilization(air.channel_utilization_percent());
        if let Some(retx) = router.poll_reliable_retransmit(now_ms) {
            enqueue_tx(retx, slot, router, node_num, b"retx");
        }

        if let Some(ack) = router.poll_ack_tx(now_ms) {
            enqueue_tx(ack, slot, router, node_num, b"ack");
        }

        if let Some(admin) = router.poll_admin_tx(now_ms) {
            enqueue_tx(admin, slot, router, node_num, b"admin");
        }

        // A command typed at the USB host, one more producer in this chain. A non-blocking
        // check -- the channel is drained here, never awaited -- so an empty queue costs
        // nothing on this pass, same as every `poll_*` above. `send_local` is called exactly
        // as any other originated frame would be: nothing shortcuts to the radio.
        if let Ok(cmd) = host_cmd.try_receive() {
            let (to, text) = match cmd {
                HostCommand::Broadcast { text } => (NODENUM_BROADCAST, text),
                HostCommand::Unicast { to, text } => (to, text),
            };
            let airtime_ms =
                packet_time_ms(slot.config(), PACKET_HEADER_LEN + text.len(), true).max(1);
            if let Some(plan) = router.send_local(
                to,
                TEXT_MESSAGE_APP,
                &text,
                false,
                router.hop_limit(),
                now_ms,
                airtime_ms,
            ) {
                enqueue_tx(plan, slot, router, node_num, b"host-cmd");
            }
        }

        if router.take_pending_radio_reinit() {
            radio_reinit_pending = true;
        }
        // Explicit AdminMessage.reboot_seconds only (not LoRa preset apply).
        if let Some(secs) = router.take_pending_reboot_seconds() {
            persist_config(store, router);
            let delay_ms = if secs <= 0 {
                0u64
            } else {
                (secs as u64).saturating_mul(1000)
            };
            reboot_deadline = Some(Instant::now() + Duration::from_millis(delay_ms));
        }
        if let Some(deadline) = reboot_deadline {
            if Instant::now() >= deadline {
                defmt::info!("[meshrustic] reboot after admin reboot_seconds (UF2-skip)");
                soft_reset_skip_uf2();
            }
        }

        router.drain_sr_logs(&mut sr_log_buf);
        for event in sr_log_buf.iter() {
            crate::usb_log::log::sr::emit(*event);
        }

        match slot.service(air, may_tx) {
            Ok(mut report) => {
                let mut last_rx_id = 0u32;
                while let Some(frame) = report.rx {
                    if let Ok(h) = PacketHeader::decode(frame.payload()) {
                        last_rx_id = h.parse().id;
                    }
                    handle_rx_frame(frame, slot, router, node_num, air);
                    // A copy of a packet we queued cancels the relay: pull the frame back before
                    // the radio gets to it.
                    router.take_tx_cancels(&mut tx_cancels);
                    for id in tx_cancels.iter() {
                        let removed = slot.remove_tx(*id);
                        if removed > 0 {
                            defmt::info!("[Radio0] TX cancelled id=0x{:08x} (copy heard)", *id);
                            crate::usb_log::log::radio::tx_cancelled(*id);
                        }
                    }
                    report.rx = slot.rx_queue.pop().ok();
                }
                if report.receptions > 0 {
                    let cw_slot = mesh_routing::slot_time_for_preset(router.modem_preset());
                    let backoff = mesh_routing::coordinated_relay::tx_delay_ms_contention(
                        air.channel_utilization_percent(),
                        cw_slot,
                        now_ms,
                        last_rx_id,
                        node_num,
                    );
                    access.note_rx((Instant::now().as_millis() & 0xFFFF_FFFF) as u32, backoff);
                }
                if report.tx_deferred_rx_busy || report.tx_deferred_rx_pending || report.tx_held {
                    if !tx_held_logged {
                        crate::usb_log::log::radio::tx_held(
                            report.tx_id.unwrap_or(0),
                            access.remaining_ms((Instant::now().as_millis() & 0xFFFF_FFFF) as u32),
                            report.tx_deferred_rx_busy,
                            report.tx_deferred_rx_pending,
                            report.tx_held,
                            report.held_behind_rx.unwrap_or(0),
                        );
                        tx_held_logged = true;
                    }
                } else {
                    tx_held_logged = false;
                }
                if let Some(len) = report.tx_len {
                    defmt::info!(
                        "[Radio0] TX done id=0x{:08x} target=!{:08x} {} bytes",
                        report.tx_id.unwrap_or(0),
                        report.tx_to.unwrap_or(0),
                        len
                    );
                    crate::usb_log::log::radio::tx_done(report.tx_id, report.tx_to, len);
                    if let Some(id) = report.tx_id {
                        router.note_tx_done(id);
                    }
                    access.note_tx_done((Instant::now().as_millis() & 0xFFFF_FFFF) as u32);
                }
                if report.tx_deferred_rx_busy {
                    defmt::trace!("[Radio0] TX deferred: reception in progress");
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

        // Soft-reinit after the completion reply has left the TX queue (old air params).
        if radio_reinit_pending && slot.tx_queue_len() == 0 {
            apply_modem_preset_soft(slot, router.modem_preset());
            router.radio_reconfigured(now_ms, slot_ms);
            radio_reinit_pending = false;
        }

        if router.admin_config_dirty() {
            persist_config(store, router);
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
            // One line, one read: `log_chip_status` fetches the same counters and prints them
            // with the chip mode, so asking for them separately cost a second SPI round trip
            // and a log line that its output already contained.
            let _ = slot.driver.log_chip_status();
            last_stats = Instant::now();
        }

        if Instant::now().duration_since(last_maintenance) >= Duration::from_secs(60) {
            // Publish every cycle, including an invalid reading: keeping the previous
            // snapshot would latch a stale "USB powered" 101 into every later broadcast
            // once the pack reading goes away. An invalid reading drops the battery
            // fields only — chutil/air util/uptime still go out.
            let batt = crate::battery::latest();
            router.update_device_metrics(DeviceMetricsSnapshot {
                battery_level: batt.valid.then_some(batt.battery_level),
                voltage_v: batt.valid.then(|| batt.voltage_mv as f32 / 1000.0),
                channel_utilization: air.channel_utilization_percent(),
                air_util_tx: air.utilization_tx_percent(),
                uptime_seconds: boot_instant.elapsed().as_secs() as u32,
            });
            let report = router.run_maintenance(now_ms, slot_ms);
            if report.graph_log_due {
                // Restate identity, role and build with each periodic dump. Emitting them only on
                // USB connect was not enough: a logger that reattaches even twenty seconds after a
                // reboot misses them, and they are evicted from the 16 KB ring long before it
                // arrives. Three reflashes in a row produced captures that could not say which
                // firmware or role they came from. One line a minute makes any capture
                // self-describing, whenever it was started.
                crate::usb_log::log::mesh::node_id(router.node_num());
                crate::usb_log::log::mesh::device_role(router.device_role());
                crate::usb_log::log::push_line(concat!("[meshrustic] build ", env!("MR_BUILD")));
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

        // Wake on the radio's own interrupt line as well as on the tick. Every received frame
        // carries `now_ms`, taken at the top of the next iteration, so before this the stamp was
        // whichever tick happened to notice the frame — up to LOOP_IDLE_MS out. Waking on the edge
        // makes it the instant the radio raised DIO1, and it is still taken before any SPI traffic,
        // so the error no longer varies with payload length either.
        //
        // A rising edge, not a level: DIO1 stays high until the interrupt is cleared, so waiting on
        // the level would return immediately and spin. Still `select`ed with the tick, which remains
        // the backstop — a missed or spurious edge can cost latency, never the loop — and the tick
        // alone continues to drive maintenance, transmit release and duty-cycle bookkeeping. The
        // line is shared with the blocking transmit inside the radio crate, so a wake is not by
        // itself evidence of a reception; what it meant is decided by the IRQ status read above.
        match select(
            Timer::after_millis(sleep_ms),
            dio1_wake.wait_for_rising_edge(),
        )
        .await
        {
            Either::First(()) | Either::Second(()) => {}
        }
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

    // Admin replies scheduled inside process_inbound size their retransmit backoff from this.
    router.set_channel_utilization(air.channel_utilization_percent());
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

        // Nothing leaves for the radio from here. An immediate relay is parked as a pending
        // relay due now, and ACKs/admin/traceroute replies already sit in their pending slots;
        // the loop top releases them once the post-reception hold has passed. Enqueueing here
        // bypassed that hold and put replies on the air ~0 ms after the request, while the
        // peer nodes were still busy with the request for 70-170 ms and heard none of them.
        if let Some(relay) = plan.relay {
            if !router.defer_relay(relay, result.radio_id, now_ms) {
                // Pending table full: the radio queue is gated by ChannelAccess as well, so the
                // frame still waits out the turnaround; it just cannot be pulled back by a dupe.
                enqueue_tx(relay, slot, router, node_num, b"relay");
            }
        }
    } else if let Ok(header) = PacketHeader::decode(frame.payload()) {
        let parsed = header.parse();
        let payload_len = frame
            .payload()
            .len()
            .saturating_sub(mesh_protocol::PACKET_HEADER_LEN);
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

fn persist_config(store: &mut NvmcConfigStore, router: &mut Router) {
    let mut cfg = store.load();
    router.write_admin_into_config(&mut cfg);
    let preset = cfg.lora.modem_preset;
    match store.save(&cfg) {
        Ok(()) => {
            router.clear_admin_config_dirty();
            let admin_keys = cfg
                .admin_public_keys
                .iter()
                .filter(|k| *k != &EMPTY_ADMIN_KEY)
                .count() as u32;
            defmt::info!(
                "[store] NodeConfig saved preset={} admin_keys={}",
                preset,
                admin_keys
            );
            crate::usb_log::log::mesh::config_saved(admin_keys);
        }
        Err(_) => {
            defmt::warn!("[store] NodeConfig save failed");
            crate::usb_log::log::radio::warn("config save failed");
        }
    }
}

/// Apply a new LoRa modem preset without MCU reset (UF2 boards enter upload mode on sys_reset).
fn apply_modem_preset_soft(slot: &mut RadioSlot<Sx1262Driver>, preset: u8) {
    let cfg = eu868_config_for_preset(preset);
    let name = cfg.preset_log_name();
    defmt::info!(
        "[Radio0] soft-reinit preset {} @ {} MHz (no reboot)",
        name,
        cfg.frequency_mhz
    );
    slot.driver.set_radio_config(cfg);
    match slot.init() {
        Ok(()) => {
            slot.driver.log_config();
            let _ = slot.driver.log_chip_status();
        }
        Err(_) => {
            defmt::error!("[Radio0] soft-reinit failed");
            crate::usb_log::log::radio::warn("modem soft-reinit failed");
        }
    }
}

/// Soft-reset without entering Adafruit UF2 / CDC upload mode.
fn soft_reset_skip_uf2() -> ! {
    // Adafruit_nRF52_Bootloader: DFU_MAGIC_SKIP = 0x6d in GPREGRET.
    const NRF_POWER_GPREGRET: *mut u32 = 0x4000_051C as *mut u32;
    // Double-reset sentinel used by that bootloader (retained RAM).
    const DFU_DBL_RESET_MEM: *mut u32 = 0x2000_7F7C as *mut u32;
    unsafe {
        core::ptr::write_volatile(NRF_POWER_GPREGRET, 0x6d);
        core::ptr::write_volatile(DFU_DBL_RESET_MEM, 0);
    }
    cortex_m::peripheral::SCB::sys_reset()
}
