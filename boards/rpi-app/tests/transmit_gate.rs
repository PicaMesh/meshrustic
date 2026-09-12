//! Transmit gate: only a completed reception arms the contention hold.

use mesh_radio::{
    AirTime, RadioError, RadioId, RadioInterface, RadioSlot, RxFrame, TxFrame, EU_868,
};
use mesh_routing::channel_access::{ChannelAccess, PEER_TURNAROUND_MS};

struct MockRadio {
    busy: bool,
    sent: usize,
    inbox: Option<RxFrame>,
    cfg: mesh_radio::RadioConfig,
}

impl RadioInterface for MockRadio {
    fn radio_id(&self) -> RadioId {
        0
    }
    fn config(&self) -> &mesh_radio::RadioConfig {
        &self.cfg
    }
    fn init(&mut self) -> Result<(), RadioError> {
        Ok(())
    }
    fn poll_recv(&mut self) -> Result<Option<RxFrame>, RadioError> {
        Ok(self.inbox.take())
    }
    fn send(&mut self, _frame: &TxFrame) -> Result<(), RadioError> {
        self.sent += 1;
        Ok(())
    }
    fn start_rx(&mut self) -> Result<(), RadioError> {
        Ok(())
    }
    fn rx_in_progress(&mut self) -> Result<bool, RadioError> {
        Ok(self.busy)
    }
}

fn rx_frame(id: u32) -> RxFrame {
    let mut f = RxFrame::empty(0);
    f.len = 20;
    f.bytes[8..12].copy_from_slice(&id.to_le_bytes());
    f.rssi = -70;
    f.snr = 8;
    f
}

fn tx_bytes(id: u32) -> [u8; 20] {
    let mut b = [0u8; 20];
    b[8..12].copy_from_slice(&id.to_le_bytes());
    b
}

fn slot_with(busy: bool, inbox: Option<RxFrame>) -> RadioSlot<MockRadio> {
    RadioSlot::new(
        0,
        MockRadio {
            busy,
            sent: 0,
            inbox,
            cfg: mesh_radio::RadioConfig::eu868_default(),
        },
    )
}

/// The board's arming rule: a completed reception this pass, nothing else.
fn arm_hold(access: &mut ChannelAccess, receptions: u8, now_ms: u32, backoff_ms: u32) {
    if receptions > 0 {
        access.note_rx(now_ms, backoff_ms);
    }
}

#[test]
fn a_busy_modem_defers_without_extending_the_hold() {
    let mut slot = slot_with(false, Some(rx_frame(1)));
    slot.enqueue_tx(TxFrame::new(0, &tx_bytes(0x42)).unwrap())
        .unwrap();
    let mut air = AirTime::new(EU_868);
    let mut access = ChannelAccess::new();

    let report = slot.service(&mut air, true).unwrap();
    assert_eq!(report.receptions, 1);
    arm_hold(&mut access, report.receptions, 1_000, 0);
    let remaining = access.remaining_ms(1_000);
    assert_eq!(remaining, PEER_TURNAROUND_MS);

    slot.driver.busy = true;
    let busy = slot.service(&mut air, access.may_transmit(1_050)).unwrap();
    assert!(busy.tx_deferred_rx_busy);
    assert_eq!(busy.receptions, 0);
    arm_hold(&mut access, busy.receptions, 1_050, 0);
    assert_eq!(
        access.remaining_ms(1_050),
        remaining - 50,
        "busy deferral must not re-arm the hold"
    );
    assert_eq!(slot.tx_queue_len(), 1);
}

#[test]
fn a_pending_receive_queue_defers_without_extending_the_hold() {
    let mut slot = slot_with(false, Some(rx_frame(1)));
    slot.enqueue_tx(TxFrame::new(0, &tx_bytes(0x42)).unwrap())
        .unwrap();
    let mut air = AirTime::new(EU_868);
    let mut access = ChannelAccess::new();

    let report = slot.service(&mut air, true).unwrap();
    assert_eq!(report.receptions, 1);
    arm_hold(&mut access, report.receptions, 1_000, 0);
    let _ = report.rx;

    slot.rx_queue.push(rx_frame(99)).unwrap();
    let pending = slot.service(&mut air, access.may_transmit(1_040)).unwrap();
    assert!(pending.tx_deferred_rx_pending);
    assert_eq!(pending.receptions, 0);
    arm_hold(&mut access, pending.receptions, 1_040, 0);
    assert_eq!(
        access.remaining_ms(1_040),
        PEER_TURNAROUND_MS - 40,
        "leftover RX must not re-arm the hold"
    );
}

#[test]
fn a_real_reception_arms_the_hold() {
    let mut slot = slot_with(false, Some(rx_frame(7)));
    let mut air = AirTime::new(EU_868);
    let mut access = ChannelAccess::new();
    assert!(access.may_transmit(1_000));

    let report = slot.service(&mut air, true).unwrap();
    assert_eq!(report.receptions, 1);
    assert_eq!(report.rx_ordinal, 1);
    arm_hold(&mut access, report.receptions, 1_000, 0);
    assert!(!access.may_transmit(1_000));
    assert!(access.may_transmit(1_000 + PEER_TURNAROUND_MS));
}

#[test]
fn continuous_busy_still_releases_once_the_hold_expires_and_the_channel_is_clear() {
    const TX_ID: u32 = 0x5150;
    let mut slot = slot_with(false, Some(rx_frame(1)));
    slot.enqueue_tx(TxFrame::new(0, &tx_bytes(TX_ID)).unwrap())
        .unwrap();
    let mut air = AirTime::new(EU_868);
    let mut access = ChannelAccess::new();

    let start = slot.service(&mut air, true).unwrap();
    assert_eq!(start.receptions, 1);
    arm_hold(&mut access, start.receptions, 0, 0);
    let _ = start.rx;

    slot.driver.busy = true;
    let mut now = 5u32;
    while now < PEER_TURNAROUND_MS + 80 {
        let report = slot.service(&mut air, access.may_transmit(now)).unwrap();
        assert!(
            report.tx_len.is_none(),
            "must not key up while the modem is busy at {now}"
        );
        assert_eq!(report.tx_id, Some(TX_ID));
        arm_hold(&mut access, report.receptions, now, 0);
        now += 5;
    }

    assert!(
        access.may_transmit(now),
        "hold must have expired despite continuous busy"
    );
    slot.driver.busy = false;
    let sent = slot.service(&mut air, access.may_transmit(now)).unwrap();
    assert_eq!(sent.tx_id, Some(TX_ID));
    assert_eq!(sent.tx_len, Some(20));
    assert_eq!(slot.driver.sent, 1);
    assert_eq!(slot.tx_queue_len(), 0);
}

#[test]
fn a_due_frame_keeps_its_identity_when_the_gate_opens_late() {
    const TX_ID: u32 = 0xA11;
    let mut slot = slot_with(false, Some(rx_frame(3)));
    slot.enqueue_tx(TxFrame::new(0, &tx_bytes(TX_ID)).unwrap())
        .unwrap();
    let mut air = AirTime::new(EU_868);
    let mut access = ChannelAccess::new();

    let start = slot.service(&mut air, true).unwrap();
    arm_hold(&mut access, start.receptions, 0, 0);
    let _ = start.rx;

    let late = PEER_TURNAROUND_MS + 10;
    assert!(access.may_transmit(late));
    let sent = slot.service(&mut air, true).unwrap();
    assert_eq!(sent.tx_id, Some(TX_ID), "same frame, not a redrawn delay");
    assert_eq!(sent.tx_len, Some(20));
}

#[test]
fn reception_ordinal_is_in_the_report_and_advances_once_per_reception() {
    let mut slot = slot_with(false, Some(rx_frame(1)));
    slot.enqueue_tx(TxFrame::new(0, &tx_bytes(9)).unwrap())
        .unwrap();
    let mut air = AirTime::new(EU_868);

    let a = slot.service(&mut air, true).unwrap();
    assert_eq!(a.rx_ordinal, 1);
    assert_eq!(a.receptions, 1);
    assert_eq!(a.held_behind_rx, Some(1));
    let _ = a.rx;

    slot.driver.inbox = Some(rx_frame(2));
    let b = slot.service(&mut air, true).unwrap();
    assert_eq!(b.rx_ordinal, 2);
    assert_eq!(b.receptions, 1);
    assert_eq!(b.held_behind_rx, Some(2));
}
