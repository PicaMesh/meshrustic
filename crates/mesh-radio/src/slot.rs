use crate::airtime::AirTime;
use crate::config::RadioConfig;
use crate::frame::{RadioId, RxFrame, TxFrame};
use crate::interface::{RadioError, RadioInterface, TxStatus};
use crate::queue::{QueueError, RxQueue, TxQueue, DEFAULT_RX_QUEUE, DEFAULT_TX_QUEUE};

#[derive(Clone, Copy, Default)]
pub struct ServiceReport {
    pub rx: Option<RxFrame>,
    pub tx_len: Option<u8>,
    pub rx_restart_error: Option<RadioError>,
    pub tx_id: Option<u32>,
    pub tx_to: Option<u32>,
    pub tx_from: Option<u32>,
    pub duty_cycle_blocked: bool,
    pub tx_deferred_rx_busy: bool,
    pub tx_deferred_rx_pending: bool,
    pub tx_held: bool,
    pub tx_queue_len: u8,
    pub rx_ordinal: u32,
    pub receptions: u8,
    pub held_behind_rx: Option<u32>,
}

fn mesh_header_id_to(payload: &[u8]) -> Option<(u32, u32, u32)> {
    if payload.len() < crate::config::PACKET_HEADER_LEN {
        return None;
    }
    let to = u32::from_le_bytes(payload[0..4].try_into().ok()?);
    let id = u32::from_le_bytes(payload[8..12].try_into().ok()?);
    let from = u32::from_le_bytes(payload[4..8].try_into().ok()?);
    Some((id, to, from))
}

fn oldest_rx_ordinal(last: u32, queued: usize) -> Option<u32> {
    if last == 0 || queued == 0 {
        return None;
    }
    Some(last.wrapping_sub(queued as u32 - 1))
}

pub struct RadioSlot<D, const RX: usize = DEFAULT_RX_QUEUE, const TX: usize = DEFAULT_TX_QUEUE> {
    pub id: RadioId,
    pub driver: D,
    pub rx_queue: RxQueue<RX>,
    pub tx_queue: TxQueue<TX>,
    rx_ordinal: u32,
    rx_restart_pending: bool,
    tx_in_flight: Option<TxFrame>,
    tx_failure: Option<(u32, u32)>,
}

impl<D, const RX: usize, const TX: usize> RadioSlot<D, RX, TX>
where
    D: RadioInterface,
{
    pub const fn new(id: RadioId, driver: D) -> Self {
        Self {
            id,
            driver,
            rx_queue: RxQueue::new(),
            tx_queue: TxQueue::new(),
            rx_ordinal: 0,
            rx_restart_pending: false,
            tx_in_flight: None,
            tx_failure: None,
        }
    }

    pub fn rx_ordinal(&self) -> u32 {
        self.rx_ordinal
    }

    pub fn config(&self) -> &RadioConfig {
        self.driver.config()
    }

    pub fn init(&mut self) -> Result<(), RadioError> {
        self.driver.init()
    }

    pub fn tx_in_flight(&self) -> bool {
        self.tx_in_flight.is_some()
    }

    pub fn take_tx_failure(&mut self) -> Option<(u32, u32)> {
        self.tx_failure.take()
    }

    pub fn service(
        &mut self,
        air_time: &mut AirTime,
        may_tx: bool,
    ) -> Result<ServiceReport, RadioError> {
        let mut report = ServiceReport::default();
        self.tx_failure = None;
        let mut tx_completed = false;
        if let Some(tx) = self.tx_in_flight {
            match self.driver.poll_tx() {
                Err(_) => {
                    self.tx_in_flight = None;
                    self.tx_failure =
                        mesh_header_id_to(tx.payload()).map(|(id, _, from)| (from, id));
                    self.rx_restart_pending = self.driver.start_rx().is_err();
                    return Err(RadioError::TxOutcomeUnknown);
                }
                Ok(None) => {
                    report.tx_queue_len = self.tx_queue.len().min(u8::MAX as usize) as u8;
                    return Ok(report);
                }
                Ok(Some(TxStatus::Complete)) => {
                    self.tx_in_flight = None;
                    tx_completed = true;
                    report.tx_len = Some(tx.len);
                    if let Some((id, to, from)) = mesh_header_id_to(tx.payload()) {
                        report.tx_id = Some(id);
                        report.tx_to = Some(to);
                        report.tx_from = Some(from);
                    }
                    if let Err(err) = self.driver.start_rx() {
                        self.rx_restart_pending = true;
                        report.rx_restart_error = Some(err);
                    }
                }
                Ok(Some(TxStatus::OutcomeUnknown)) => {
                    self.tx_in_flight = None;
                    self.tx_failure =
                        mesh_header_id_to(tx.payload()).map(|(id, _, from)| (from, id));
                    self.rx_restart_pending = self.driver.start_rx().is_err();
                    return Err(RadioError::TxOutcomeUnknown);
                }
            }
        }
        if self.rx_restart_pending && !tx_completed {
            self.driver.start_rx()?;
            self.rx_restart_pending = false;
        }

        while self.tx_in_flight.is_none() && !self.rx_restart_pending && self.rx_queue.len() < RX {
            let Some(frame) = self.driver.poll_recv()? else {
                break;
            };
            let ms = crate::packet_time::packet_time_ms(self.config(), frame.len as usize, true);
            air_time.log_airtime(crate::airtime::AirtimeLog::RxAll, ms);
            let _ = self.rx_queue.push(frame);
            self.rx_ordinal = self.rx_ordinal.wrapping_add(1);
            if self.rx_ordinal == 0 {
                self.rx_ordinal = 1;
            }
            report.receptions = report.receptions.saturating_add(1);
        }
        report.rx_ordinal = self.rx_ordinal;

        if report.tx_len.is_none() {
            if let Some(tx) = self.tx_queue.front() {
                if let Some((id, to, from)) = mesh_header_id_to(tx.payload()) {
                    report.tx_id = Some(id);
                    report.tx_to = Some(to);
                    report.tx_from = Some(from);
                }
                if self.driver.rx_in_progress()? {
                    report.tx_deferred_rx_busy = true;
                } else if !self.rx_queue.is_empty() {
                    // Sending before the router processes RX can race the duplicate cancellation and put an
                    // unnecessary relay on air.
                    report.tx_deferred_rx_pending = true;
                    report.held_behind_rx = oldest_rx_ordinal(self.rx_ordinal, self.rx_queue.len());
                } else if !may_tx {
                    report.tx_held = true;
                    if self.rx_ordinal != 0 {
                        report.held_behind_rx = Some(self.rx_ordinal);
                    }
                } else if !air_time.is_tx_allowed_duty_cycle() {
                    report.duty_cycle_blocked = true;
                } else if let Ok(tx) = self.tx_queue.pop() {
                    match self.driver.start_send(&tx) {
                        Ok(()) => {
                            air_time.log_tx_packet(self.config(), tx.len as usize);
                            self.tx_in_flight = Some(tx);
                        }
                        Err(RadioError::TxNotStarted) => {
                            if self.driver.start_rx().is_err() {
                                self.rx_restart_pending = true;
                            }
                            self.tx_queue
                                .push_front(tx)
                                .map_err(|_| RadioError::Hardware)?;
                            return Err(RadioError::TxNotStarted);
                        }
                        Err(RadioError::InvalidLength) => {
                            if self.driver.start_rx().is_err() {
                                self.rx_restart_pending = true;
                            }
                            return Err(RadioError::InvalidLength);
                        }
                        Err(err) => {
                            air_time.log_tx_packet(self.config(), tx.len as usize);
                            self.tx_in_flight = Some(tx);
                            return Err(err);
                        }
                    }
                }
            }
        }

        report.tx_queue_len = self.tx_queue.len().min(u8::MAX as usize) as u8;

        report.rx = self.rx_queue.pop().ok();
        Ok(report)
    }
}

impl<D, const RX: usize, const TX: usize> RadioSlot<D, RX, TX> {
    pub fn enqueue_tx(&mut self, frame: TxFrame) -> Result<(), QueueError> {
        self.tx_queue.push(frame)
    }

    pub fn tx_queue_len(&self) -> usize {
        self.tx_queue.len()
    }

    pub fn remove_tx(&mut self, from: u32, id: u32) -> usize {
        self.tx_queue.remove_where(|f| {
            mesh_header_id_to(f.payload())
                .is_some_and(|(fid, _, origin)| fid == id && origin == from)
        })
    }
}

impl<D, const RX: usize, const TX: usize> RadioSlot<D, RX, TX>
where
    D: RadioInterface,
{
    pub fn rx_busy(&mut self) -> Result<bool, RadioError> {
        self.driver.rx_in_progress()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AirTime, RadioConfig, RadioError, RadioInterface, RxFrame, TxFrame, EU_868};

    struct MockRadio {
        busy: bool,
        sent: usize,
        cfg: RadioConfig,
        inbox: Option<RxFrame>,
    }

    impl RadioInterface for MockRadio {
        fn radio_id(&self) -> RadioId {
            0
        }
        fn config(&self) -> &RadioConfig {
            &self.cfg
        }
        fn init(&mut self) -> Result<(), RadioError> {
            Ok(())
        }
        fn poll_recv(&mut self) -> Result<Option<RxFrame>, RadioError> {
            Ok(self.inbox.take())
        }
        fn start_send(&mut self, _frame: &TxFrame) -> Result<(), RadioError> {
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

    #[test]
    fn tx_waits_while_a_frame_is_being_received() {
        let mut slot = RadioSlot::<MockRadio>::new(
            0,
            MockRadio {
                busy: true,
                sent: 0,
                cfg: RadioConfig::eu868_default(),
                inbox: None,
            },
        );
        let mut air = AirTime::new(EU_868);
        slot.enqueue_tx(TxFrame::new(0, &[0u8; 20]).unwrap())
            .unwrap();

        let report = slot.service(&mut air, true).unwrap();
        assert!(report.tx_deferred_rx_busy);
        assert!(report.tx_len.is_none());
        assert_eq!(slot.tx_queue_len(), 1, "frame stays queued");
        assert_eq!(slot.driver.sent, 0);

        slot.driver.busy = false;
        let started = slot.service(&mut air, true).unwrap();
        assert!(started.tx_len.is_none());
        let report = slot.service(&mut air, true).unwrap();
        assert!(!report.tx_deferred_rx_busy);
        assert_eq!(report.tx_len, Some(20));
        assert_eq!(slot.driver.sent, 1);
        assert_eq!(slot.tx_queue_len(), 0);
    }

    fn rx_frame(data: &[u8]) -> RxFrame {
        let mut f = RxFrame::empty(0);
        f.len = data.len() as u8;
        f.bytes[..data.len()].copy_from_slice(data);
        f.rssi = -70;
        f.snr = 8;
        f
    }

    fn frame_with_id(id: u32) -> [u8; 20] {
        let mut b = [0u8; 20];
        b[8..12].copy_from_slice(&id.to_le_bytes());
        b
    }

    #[test]
    fn received_frame_reaches_the_router_before_a_queued_tx_goes_out() {
        let mut slot = RadioSlot::<MockRadio>::new(
            0,
            MockRadio {
                busy: false,
                sent: 0,
                cfg: RadioConfig::eu868_default(),
                inbox: Some(rx_frame(&frame_with_id(0x1234))),
            },
        );
        let mut air = AirTime::new(EU_868);
        slot.enqueue_tx(TxFrame::new(0, &frame_with_id(0x1234)).unwrap())
            .unwrap();

        let report = slot.service(&mut air, true).unwrap();
        assert!(report.rx.is_some());
        assert!(report.tx_deferred_rx_pending);
        assert!(report.tx_len.is_none());
        assert_eq!(slot.driver.sent, 0);

        assert_eq!(slot.remove_tx(0, 0x1234), 1);
        let report = slot.service(&mut air, true).unwrap();
        assert!(report.tx_len.is_none());
        assert_eq!(slot.driver.sent, 0);
        assert_eq!(slot.tx_queue_len(), 0);
    }

    #[test]
    fn remove_tx_only_drops_frames_with_that_id() {
        let mut slot = RadioSlot::<MockRadio>::new(
            0,
            MockRadio {
                busy: false,
                sent: 0,
                cfg: RadioConfig::eu868_default(),
                inbox: None,
            },
        );
        slot.enqueue_tx(TxFrame::new(0, &frame_with_id(1)).unwrap())
            .unwrap();
        slot.enqueue_tx(TxFrame::new(0, &frame_with_id(2)).unwrap())
            .unwrap();
        slot.enqueue_tx(TxFrame::new(0, &frame_with_id(3)).unwrap())
            .unwrap();
        assert_eq!(slot.remove_tx(0, 2), 1);
        assert_eq!(slot.remove_tx(0, 2), 0);
        assert_eq!(slot.tx_queue_len(), 2);
        let mut air = AirTime::new(EU_868);
        let first = slot.service(&mut air, true).unwrap();
        assert_eq!(first.tx_id, Some(1));
        let second = slot.service(&mut air, true).unwrap();
        assert_eq!(second.tx_id, Some(1));
        assert_eq!(second.tx_len, Some(20));
        let third = slot.service(&mut air, true).unwrap();
        assert_eq!(third.tx_id, Some(3));
    }

    /// Cancelling a queued frame has to work after a frame has been popped.
    ///
    /// The radio task transmits frames and cancels the ones it hears a copy
    /// of, so the queue head is normally not zero when a cancellation runs.
    /// A compaction that assumes a zero head destroys the frames it has not
    /// read yet, which silently keeps the duplicate on the air.
    #[test]
    fn remove_tx_cancels_the_right_frame_after_a_frame_was_sent() {
        let mut slot = RadioSlot::<MockRadio>::new(
            0,
            MockRadio {
                busy: false,
                sent: 0,
                cfg: RadioConfig::eu868_default(),
                inbox: None,
            },
        );
        for id in [1u32, 2, 3] {
            slot.enqueue_tx(TxFrame::new(0, &frame_with_id(id)).unwrap())
                .unwrap();
        }
        let mut air = AirTime::new(EU_868);
        // Send the first frame: the queue head moves.
        let first = slot.service(&mut air, true).unwrap();
        assert_eq!(first.tx_id, Some(1));
        assert_eq!(slot.tx_queue_len(), 2);

        // Cancel the last queued frame: it must go, and the other must stay.
        assert_eq!(slot.remove_tx(0, 3), 1);
        assert_eq!(slot.tx_queue_len(), 1);
        assert_eq!(slot.remove_tx(0, 3), 0);
        assert_eq!(slot.tx_queue_len(), 1);

        let second = slot.service(&mut air, true).unwrap();
        assert_eq!(second.tx_id, Some(1), "the in-flight frame completes");
        let third = slot.service(&mut air, true).unwrap();
        assert_eq!(third.tx_id, Some(2), "the cancelled frame must not go out");
    }

    #[test]
    fn a_held_frame_is_named_and_attributed_to_the_reception() {
        let mut slot = RadioSlot::<MockRadio>::new(
            0,
            MockRadio {
                busy: false,
                sent: 0,
                cfg: RadioConfig::eu868_default(),
                inbox: Some(rx_frame(&frame_with_id(0xAA))),
            },
        );
        let mut air = AirTime::new(EU_868);
        slot.enqueue_tx(TxFrame::new(0, &frame_with_id(0xBB)).unwrap())
            .unwrap();

        let first = slot.service(&mut air, true).unwrap();
        assert_eq!(first.receptions, 1);
        assert_eq!(first.rx_ordinal, 1);
        assert_eq!(first.tx_id, Some(0xBB));
        assert!(first.tx_deferred_rx_pending);
        assert_eq!(first.held_behind_rx, Some(1));
        assert!(first.tx_len.is_none());

        let _ = first.rx;
        assert!(slot.rx_queue.is_empty());
        let held = slot.service(&mut air, false).unwrap();
        assert_eq!(held.receptions, 0);
        assert_eq!(held.rx_ordinal, 1);
        assert!(held.tx_held);
        assert_eq!(held.tx_id, Some(0xBB));
        assert_eq!(held.held_behind_rx, Some(1));
        assert_eq!(slot.tx_queue_len(), 1);
    }

    #[test]
    fn reception_ordinal_advances_once_per_completed_frame() {
        let mut slot = RadioSlot::<MockRadio>::new(
            0,
            MockRadio {
                busy: false,
                sent: 0,
                cfg: RadioConfig::eu868_default(),
                inbox: Some(rx_frame(&frame_with_id(1))),
            },
        );
        let mut air = AirTime::new(EU_868);
        let a = slot.service(&mut air, true).unwrap();
        assert_eq!(a.rx_ordinal, 1);
        assert_eq!(a.receptions, 1);

        slot.driver.inbox = Some(rx_frame(&frame_with_id(2)));
        let b = slot.service(&mut air, true).unwrap();
        assert_eq!(b.rx_ordinal, 2);
        assert_eq!(b.receptions, 1);
        assert_eq!(slot.rx_ordinal(), 2);

        let idle = slot.service(&mut air, true).unwrap();
        assert_eq!(idle.rx_ordinal, 2);
        assert_eq!(idle.receptions, 0);
    }

    #[test]
    fn leftover_rx_defers_tx_without_counting_a_new_reception() {
        let mut slot = RadioSlot::<MockRadio>::new(
            0,
            MockRadio {
                busy: false,
                sent: 0,
                cfg: RadioConfig::eu868_default(),
                inbox: None,
            },
        );
        let mut air = AirTime::new(EU_868);
        slot.rx_queue.push(rx_frame(&frame_with_id(0x11))).unwrap();
        slot.enqueue_tx(TxFrame::new(0, &frame_with_id(0x22)).unwrap())
            .unwrap();

        let report = slot.service(&mut air, true).unwrap();
        assert_eq!(report.receptions, 0);
        assert_eq!(report.rx_ordinal, 0);
        assert!(report.tx_deferred_rx_pending);
        assert_eq!(report.tx_id, Some(0x22));
        assert!(report.tx_len.is_none());
        assert_eq!(slot.driver.sent, 0);
    }
    #[test]
    fn queue_cancellation_does_not_remove_same_id_from_other_originators() {
        let mut slot = RadioSlot::<MockRadio>::new(
            0,
            MockRadio {
                busy: false,
                sent: 0,
                cfg: RadioConfig::eu868_default(),
                inbox: None,
            },
        );
        for from in [1u32, 2] {
            let mut frame = frame_with_id(42);
            frame[4..8].copy_from_slice(&from.to_le_bytes());
            slot.enqueue_tx(TxFrame::new(0, &frame).unwrap()).unwrap();
        }
        assert_eq!(slot.remove_tx(1, 42), 1);
        assert_eq!(slot.tx_queue_len(), 1);
        assert_eq!(slot.remove_tx(1, 42), 0);
        assert_eq!(slot.remove_tx(2, 42), 1);
    }

    struct FailingRadio {
        cfg: RadioConfig,
        resumed: bool,
        send_error: Option<RadioError>,
        poll_error: Option<RadioError>,
        poll_status: Option<TxStatus>,
        fail_resume_once: bool,
    }
    impl RadioInterface for FailingRadio {
        fn radio_id(&self) -> RadioId {
            0
        }
        fn config(&self) -> &RadioConfig {
            &self.cfg
        }
        fn init(&mut self) -> Result<(), RadioError> {
            Ok(())
        }
        fn poll_recv(&mut self) -> Result<Option<RxFrame>, RadioError> {
            Ok(None)
        }
        fn start_send(&mut self, _: &TxFrame) -> Result<(), RadioError> {
            match self.send_error {
                Some(err) => Err(err),
                None => Ok(()),
            }
        }
        fn poll_tx(&mut self) -> Result<Option<TxStatus>, RadioError> {
            if let Some(err) = self.poll_error {
                Err(err)
            } else {
                Ok(self.poll_status)
            }
        }
        fn start_rx(&mut self) -> Result<(), RadioError> {
            if self.fail_resume_once {
                self.fail_resume_once = false;
                return Err(RadioError::Hardware);
            }
            self.resumed = true;
            Ok(())
        }
    }
    #[test]
    fn failed_transmission_restores_reception_and_charges_possible_airtime() {
        let mut slot = RadioSlot::<FailingRadio>::new(
            0,
            FailingRadio {
                cfg: RadioConfig::eu868_default(),
                resumed: false,
                send_error: None,
                poll_error: None,
                poll_status: Some(TxStatus::OutcomeUnknown),
                fail_resume_once: false,
            },
        );
        let mut air = AirTime::new(EU_868);
        slot.enqueue_tx(TxFrame::new(0, &[0; 20]).unwrap()).unwrap();
        slot.service(&mut air, true).unwrap();
        assert!(matches!(
            slot.service(&mut air, true),
            Err(RadioError::TxOutcomeUnknown)
        ));
        assert!(slot.driver.resumed);
        assert!(air.utilization_tx_percent() > 0.0);
        assert_eq!(
            slot.tx_queue_len(),
            0,
            "ambiguous TX is not blindly retried"
        );
    }

    #[test]
    fn definitely_not_started_transmission_is_requeued() {
        let mut slot = RadioSlot::<FailingRadio>::new(
            0,
            FailingRadio {
                cfg: RadioConfig::eu868_default(),
                resumed: false,
                send_error: Some(RadioError::TxNotStarted),
                poll_error: None,
                poll_status: None,
                fail_resume_once: false,
            },
        );
        let mut air = AirTime::new(EU_868);
        slot.enqueue_tx(TxFrame::new(0, &[0; 20]).unwrap()).unwrap();
        assert!(matches!(
            slot.service(&mut air, true),
            Err(RadioError::TxNotStarted)
        ));
        assert_eq!(slot.tx_queue_len(), 1);
        assert_eq!(air.utilization_tx_percent(), 0.0);
    }

    #[test]
    fn successful_tx_is_reported_when_rx_restart_fails_and_is_retried() {
        let mut slot = RadioSlot::<FailingRadio>::new(
            0,
            FailingRadio {
                cfg: RadioConfig::eu868_default(),
                resumed: false,
                send_error: None,
                poll_error: None,
                poll_status: Some(TxStatus::Complete),
                fail_resume_once: true,
            },
        );
        let mut air = AirTime::new(EU_868);
        slot.enqueue_tx(TxFrame::new(0, &frame_with_id(42)).unwrap())
            .unwrap();
        let started = slot.service(&mut air, true).unwrap();
        assert!(started.tx_len.is_none());
        let report = slot.service(&mut air, true).unwrap();
        assert_eq!(report.tx_len, Some(20));
        assert_eq!(report.tx_id, Some(42));
        assert_eq!(report.rx_restart_error, Some(RadioError::Hardware));
        assert!(!slot.driver.resumed);
        let next = slot.service(&mut air, true).unwrap();
        assert!(slot.driver.resumed);
        assert!(next.tx_len.is_none());
        assert!(next.rx_restart_error.is_none());
    }

    #[test]
    fn tx_poll_error_is_terminal_unknown_and_releases_the_in_flight_slot() {
        let mut slot = RadioSlot::<FailingRadio>::new(
            0,
            FailingRadio {
                cfg: RadioConfig::eu868_default(),
                resumed: false,
                send_error: None,
                poll_error: Some(RadioError::Hardware),
                poll_status: None,
                fail_resume_once: false,
            },
        );
        let mut air = AirTime::new(EU_868);
        let mut frame = frame_with_id(0x42);
        frame[4..8].copy_from_slice(&0x1234u32.to_le_bytes());
        slot.enqueue_tx(TxFrame::new(0, &frame).unwrap()).unwrap();
        slot.service(&mut air, true).unwrap();

        assert!(matches!(
            slot.service(&mut air, true),
            Err(RadioError::TxOutcomeUnknown)
        ));
        assert!(!slot.tx_in_flight());
        assert_eq!(slot.take_tx_failure(), Some((0x1234, 0x42)));
        assert!(slot.driver.resumed);
    }
}
