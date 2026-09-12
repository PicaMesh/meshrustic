//! One physical radio slot (driver + bounded queues).

use crate::airtime::AirTime;
use crate::config::RadioConfig;
use crate::frame::{RadioId, RxFrame, TxFrame};
use crate::interface::{RadioError, RadioInterface};
use crate::queue::{QueueError, RxQueue, TxQueue, DEFAULT_RX_QUEUE, DEFAULT_TX_QUEUE};

/// Result of one `RadioSlot::service` poll.
#[derive(Clone, Copy, Default)]
pub struct ServiceReport {
    pub rx: Option<RxFrame>,
    pub tx_len: Option<u8>,
    /// Packet id from the 16-byte mesh header (when present). Set when a frame is sent *or*
    /// when a queued frame is held, so the report names the frame that waited.
    pub tx_id: Option<u32>,
    /// Destination node from the mesh header (when present).
    pub tx_to: Option<u32>,
    /// TX queue had a frame but hourly duty cycle blocked dequeue.
    pub duty_cycle_blocked: bool,
    /// TX queue had a frame but a reception was in progress; retried on the next poll.
    pub tx_deferred_rx_busy: bool,
    /// TX queue had a frame but a received frame had not yet reached the router; the router
    /// gets to cancel the queued relay first (a copy of the same packet is the usual reason).
    pub tx_deferred_rx_pending: bool,
    /// TX queue had a frame but the channel-access gate (post-RX turnaround, post-TX gap) held it.
    pub tx_held: bool,
    /// Frames waiting in the TX queue after this poll.
    pub tx_queue_len: u8,
    /// Last completed reception's ordinal (0 if none yet). Advances once per `poll_recv` frame.
    pub rx_ordinal: u32,
    /// Hardware receptions completed during this poll (not leftover queue depth).
    pub receptions: u8,
    /// The queued TX was held behind this completed reception, when that is known.
    pub held_behind_rx: Option<u32>,
}

fn mesh_header_id_to(payload: &[u8]) -> Option<(u32, u32)> {
    if payload.len() < crate::config::PACKET_HEADER_LEN {
        return None;
    }
    let to = u32::from_le_bytes(payload[0..4].try_into().ok()?);
    let id = u32::from_le_bytes(payload[8..12].try_into().ok()?);
    Some((id, to))
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

    /// Poll hardware, enqueue RX frames, and send the head of the TX queue when the channel is
    /// clear. The release decision is made here, with the frame in hand, so a held frame is
    /// named in the report together with the reason it waited.
    ///
    /// `may_tx` is the board's post-reception / post-TX gate. Listen-before-talk and "router
    /// has not seen this RX yet" are decided here from the modem and the receive queue; they
    /// defer the send but are not themselves a reason to extend that gate.
    pub fn service(
        &mut self,
        air_time: &mut AirTime,
        may_tx: bool,
    ) -> Result<ServiceReport, RadioError> {
        let mut report = ServiceReport::default();

        while let Some(frame) = self.driver.poll_recv()? {
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

        if let Some(tx) = self.tx_queue.front() {
            if let Some((id, to)) = mesh_header_id_to(tx.payload()) {
                report.tx_id = Some(id);
                report.tx_to = Some(to);
            }
            if self.driver.rx_in_progress()? {
                // Listen before talk: a packet is arriving. Keying up now collides with it, and
                // SR's half-airtime slots assume an earlier slot's copy is heard, not trampled.
                report.tx_deferred_rx_busy = true;
            } else if !self.rx_queue.is_empty() {
                // A frame just completed and has not been seen by the router yet. Sending now
                // would put our relay on the air a few ms before the dedupe that cancels it
                // runs: two colocated nodes did exactly that, one keying up the instant the
                // other's copy ended.
                report.tx_deferred_rx_pending = true;
                report.held_behind_rx = oldest_rx_ordinal(self.rx_ordinal, self.rx_queue.len());
            } else if !may_tx {
                report.tx_held = true;
                if self.rx_ordinal != 0 {
                    report.held_behind_rx = Some(self.rx_ordinal);
                }
            } else if air_time.is_tx_allowed_duty_cycle() {
                if let Ok(tx) = self.tx_queue.pop() {
                    let len = tx.len;
                    self.driver.send(&tx)?;
                    air_time.log_tx_packet(self.config(), len as usize);
                    self.driver.start_rx()?;
                    report.tx_len = Some(len);
                }
            } else {
                report.duty_cycle_blocked = true;
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

    /// Drop queued frames carrying mesh packet `id` (a copy of the packet was heard, or the
    /// relay was cancelled for another reason). Returns how many frames were removed.
    pub fn remove_tx(&mut self, id: u32) -> usize {
        self.tx_queue
            .remove_where(|f| mesh_header_id_to(f.payload()).is_some_and(|(fid, _)| fid == id))
    }
}

impl<D, const RX: usize, const TX: usize> RadioSlot<D, RX, TX>
where
    D: RadioInterface,
{
    /// A frame is being received right now: nothing should be handed to the radio for TX.
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

        // The reception just completed: it is returned, the TX waits.
        let report = slot.service(&mut air, true).unwrap();
        assert!(report.rx.is_some());
        assert!(report.tx_deferred_rx_pending);
        assert!(report.tx_len.is_none());
        assert_eq!(slot.driver.sent, 0);

        // The router saw a copy of the same packet and cancels our relay.
        assert_eq!(slot.remove_tx(0x1234), 1);
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
        assert_eq!(slot.remove_tx(2), 1);
        assert_eq!(slot.remove_tx(2), 0);
        assert_eq!(slot.tx_queue_len(), 2);
        let mut air = AirTime::new(EU_868);
        let first = slot.service(&mut air, true).unwrap();
        assert_eq!(first.tx_id, Some(1));
        let second = slot.service(&mut air, true).unwrap();
        assert_eq!(second.tx_id, Some(3));
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
        slot.rx_queue
            .push(rx_frame(&frame_with_id(0x11)))
            .unwrap();
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
}
