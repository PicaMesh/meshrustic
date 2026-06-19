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
    /// Packet id from the 16-byte mesh header (when present).
    pub tx_id: Option<u32>,
    /// Destination node from the mesh header (when present).
    pub tx_to: Option<u32>,
    /// TX queue had a frame but hourly duty cycle blocked dequeue.
    pub duty_cycle_blocked: bool,
    /// Frames waiting in the TX queue after this poll.
    pub tx_queue_len: u8,
}

fn mesh_header_id_to(payload: &[u8]) -> Option<(u32, u32)> {
    if payload.len() < crate::config::PACKET_HEADER_LEN {
        return None;
    }
    let to = u32::from_le_bytes(payload[0..4].try_into().ok()?);
    let id = u32::from_le_bytes(payload[8..12].try_into().ok()?);
    Some((id, to))
}

pub struct RadioSlot<D, const RX: usize = DEFAULT_RX_QUEUE, const TX: usize = DEFAULT_TX_QUEUE> {
    pub id: RadioId,
    pub driver: D,
    pub rx_queue: RxQueue<RX>,
    pub tx_queue: TxQueue<TX>,
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
        }
    }

    pub fn config(&self) -> &RadioConfig {
        self.driver.config()
    }

    pub fn init(&mut self) -> Result<(), RadioError> {
        self.driver.init()
    }

    /// Poll hardware, enqueue RX frames, drain TX queue when duty cycle allows.
    pub fn service(&mut self, air_time: &mut AirTime) -> Result<ServiceReport, RadioError> {
        let mut report = ServiceReport::default();

        while let Some(frame) = self.driver.poll_recv()? {
            let ms = crate::packet_time::packet_time_ms(self.config(), frame.len as usize, true);
            air_time.log_airtime(crate::airtime::AirtimeLog::RxAll, ms);
            let _ = self.rx_queue.push(frame);
        }

        if air_time.is_tx_allowed_duty_cycle() {
            if let Ok(tx) = self.tx_queue.pop() {
                let len = tx.len;
                if let Some((id, to)) = mesh_header_id_to(tx.payload()) {
                    report.tx_id = Some(id);
                    report.tx_to = Some(to);
                }
                self.driver.send(&tx)?;
                air_time.log_tx_packet(self.config(), len as usize);
                self.driver.start_rx()?;
                report.tx_len = Some(len);
            }
        } else if self.tx_queue.len() > 0 {
            report.duty_cycle_blocked = true;
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
}
