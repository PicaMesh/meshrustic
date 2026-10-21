use crate::frame::{RxFrame, TxFrame};

pub const DEFAULT_RX_QUEUE: usize = 4;
pub const DEFAULT_TX_QUEUE: usize = 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QueueError {
    Full,
    Empty,
}

pub struct RxQueue<const N: usize = DEFAULT_RX_QUEUE> {
    buf: [RxFrame; N],
    head: usize,
    tail: usize,
    len: usize,
}

impl<const N: usize> Default for RxQueue<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> RxQueue<N> {
    pub const fn new() -> Self {
        Self {
            buf: [RxFrame::empty(0); N],
            head: 0,
            tail: 0,
            len: 0,
        }
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn push(&mut self, frame: RxFrame) -> Result<(), QueueError> {
        if self.len == N {
            return Err(QueueError::Full);
        }
        self.buf[self.tail] = frame;
        self.tail = (self.tail + 1) % N;
        self.len += 1;
        Ok(())
    }

    pub fn pop(&mut self) -> Result<RxFrame, QueueError> {
        if self.len == 0 {
            return Err(QueueError::Empty);
        }
        let frame = self.buf[self.head];
        self.head = (self.head + 1) % N;
        self.len -= 1;
        Ok(frame)
    }
}

pub struct TxQueue<const N: usize = DEFAULT_TX_QUEUE> {
    buf: [TxFrame; N],
    head: usize,
    tail: usize,
    len: usize,
}

impl<const N: usize> Default for TxQueue<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> TxQueue<N> {
    pub const fn new() -> Self {
        Self {
            buf: [TxFrame {
                radio_id: 0,
                len: 0,
                bytes: [0; crate::frame::MAX_LORA_PAYLOAD],
            }; N],
            head: 0,
            tail: 0,
            len: 0,
        }
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_full(&self) -> bool {
        self.len == N
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn front(&self) -> Option<&TxFrame> {
        if self.len == 0 {
            None
        } else {
            Some(&self.buf[self.head])
        }
    }

    pub fn push(&mut self, frame: TxFrame) -> Result<(), QueueError> {
        if self.len == N {
            return Err(QueueError::Full);
        }
        self.buf[self.tail] = frame;
        self.tail = (self.tail + 1) % N;
        self.len += 1;
        Ok(())
    }

    pub fn push_front(&mut self, frame: TxFrame) -> Result<(), QueueError> {
        if self.len == N {
            return Err(QueueError::Full);
        }
        self.head = (self.head + N - 1) % N;
        self.buf[self.head] = frame;
        self.len += 1;
        Ok(())
    }

    /// Drop the frames the predicate rejects, keeping the rest in order.
    ///
    /// The queue is compacted in place: copying the whole array to the stack on
    /// every call would cost a kilobyte of stack per call, and the radio loop
    /// calls this for every queued frame it rejects.
    ///
    /// The destination index is circular as well, so it trails the source: the
    /// slot it writes to always holds a frame that has already been read. A
    /// linear destination would disagree with the circular source as soon as
    /// the ring head is not zero, and would overwrite a frame that has not been
    /// read yet.
    pub fn remove_where(&mut self, mut drop: impl FnMut(&TxFrame) -> bool) -> usize {
        let len = self.len;
        let mut write = 0usize;
        let mut removed = 0usize;
        for read in 0..len {
            let src = (self.head + read) % N;
            if drop(&self.buf[src]) {
                removed += 1;
                continue;
            }
            let dst = (self.head + write) % N;
            if write != read {
                self.buf[dst] = self.buf[src];
            }
            write += 1;
        }
        if removed > 0 {
            self.tail = (self.head + write) % N;
            self.len = write;
        }
        removed
    }

    pub fn pop(&mut self) -> Result<TxFrame, QueueError> {
        if self.len == 0 {
            return Err(QueueError::Empty);
        }
        let frame = self.buf[self.head];
        self.head = (self.head + 1) % N;
        self.len -= 1;
        Ok(frame)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const N: usize = 4;

    fn frame(tag: u8) -> TxFrame {
        TxFrame::new(0, &[tag]).unwrap()
    }

    /// The tags of the queued frames, in order, padded with zero.
    fn tags(queue: &TxQueue<N>) -> [u8; N] {
        let mut out = [0u8; N];
        for (i, slot) in out.iter_mut().enumerate().take(queue.len()) {
            *slot = queue.buf[(queue.head + i) % N].bytes[0];
        }
        out
    }

    /// The compaction must not depend on where the ring head happens to be.
    ///
    /// The radio loop pops frames before it cancels a queued one, so the
    /// head is normally non-zero. A compaction that mixes a circular source
    /// with a linear destination destroys the frame it has not read yet.
    #[test]
    fn remove_where_keeps_the_queue_intact_after_a_pop() {
        let mut queue = TxQueue::<4>::new();
        for tag in [1u8, 2, 3, 4] {
            queue.push(frame(tag)).unwrap();
        }
        queue.pop().unwrap();
        queue.pop().unwrap();
        queue.push(frame(5)).unwrap();
        assert_eq!(tags(&queue), [3, 4, 5, 0]);

        assert_eq!(queue.remove_where(|f| f.bytes[0] == 5), 1);
        assert_eq!(tags(&queue), [3, 4, 0, 0]);
        assert_eq!(queue.len(), 2);
    }

    #[test]
    fn remove_where_drops_only_the_rejected_frames() {
        let mut queue = TxQueue::<4>::new();
        for tag in [1u8, 2, 3, 4] {
            queue.push(frame(tag)).unwrap();
        }
        queue.pop().unwrap();
        queue.push(frame(5)).unwrap();

        assert_eq!(queue.remove_where(|f| f.bytes[0] == 3), 1);
        assert_eq!(tags(&queue), [2, 4, 5, 0]);
        assert_eq!(queue.remove_where(|f| f.bytes[0] == 3), 0);
        assert_eq!(tags(&queue), [2, 4, 5, 0]);
    }

    #[test]
    fn remove_where_keeps_the_order_of_the_survivors() {
        let mut queue = TxQueue::<4>::new();
        for tag in [1u8, 2, 3, 4] {
            queue.push(frame(tag)).unwrap();
        }
        queue.pop().unwrap();
        assert_eq!(
            queue.remove_where(|f| f.bytes[0] == 2 || f.bytes[0] == 4),
            2
        );
        assert_eq!(tags(&queue), [3, 0, 0, 0]);
    }

    #[test]
    fn remove_where_on_an_empty_queue_does_nothing() {
        let mut queue = TxQueue::<4>::new();
        assert_eq!(queue.remove_where(|_| true), 0);
        assert_eq!(queue.len(), 0);
    }
}
