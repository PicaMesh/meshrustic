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
            if write != src {
                self.buf[write] = self.buf[src];
            }
            write += 1;
        }
        if removed > 0 {
            self.head = 0;
            self.tail = write % N;
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
