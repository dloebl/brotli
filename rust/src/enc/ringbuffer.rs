//! Port of `c/enc/ringbuffer.h`: sliding window ring buffer.
//!
//! A RingBuffer(window_bits, tail_bits) contains `1 << window_bits` bytes of
//! data in a circular manner: writing a byte writes it to
//! `position() % (1 << window_bits)`.  For convenience, the RingBuffer array
//! contains another copy of the first `1 << tail_bits` bytes:
//! `buffer_[i] == buffer_[i + (1 << window_bits)]` if `i < (1 << tail_bits)`,
//! and another copy of the last two bytes:
//! `buffer_[-1] == buffer_[(1 << window_bits) - 1]` and
//! `buffer_[-2] == buffer_[(1 << window_bits) - 2]`.

use super::memory::{Buf, MemoryManager};
use super::params::BrotliEncoderParams;
use super::quality::compute_rb_bits;

const SLACK_FOR_EIGHT_BYTE_HASHING_EVERYWHERE: usize = 7;

#[derive(Default)]
pub struct RingBuffer {
    /// Size of the ring-buffer is (1 << window_bits) + tail_size_.
    pub size_: u32,
    pub mask_: u32,
    pub tail_size_: u32,
    pub total_size_: u32,

    pub cur_size_: u32,
    /// Position to write in the ring buffer.
    pub pos_: u32,
    /// The actual ring buffer containing the copy of the last two bytes, the
    /// data, and the copy of the beginning as a tail.  `buffer_` == `data_+2`.
    data_: Buf<u8>,
}

impl RingBuffer {
    /// `RingBufferInit`.
    pub fn new() -> Self {
        RingBuffer::default()
    }

    /// `RingBufferSetup`.
    pub fn setup(&mut self, params: &BrotliEncoderParams) {
        let window_bits = compute_rb_bits(params);
        let tail_bits = params.lgblock;
        self.size_ = 1u32 << window_bits;
        self.mask_ = (1u32 << window_bits) - 1;
        self.tail_size_ = 1u32 << tail_bits;
        self.total_size_ = self.size_ + self.tail_size_;
    }

    /// `RingBufferFree`.
    pub fn free(&mut self) {
        self.data_.free();
    }

    /// True once the buffer has been allocated (C: `buffer_ != NULL`).
    #[inline]
    pub fn is_allocated(&self) -> bool {
        !self.data_.is_empty()
    }

    /// The ring buffer contents starting at `buffer_` (i.e. `data_ + 2`),
    /// including the tail copy and the 7 bytes of zero slack.
    #[inline]
    pub fn buffer(&self) -> &[u8] {
        if self.data_.is_empty() {
            &[]
        } else {
            &self.data_[2..]
        }
    }

    #[inline]
    pub fn buffer_mut(&mut self) -> &mut [u8] {
        if self.data_.is_empty() {
            &mut []
        } else {
            &mut self.data_[2..]
        }
    }

    /// The whole allocation (`data_`), i.e. `buffer_ - 2`.
    #[inline]
    pub fn data(&self) -> &[u8] {
        &self.data_
    }

    /// `RingBufferInitBuffer`: allocates or re-allocates data_ to the given
    /// length plus some slack region before and after.  Fills the slack
    /// regions with zeros.
    fn init_buffer(&mut self, m: &MemoryManager, buflen: u32) {
        let mut new_data: Buf<u8> = Buf::new(m, 2 + buflen as usize + SLACK_FOR_EIGHT_BYTE_HASHING_EVERYWHERE);
        if !self.data_.is_empty() {
            let n = 2 + self.cur_size_ as usize + SLACK_FOR_EIGHT_BYTE_HASHING_EVERYWHERE;
            new_data[..n].copy_from_slice(&self.data_[..n]);
        }
        self.data_ = new_data;
        self.cur_size_ = buflen;
        self.data_[0] = 0;
        self.data_[1] = 0;
        for i in 0..SLACK_FOR_EIGHT_BYTE_HASHING_EVERYWHERE {
            self.data_[2 + self.cur_size_ as usize + i] = 0;
        }
    }

    /// `RingBufferWriteTail`.
    fn write_tail(&mut self, bytes: &[u8], n: usize) {
        let masked_pos = (self.pos_ & self.mask_) as usize;
        if masked_pos < self.tail_size_ as usize {
            // Just fill the tail buffer with the beginning data.
            let p = self.size_ as usize + masked_pos;
            let len = n.min(self.tail_size_ as usize - masked_pos);
            self.buffer_mut()[p..p + len].copy_from_slice(&bytes[..len]);
        }
    }

    /// `RingBufferWrite`: push bytes into the ring buffer.
    pub fn write(&mut self, m: &MemoryManager, bytes: &[u8]) {
        let n = bytes.len();
        if self.pos_ == 0 && n < self.tail_size_ as usize {
            // Special case for the first write: to process the first block,
            // we don't need to allocate the whole ring-buffer and we don't
            // need the tail either. However, we do this memory usage
            // optimization only if the first write is less than the tail
            // size, which is also the input block size, otherwise it is
            // likely that other blocks will follow and we will need to
            // reallocate to the full size anyway.
            self.pos_ = n as u32;
            self.init_buffer(m, self.pos_);
            self.buffer_mut()[..n].copy_from_slice(bytes);
            return;
        }
        if self.cur_size_ < self.total_size_ {
            // Lazily allocate the full buffer.
            self.init_buffer(m, self.total_size_);
            // Initialize the last two bytes to zero, so that we don't have to
            // worry later when we copy the last two bytes to the first two
            // positions.
            let size = self.size_ as usize;
            let pos = self.pos_ as usize;
            let tail = self.tail_size_ as usize;
            let buf = self.buffer_mut();
            buf[size - 2] = 0;
            buf[size - 1] = 0;
            // Mirror the bytes written by the "first write" shortcut (see
            // above) into the tail.
            let len = pos.min(tail);
            buf.copy_within(0..len, size);
        }
        {
            let masked_pos = (self.pos_ & self.mask_) as usize;
            // The length of the writes is limited so that we do not need to
            // worry about a write.
            self.write_tail(bytes, n);
            let size = self.size_ as usize;
            let total = self.total_size_ as usize;
            let buf = self.buffer_mut();
            if masked_pos + n <= size {
                // A single write fits.
                buf[masked_pos..masked_pos + n].copy_from_slice(bytes);
            } else {
                // Split into two writes.
                // Copy into the end of the buffer, including the tail buffer.
                let first = n.min(total - masked_pos);
                buf[masked_pos..masked_pos + first].copy_from_slice(&bytes[..first]);
                // Copy into the beginning of the buffer
                let off = size - masked_pos;
                buf[..n - off].copy_from_slice(&bytes[off..]);
            }
        }
        {
            let not_first_lap = (self.pos_ & (1u32 << 31)) != 0;
            let rb_pos_mask: u32 = (1u32 << 31) - 1;
            let size = self.size_ as usize;
            let a = self.buffer()[size - 2];
            let b = self.buffer()[size - 1];
            self.data_[0] = a;
            self.data_[1] = b;
            self.pos_ = (self.pos_ & rb_pos_mask).wrapping_add((n as u32) & rb_pos_mask);
            if not_first_lap {
                // Wrap, but preserve not-a-first-lap feature.
                self.pos_ |= 1u32 << 31;
            }
        }
    }
}
