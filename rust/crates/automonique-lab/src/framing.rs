// SPDX-License-Identifier: Elastic-2.0

//! Bounded, exactly-one-frame byte transport for encoded protocol payloads.

use std::error::Error;
use std::fmt;

pub const FRAME_PREFIX_BYTES: usize = 4;
pub const ABSOLUTE_MAX_FRAME_BYTES: u32 = 16 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FrameLimits {
    maximum_payload_bytes: u32,
}

impl FrameLimits {
    pub fn new(maximum_payload_bytes: u32) -> Result<Self, FrameError> {
        if maximum_payload_bytes == 0 || maximum_payload_bytes > ABSOLUTE_MAX_FRAME_BYTES {
            return Err(FrameError::InvalidMaximum);
        }
        Ok(Self {
            maximum_payload_bytes,
        })
    }

    pub const fn maximum_payload_bytes(self) -> u32 {
        self.maximum_payload_bytes
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FrameError {
    InvalidMaximum,
    FrameTooLarge {
        length: usize,
        maximum: u32,
    },
    TruncatedPrefix {
        available: usize,
    },
    TruncatedPayload {
        expected: usize,
        available: usize,
    },
    ExtraData {
        expected_total: usize,
        actual_total: usize,
    },
}

impl fmt::Display for FrameError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidMaximum => formatter.write_str("frame maximum must be positive"),
            Self::FrameTooLarge { length, maximum } => {
                write!(
                    formatter,
                    "frame payload length {length} exceeds bound {maximum}"
                )
            }
            Self::TruncatedPrefix { available } => {
                write!(formatter, "frame prefix is truncated at {available} bytes")
            }
            Self::TruncatedPayload {
                expected,
                available,
            } => write!(
                formatter,
                "frame payload is truncated: expected {expected} bytes, received {available}",
            ),
            Self::ExtraData {
                expected_total,
                actual_total,
            } => write!(
                formatter,
                "frame has extra data: expected {expected_total} bytes, received {actual_total}",
            ),
        }
    }
}

impl Error for FrameError {}

/// Payload serialization boundary. Canonical JSON can implement this trait in
/// a later slice without coupling frame parsing to a particular data format.
pub trait PayloadCodec {
    type Value;
    type Error;

    fn encode_payload(&self, value: &Self::Value) -> Result<Vec<u8>, Self::Error>;
    fn decode_payload(&self, payload: &[u8]) -> Result<Self::Value, Self::Error>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CodecError<E> {
    Frame(FrameError),
    Payload(E),
}

impl<E: fmt::Display> fmt::Display for CodecError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Frame(error) => error.fmt(formatter),
            Self::Payload(error) => error.fmt(formatter),
        }
    }
}

impl<E: Error + 'static> Error for CodecError<E> {}

pub fn encode_frame(payload: &[u8], limits: FrameLimits) -> Result<Vec<u8>, FrameError> {
    if payload.is_empty() || payload.len() > limits.maximum_payload_bytes as usize {
        return Err(FrameError::FrameTooLarge {
            length: payload.len(),
            maximum: limits.maximum_payload_bytes,
        });
    }
    let length = u32::try_from(payload.len()).map_err(|_| FrameError::FrameTooLarge {
        length: payload.len(),
        maximum: limits.maximum_payload_bytes,
    })?;
    let total = FRAME_PREFIX_BYTES
        .checked_add(payload.len())
        .ok_or(FrameError::FrameTooLarge {
            length: payload.len(),
            maximum: limits.maximum_payload_bytes,
        })?;
    let mut frame = Vec::with_capacity(total);
    frame.extend_from_slice(&length.to_be_bytes());
    frame.extend_from_slice(payload);
    Ok(frame)
}

pub fn decode_frame(frame: &[u8], limits: FrameLimits) -> Result<&[u8], FrameError> {
    if frame.len() < FRAME_PREFIX_BYTES {
        return Err(FrameError::TruncatedPrefix {
            available: frame.len(),
        });
    }
    let length = u32::from_be_bytes([frame[0], frame[1], frame[2], frame[3]]);
    if length == 0 || length > limits.maximum_payload_bytes {
        return Err(FrameError::FrameTooLarge {
            length: length as usize,
            maximum: limits.maximum_payload_bytes,
        });
    }
    let expected_total =
        FRAME_PREFIX_BYTES
            .checked_add(length as usize)
            .ok_or(FrameError::FrameTooLarge {
                length: length as usize,
                maximum: limits.maximum_payload_bytes,
            })?;
    if frame.len() < expected_total {
        return Err(FrameError::TruncatedPayload {
            expected: length as usize,
            available: frame.len() - FRAME_PREFIX_BYTES,
        });
    }
    if frame.len() > expected_total {
        return Err(FrameError::ExtraData {
            expected_total,
            actual_total: frame.len(),
        });
    }
    Ok(&frame[FRAME_PREFIX_BYTES..])
}

pub fn encode_with<C: PayloadCodec>(
    codec: &C,
    value: &C::Value,
    limits: FrameLimits,
) -> Result<Vec<u8>, CodecError<C::Error>> {
    let payload = codec.encode_payload(value).map_err(CodecError::Payload)?;
    encode_frame(&payload, limits).map_err(CodecError::Frame)
}

pub fn decode_with<C: PayloadCodec>(
    codec: &C,
    frame: &[u8],
    limits: FrameLimits,
) -> Result<C::Value, CodecError<C::Error>> {
    let payload = decode_frame(frame, limits).map_err(CodecError::Frame)?;
    codec.decode_payload(payload).map_err(CodecError::Payload)
}
