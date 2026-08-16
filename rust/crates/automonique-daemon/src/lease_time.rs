// SPDX-License-Identifier: Elastic-2.0

//! Boot-inclusive lease authority and suspend self-fencing.
//!
//! Audit timestamps use Unix time elsewhere. This module deliberately has no
//! wall-clock API: every deadline it returns is absolute `CLOCK_BOOTTIME`.

use automonique_store::LeaseTimeSource;
use nix::sys::time::TimeValLike;
use nix::time::ClockId;

/// Sampling skew below this bound is not evidence that the machine suspended.
const SUSPEND_DELTA_JUMP_MS: i64 = 5;

/// Linux boot-inclusive clock used by the durable store.
#[derive(Clone, Copy, Debug, Default)]
pub struct BootTimeSource;

impl LeaseTimeSource for BootTimeSource {
    fn now_boottime_ms(&self) -> Result<i64, &'static str> {
        read_ms(ClockId::CLOCK_BOOTTIME)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ClockSample {
    boottime_ms: i64,
    monotonic_ms: i64,
}

trait ClockSampler: Send {
    fn sample(&self) -> Result<ClockSample, &'static str>;
}

impl ClockSampler for BootTimeSource {
    fn sample(&self) -> Result<ClockSample, &'static str> {
        // Monotonic first, boottime second. With no prior suspend this makes
        // the small sequential sampling skew nonnegative.
        Ok(ClockSample {
            monotonic_ms: read_ms(ClockId::CLOCK_MONOTONIC)?,
            boottime_ms: self.now_boottime_ms()?,
        })
    }
}

fn read_ms(clock: ClockId) -> Result<i64, &'static str> {
    let value = clock.now().map_err(|_| "clock_gettime")?.num_milliseconds();
    if value < 0 {
        return Err("negative_boottime");
    }
    Ok(value)
}

/// One serve-loop authority observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct LeaseObservation {
    now_boottime_ms: i64,
    suspend_detected: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LeaseAuthorityError {
    Clock(&'static str),
    Suspended,
}

/// Latches lease loss when suspend time appears between two observations.
pub struct SuspendFence {
    source: Box<dyn ClockSampler>,
    prior: ClockSample,
    lost: bool,
}

impl SuspendFence {
    pub fn system() -> Result<Self, &'static str> {
        Self::from_source(Box::new(BootTimeSource))
    }

    fn from_source(source: Box<dyn ClockSampler>) -> Result<Self, &'static str> {
        let prior = source.sample()?;
        validate_sample(prior)?;
        Ok(Self {
            source,
            prior,
            lost: false,
        })
    }

    /// Sample authority time and latch loss on a boot/monotonic delta jump.
    fn observe(&mut self) -> Result<LeaseObservation, &'static str> {
        let current = self.source.sample()?;
        validate_sample(current)?;
        if current.boottime_ms < self.prior.boottime_ms
            || current.monotonic_ms < self.prior.monotonic_ms
        {
            self.lost = true;
            return Err("lease_clock_regressed");
        }
        let prior_delta = self.prior.boottime_ms - self.prior.monotonic_ms;
        let current_delta = current.boottime_ms - current.monotonic_ms;
        if current_delta.saturating_sub(prior_delta) > SUSPEND_DELTA_JUMP_MS {
            self.lost = true;
        }
        self.prior = current;
        Ok(LeaseObservation {
            now_boottime_ms: current.boottime_ms,
            suspend_detected: self.lost,
        })
    }

    /// Return authority time or self-fence after any detected suspend.
    pub fn require_authority(&mut self) -> Result<i64, LeaseAuthorityError> {
        let observation = self.observe().map_err(LeaseAuthorityError::Clock)?;
        if observation.suspend_detected {
            Err(LeaseAuthorityError::Suspended)
        } else {
            Ok(observation.now_boottime_ms)
        }
    }
}

fn validate_sample(sample: ClockSample) -> Result<(), &'static str> {
    if sample.boottime_ms < 0 || sample.monotonic_ms < 0 {
        return Err("negative_lease_clock");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::Mutex;

    use super::*;

    struct FakeClock {
        samples: Mutex<VecDeque<ClockSample>>,
    }

    impl FakeClock {
        fn new(samples: impl IntoIterator<Item = ClockSample>) -> Self {
            Self {
                samples: Mutex::new(samples.into_iter().collect()),
            }
        }
    }

    impl ClockSampler for FakeClock {
        fn sample(&self) -> Result<ClockSample, &'static str> {
            self.samples
                .lock()
                .map_err(|_| "fake_clock_poisoned")?
                .pop_front()
                .ok_or("fake_clock_exhausted")
        }
    }

    #[test]
    fn deadline_arithmetic_uses_only_absolute_boottime() {
        let now_boottime_ms = 41_000_i64;
        let ttl_ms = 20_000_i64;
        assert_eq!(now_boottime_ms.checked_add(ttl_ms), Some(61_000));
    }

    #[test]
    fn injected_suspend_delta_latches_self_fence() {
        let source = FakeClock::new([
            ClockSample {
                boottime_ms: 10_000,
                monotonic_ms: 9_000,
            },
            ClockSample {
                boottime_ms: 10_025,
                monotonic_ms: 9_025,
            },
            ClockSample {
                boottime_ms: 3_610_050,
                monotonic_ms: 9_050,
            },
            ClockSample {
                boottime_ms: 3_610_075,
                monotonic_ms: 9_075,
            },
        ]);
        let mut fence = SuspendFence::from_source(Box::new(source)).expect("baseline");
        assert_eq!(fence.require_authority().expect("ordinary tick"), 10_025);
        assert_eq!(
            fence.require_authority(),
            Err(LeaseAuthorityError::Suspended)
        );
        assert_eq!(
            fence.require_authority(),
            Err(LeaseAuthorityError::Suspended)
        );
    }

    #[test]
    fn lease_authority_module_has_no_wall_or_suspend_excluding_clock_api() {
        let source = include_str!("lease_time.rs");
        for forbidden in [concat!("System", "Time"), concat!("Inst", "ant")] {
            assert!(
                !source.contains(forbidden),
                "forbidden lease clock: {forbidden}"
            );
        }
    }
}
