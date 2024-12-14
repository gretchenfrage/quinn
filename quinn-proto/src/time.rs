//! Abstraction over platform-specific and mockable time

use std::ops::{Add, AddAssign, Div, Mul, MulAssign, Sub};

/// Responsible for providing timestamps
pub trait Clock {
    /// Get an `Instant` representing the current time
    fn now(&mut self) -> Instant;

    /// Get a `SystemTime` representing the current time
    fn system_now(&mut self) -> SystemTime;
}

/// Unix epoch, expressed in Quinn's [`SystemTime`] wrapper
pub const UNIX_EPOCH: SystemTime = SystemTime(platform::UNIX_EPOCH);

/// Wrapper around whatever [`Duration`]-like type Quinn uses on the current platform
#[derive(Debug, Default, Copy, Clone, Ord, PartialOrd, Eq, PartialEq)]
pub struct Duration(platform::Duration);

impl Duration {
    pub const fn from_millis(millis: u64) -> Self {
        Self(platform::Duration::from_millis(millis))
    }

    pub const fn from_secs(secs: u64) -> Self {
        Self(platform::Duration::from_secs(secs))
    }

    pub const fn from_micros(micros: u64) -> Self {
        Self(platform::Duration::from_micros(micros))
    }

    pub const fn from_nanos(nanos: u64) -> Self {
        Self(platform::Duration::from_nanos(nanos))
    }

    pub const fn as_micros(&self) -> u128 {
        self.0.as_micros()
    }

    pub const fn as_millis(&self) -> u128 {
        self.0.as_millis()
    }

    pub const fn new(secs: u64, nanos: u32) -> Self {
        Self(platform::Duration::new(secs, nanos))
    }

    pub const fn as_secs(&self) -> u64 {
        self.0.as_secs()
    }

    pub const fn as_nanos(&self) -> u128 {
        self.0.as_nanos()
    }

    pub fn checked_mul(self, rhs: u32) -> Option<Duration> {
        self.0.checked_mul(rhs).map(Self)
    }

    pub fn as_secs_f64(&self) -> f64 {
        self.0.as_secs_f64()
    }

    pub fn as_secs_f32(&self) -> f32 {
        self.0.as_secs_f32()
    }

    pub fn mul_f32(self, rhs: f32) -> Self {
        Self(self.0.mul_f32(rhs))
    }

    #[cfg(test)]
    pub fn into_platform_specific(self) -> platform::Duration {
        self.0
    }
}

impl Add for Duration {
    type Output = Self;

    fn add(self, rhs: Self) -> Self {
        Self(self.0 + rhs.0)
    }
}

impl AddAssign for Duration {
    fn add_assign(&mut self, rhs: Duration) {
        self.0 += rhs.0;
    }
}

impl Sub<Duration> for Duration {
    type Output = Self;

    fn sub(self, rhs: Duration) -> Self {
        Self(self.0 - rhs.0)
    }
}

impl Mul<u32> for Duration {
    type Output = Self;

    fn mul(self, rhs: u32) -> Self {
        Self(self.0 * rhs)
    }
}

impl Div<u32> for Duration {
    type Output = Self;

    fn div(self, rhs: u32) -> Self {
        Self(self.0 / rhs)
    }
}

impl MulAssign<u32> for Duration {
    fn mul_assign(&mut self, rhs: u32) {
        self.0 *= rhs;
    }
}

/// Wrapper around whatever [`Instant`]-like type Quinn uses on the current platform
#[derive(Debug, Copy, Clone, Ord, PartialOrd, PartialEq, Eq)]
pub struct Instant(platform::Instant);

impl Instant {
    pub fn now() -> Self {
        Self(platform::Instant::now())
    }

    pub fn duration_since(&self, earlier: Self) -> Duration {
        Duration(self.0.duration_since(earlier.0))
    }

    pub fn checked_duration_since(&self, earlier: Instant) -> Option<Duration> {
        self.0.checked_duration_since(earlier.0).map(Duration)
    }

    pub fn checked_sub(&self, duration: Duration) -> Option<Self> {
        self.0.checked_sub(duration.0).map(Self)
    }

    pub fn checked_add(&self, duration: Duration) -> Option<Self> {
        self.0.checked_add(duration.0).map(Self)
    }

    pub fn saturating_duration_since(&self, earlier: Self) -> Duration {
        Duration(self.0.saturating_duration_since(earlier.0))
    }
}

impl Add<Duration> for Instant {
    type Output = Self;

    fn add(self, rhs: Duration) -> Self {
        Self(self.0 + rhs.0)
    }
}

impl AddAssign<Duration> for Instant {
    fn add_assign(&mut self, rhs: Duration) {
        self.0 += rhs.0;
    }
}

impl Sub<Duration> for Instant {
    type Output = Self;

    fn sub(self, rhs: Duration) -> Self {
        Self(self.0 - rhs.0)
    }
}

impl Sub for Instant {
    type Output = Duration;

    fn sub(self, rhs: Self) -> Duration {
        Duration(self.0 - rhs.0)
    }
}

/// Wrapper around whatever [`SystemTime`]-like type Quinn uses on the current platform
#[derive(Debug, Copy, Clone, PartialOrd, PartialEq)]
pub struct SystemTime(platform::SystemTime);

impl SystemTime {
    pub fn now() -> Self {
        Self(platform::SystemTime::now())
    }

    pub fn duration_since(&self, earlier: Self) -> Option<Duration> {
        self.0.duration_since(earlier.0).ok().map(Duration)
    }
}

impl Add<Duration> for SystemTime {
    type Output = Self;

    fn add(self, rhs: Duration) -> Self {
        Self(self.0 + rhs.0)
    }
}

#[cfg(not(all(target_family = "wasm", target_os = "unknown")))]
mod platform {
    pub use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
}

#[cfg(all(target_family = "wasm", target_os = "unknown"))]
mod platform {
    pub use web_time::{Duration, Instant, SystemTime, UNIX_EPOCH};
}
