//! DLEP Status Codes (RFC 8175 §13.1.1).
//!
//! Codes < 128 mean "continue the session"; codes >= 128 mean "terminate".

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct StatusCode(pub u8);

impl StatusCode {
    // Continue-category codes
    pub const SUCCESS: Self = Self(0);
    pub const NOT_INTERESTED: Self = Self(1);
    pub const REQUEST_DENIED: Self = Self(2);
    pub const INCONSISTENT_DATA: Self = Self(3);

    // Terminate-category codes
    pub const UNKNOWN_MESSAGE: Self = Self(128);
    pub const UNEXPECTED_MESSAGE: Self = Self(129);
    pub const INVALID_DATA: Self = Self(130);
    pub const INVALID_DESTINATION: Self = Self(131);
    pub const TIMED_OUT: Self = Self(132);
    pub const SHUTTING_DOWN: Self = Self(255);

    pub const fn terminates_session(self) -> bool {
        self.0 >= 128
    }
}

impl From<u8> for StatusCode {
    fn from(v: u8) -> Self {
        Self(v)
    }
}
